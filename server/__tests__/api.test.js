// FR-11 — automated tests for the Test Plan (docs/SPEC.md T-1..T-7).
//
// Strategy: no running Keycloak. A ~30-line fake IdP (plain node:http) serves
// the OIDC discovery document and a JWKS built from a locally generated RSA
// key; test tokens are signed with that key's private half. The API can't
// tell the difference — which is the point: it trusts *the protocol*, not a
// particular server.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import jwt from "jsonwebtoken";

// ---- local RSA key + JWKS (what Keycloak would publish) ----
const KID = "test-key";
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const { publicKey: strangerPublic, privateKey: strangerPrivate } =
  crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }); // a key NOT in the JWKS
const jwk = { ...publicKey.export({ format: "jwk" }), kid: KID, alg: "RS256", use: "sig" };

let idp;        // fake identity provider
let issuer;     // iss value tokens must carry
let server;     // the API under test
let base;       // http://localhost:<port>
let queryAudit; // imported after env is set

before(async () => {
  // Fake IdP: discovery + JWKS, nothing else.
  idp = http.createServer((req, res) => {
    res.setHeader("content-type", "application/json");
    if (req.url.endsWith("/.well-known/openid-configuration")) {
      res.end(JSON.stringify({ issuer, jwks_uri: `http://localhost:${idp.address().port}/jwks` }));
    } else if (req.url === "/jwks") {
      res.end(JSON.stringify({ keys: [jwk] }));
    } else {
      res.statusCode = 404;
      res.end("{}");
    }
  });
  await new Promise((resolve) => idp.listen(0, resolve));
  const idpUrl = `http://localhost:${idp.address().port}`;
  issuer = `${idpUrl}/realms/secure-portal`;

  // Env must be set BEFORE the app modules load (they read it at import).
  process.env.KEYCLOAK_URL = idpUrl;
  process.env.AUDIT_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "audit-test-"));

  const { app } = await import("../src/app.js");
  ({ queryAudit } = await import("../src/audit-store.js"));
  server = app.listen(0);
  base = `http://localhost:${server.address().port}`;
});

after(() => {
  server?.close();
  idp?.close();
});

// ---- helpers ----
function signAccessToken({
  roles = [],
  user = "test.user",
  sid = crypto.randomUUID(),
  aud = "secure-portal-api",
  expiresIn = "5m",
  key = privateKey,
} = {}) {
  return jwt.sign(
    { realm_access: { roles }, preferred_username: user, email: `${user}@kc.local`, sid },
    key,
    { algorithm: "RS256", keyid: KID, issuer, audience: aud, expiresIn, subject: `sub-${user}` }
  );
}

function signLogoutToken({ sid, withEvents = true, key = privateKey } = {}) {
  const payload = { sid, sub: "sub-test.user" };
  if (withEvents) {
    payload.events = { "http://schemas.openid.net/event/backchannel-logout": {} };
  }
  return jwt.sign(payload, key, {
    algorithm: "RS256",
    keyid: KID,
    issuer,
    audience: "portal-web",
    expiresIn: "2m",
  });
}

const get = (path, token) =>
  fetch(base + path, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
const post = (path, token, body) =>
  fetch(base + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(token && { Authorization: `Bearer ${token}` }) },
    body: JSON.stringify(body ?? {}),
  });

// ---- T-1 (FR-2): authentication failures → 401 ----
test("T-1: request without token → 401", async () => {
  const res = await get("/api/me");
  assert.equal(res.status, 401);
});

test("T-1: garbage token → 401", async () => {
  const res = await get("/api/me", "not.a.jwt");
  assert.equal(res.status, 401);
});

test("T-1: expired token → 401", async () => {
  const res = await get("/api/me", signAccessToken({ roles: ["viewer"], expiresIn: "-60s" }));
  assert.equal(res.status, 401);
});

test("T-1: token signed by a key outside the JWKS → 401", async () => {
  const res = await get("/api/me", signAccessToken({ roles: ["viewer"], key: strangerPrivate }));
  assert.equal(res.status, 401);
});

// ---- T-6 (FR-12): audience validation ----
test("T-6: valid signature but wrong audience → 401", async () => {
  const res = await get("/api/me", signAccessToken({ roles: ["viewer"], aud: "some-other-client" }));
  assert.equal(res.status, 401);
  const body = await res.json();
  assert.match(body.detail, /audience/);
});

// ---- T-2 (FR-3/FR-8): denial + audit ----
test("T-2: viewer POST /api/runs → 403 AND audit row ACCESS_DENIED", async () => {
  const res = await post("/api/runs", signAccessToken({ roles: ["viewer"], user: "t2.viewer" }), {
    instrument: "X-9",
  });
  assert.equal(res.status, 403);
  const rows = queryAudit({ action: "ACCESS_DENIED", user: "t2.viewer" });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].required, "runs:create");
});

// ---- T-3 (FR-8): grants come from config, not code ----
test("T-3: manager token → 201; removing runs:create from the map flips the same roles to denied", async () => {
  const res = await post("/api/runs", signAccessToken({ roles: ["manager"], user: "t3.manager" }), {
    instrument: "HPLC-77",
  });
  assert.equal(res.status, 201);

  // Config-flip, proven at the unit level: same roles, edited map, grant gone.
  const { permissionsForRoles } = await import("../src/permissions.js");
  const edited = { manager: ["runs:read"] }; // runs:create removed
  assert.ok(permissionsForRoles(["manager"]).includes("runs:create"));
  assert.ok(!permissionsForRoles(["manager"], edited).includes("runs:create"));
});

// ---- T-5 (FR-4): role matrix happy paths ----
test("T-5: viewer reads runs → 200 with the run list", async () => {
  const res = await get("/api/runs", signAccessToken({ roles: ["viewer"] }));
  assert.equal(res.status, 200);
  const runs = await res.json();
  assert.ok(Array.isArray(runs) && runs.length >= 3);
});

test("T-5: admin reads audit log → 200; viewer → 403", async () => {
  const ok = await get("/api/audit", signAccessToken({ roles: ["admin"] }));
  assert.equal(ok.status, 200);
  const denied = await get("/api/audit", signAccessToken({ roles: ["viewer"] }));
  assert.equal(denied.status, 403);
});

// ---- T-4 (FR-9): audit is on disk, not in memory ----
test("T-4: audit rows exist in the SQLite file itself (fresh connection)", async () => {
  const { default: Database } = await import("better-sqlite3");
  const db = new Database(path.join(process.env.AUDIT_DB_DIR, "audit.db"), { readonly: true });
  const { n } = db.prepare("SELECT COUNT(*) AS n FROM audit_log").get();
  db.close();
  assert.ok(n > 0, "expected persisted audit rows in the db file");
});

test("T-4: action filter returns only matching rows", async () => {
  const rows = queryAudit({ action: "ACCESS_DENIED" });
  assert.ok(rows.length >= 1);
  assert.ok(rows.every((r) => r.action === "ACCESS_DENIED"));
});

// ---- T-7 (FR-13): back-channel logout + revocation ----
test("T-7: logout token revokes the sid — unexpired access token → 401 Session has been revoked", async () => {
  const sid = crypto.randomUUID();
  const accessToken = signAccessToken({ roles: ["viewer"], user: "t7.user", sid });

  // Token works before logout…
  assert.equal((await get("/api/me", accessToken)).status, 200);

  // …Keycloak announces the session ended…
  const logoutRes = await fetch(base + "/api/backchannel-logout", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ logout_token: signLogoutToken({ sid }) }),
  });
  assert.equal(logoutRes.status, 200);

  // …and the same, still-unexpired token is now dead.
  const after = await get("/api/me", accessToken);
  assert.equal(after.status, 401);
  assert.equal((await after.json()).error, "Session has been revoked");

  const audited = queryAudit({ action: "SESSION_REVOKED" });
  assert.ok(audited.some((r) => r.sid === sid));
});

test("T-7: logout token missing the events claim → 400", async () => {
  const res = await fetch(base + "/api/backchannel-logout", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ logout_token: signLogoutToken({ sid: "x", withEvents: false }) }),
  });
  assert.equal(res.status, 400);
});

test("T-7: logout token signed by a key outside the JWKS → 400", async () => {
  const res = await fetch(base + "/api/backchannel-logout", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ logout_token: signLogoutToken({ sid: "y", key: strangerPrivate }) }),
  });
  assert.equal(res.status, 400);
});
