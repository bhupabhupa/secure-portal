import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";

import { isSessionRevoked } from "./revocation.js";
import { permissionsForRoles } from "./permissions.js";
import { appendAudit } from "./audit-store.js";

const KEYCLOAK_URL = process.env.KEYCLOAK_URL || "http://localhost:8080";
const REALM = process.env.KEYCLOAK_REALM || "secure-portal";
const ISSUER = `${KEYCLOAK_URL}/realms/${REALM}`;

// The audience our API expects in access tokens. Keycloak stamps it via the
// "api-audience" protocol mapper on the portal-web client (realm-export.json).
// Tokens minted for OTHER clients in the realm won't carry it → rejected.
const AUDIENCE = process.env.OIDC_AUDIENCE || "secure-portal-api";

// The SPA's client id — logout tokens (FR-13) are addressed to the CLIENT
// whose session ended, so their audience is portal-web, not the API's.
const WEB_CLIENT_ID = process.env.OIDC_WEB_CLIENT_ID || "portal-web";

// ---- OIDC discovery (FR-12) ----
// Instead of hardcoding the JWKS URL, we resolve endpoints from the issuer's
// discovery document — the standard OIDC pattern. If Keycloak's URLs ever
// change (version upgrade, path change), the API adapts without code changes.
const DISCOVERY_TTL_MS = 600000; // 10 min, same as the JWKS key cache
let discoveryCache = { doc: null, fetchedAt: 0 };

async function getDiscovery() {
  const fresh = Date.now() - discoveryCache.fetchedAt < DISCOVERY_TTL_MS;
  if (discoveryCache.doc && fresh) {
    return discoveryCache.doc;
  }
  const res = await fetch(`${ISSUER}/.well-known/openid-configuration`);
  if (!res.ok) {
    // Serve a stale document over failing hard — Keycloak may be briefly down.
    if (discoveryCache.doc) return discoveryCache.doc;
    throw new Error(`OIDC discovery failed: HTTP ${res.status}`);
  }
  discoveryCache = { doc: await res.json(), fetchedAt: Date.now() };
  return discoveryCache.doc;
}

// JWKS client is built from the DISCOVERED jwks_uri (not a hardcoded path)
// and rebuilt only if that URI ever changes.
let jwksCache = { client: null, uri: null };
function getJwksClient(jwksUri) {
  if (jwksCache.client && jwksCache.uri === jwksUri) {
    return jwksCache.client;
  }
  jwksCache = {
    uri: jwksUri,
    client: jwksClient({
      jwksUri,
      cache: true,          // cache keys in memory
      cacheMaxAge: 600000,  // 10 min
      rateLimit: true,
    }),
  };
  return jwksCache.client;
}

/**
 * authenticate — verifies the Bearer token's signature, issuer, audience,
 * and expiry. On success, attaches { sub, username, email, roles } to req.user.
 *
 * 401 on any verification failure; 503 if the IdP can't be discovered at all
 * (we can't verify anything without its public keys).
 */
export async function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: "Missing bearer token" });
  }

  let discovery;
  try {
    discovery = await getDiscovery();
  } catch (err) {
    return res.status(503).json({ error: "Identity provider unavailable", detail: err.message });
  }

  const jwks = getJwksClient(discovery.jwks_uri);
  const getKey = (header, callback) => {
    jwks.getSigningKey(header.kid, (err, key) => {
      if (err) return callback(err);
      callback(null, key.getPublicKey());
    });
  };

  const verifyOptions = {
    issuer: discovery.issuer,   // from discovery, not hardcoded
    audience: AUDIENCE,         // FR-12: reject tokens minted for other clients
    algorithms: ["RS256"],
  };

  jwt.verify(token, getKey, verifyOptions, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: "Invalid or expired token", detail: err.message });
    }
    const roles = decoded.realm_access?.roles || [];
    req.user = {
      sub: decoded.sub,
      username: decoded.preferred_username,
      email: decoded.email,
      roles,
      // FR-8: permissions resolved once per request from the role→permission
      // config; everything downstream checks these, never roles.
      permissions: permissionsForRoles(roles),
    };

    // FR-13: a signature-valid, unexpired token is still rejected if its
    // session was ended at the IdP (back-channel logout revoked the sid).
    // This closes the offline-verification revocation-lag tradeoff.
    if (isSessionRevoked(decoded.sid)) {
      audit(req, "SESSION_REVOKED", { sid: decoded.sid });
      return res.status(401).json({ error: "Session has been revoked" });
    }

    next();
  });
}

/**
 * verifyLogoutToken — validates an OIDC Back-Channel Logout token
 * (https://openid.net/specs/openid-connect-backchannel-1_0.html §2.6):
 * signature via the same JWKS, issuer, audience = the SPA client, the
 * back-channel logout `events` claim present, a `sid` to revoke, and no
 * `nonce` (the spec prohibits it to prevent replaying ID tokens here).
 * Returns the decoded payload; throws with a reason on any violation.
 */
export async function verifyLogoutToken(logoutToken) {
  const discovery = await getDiscovery();
  const jwks = getJwksClient(discovery.jwks_uri);
  const getKey = (header, callback) => {
    jwks.getSigningKey(header.kid, (err, key) => {
      if (err) return callback(err);
      callback(null, key.getPublicKey());
    });
  };

  const decoded = await new Promise((resolve, reject) => {
    jwt.verify(
      logoutToken,
      getKey,
      { issuer: discovery.issuer, audience: WEB_CLIENT_ID, algorithms: ["RS256"] },
      (err, payload) => (err ? reject(err) : resolve(payload))
    );
  });

  const LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";
  if (!decoded.events || !(LOGOUT_EVENT in decoded.events)) {
    throw new Error("Not a logout token: missing backchannel-logout event claim");
  }
  if (decoded.nonce) {
    throw new Error("Logout token must not contain a nonce");
  }
  if (!decoded.sid) {
    throw new Error("Logout token carries no sid");
  }

  return decoded;
}

/**
 * requirePermission — authorization guard (FR-8). Usage:
 *   app.post("/api/runs", authenticate, requirePermission("runs:create"), handler)
 * Endpoints name the capability they need; which roles grant it is decided
 * in permissions.js, not here.
 * 401 = we don't know who you are. 403 = we know you, and you're not allowed.
 */
export function requirePermission(permission) {
  return (req, res, next) => {
    const granted = req.user?.permissions || [];
    if (!granted.includes(permission)) {
      audit(req, "ACCESS_DENIED", { required: permission });
      return res.status(403).json({ error: `Requires permission: ${permission}` });
    }
    next();
  };
}

/**
 * audit — append-only audit log, persisted to SQLite (FR-9).
 * The habit of logging who-did-what-when comes from regulated pharma software.
 */
export function audit(req, action, extra = {}) {
  appendAudit({
    ts: new Date().toISOString(),
    user: req.user?.username || "anonymous",
    action,
    path: req.originalUrl,
    ip: req.ip,
    ...extra,
  });
}
