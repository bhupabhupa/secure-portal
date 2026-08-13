import express from "express";
import cors from "cors";
import { authenticate, requirePermission, audit, auditLog, verifyLogoutToken } from "./auth.js";
import { revokeSession } from "./revocation.js";

const app = express();
app.use(cors({ origin: "http://localhost:5173" }));
app.use(express.json());

// ---- Demo data (in production: database) ----
const labRuns = [
  { id: 1, instrument: "HPLC-01", status: "completed", result: "PASS" },
  { id: 2, instrument: "MS-04", status: "running", result: null },
  { id: 3, instrument: "PCR-11", status: "queued", result: null },
];

// ---- Public ----
app.get("/api/health", (req, res) => res.json({ ok: true }));

// ---- Back-channel logout (FR-13) ----
// Called by KEYCLOAK (server-to-server), not by browsers: when a session ends
// (user logout, admin revocation), Keycloak POSTs a signed logout token here
// as application/x-www-form-urlencoded per the OIDC spec. We verify it and
// blacklist the session id so still-unexpired access tokens die immediately.
app.post(
  "/api/backchannel-logout",
  express.urlencoded({ extended: false }),
  async (req, res) => {
    const logoutToken = req.body?.logout_token;
    if (!logoutToken) {
      return res.status(400).json({ error: "Missing logout_token" });
    }
    try {
      const { sid, sub } = await verifyLogoutToken(logoutToken);
      revokeSession(sid);
      audit(req, "BACKCHANNEL_LOGOUT", { sid, sub });
      return res.status(200).end();
    } catch (err) {
      // Spec: invalid logout tokens get a 400. Never leak why to the caller
      // beyond that — but audit it, because someone probing this endpoint
      // with forged tokens is exactly what the audit log is for.
      audit(req, "BACKCHANNEL_LOGOUT_REJECTED", { detail: err.message });
      return res.status(400).json({ error: "Invalid logout token" });
    }
  }
);

// ---- Any authenticated user (viewer and above) ----
app.get("/api/me", authenticate, (req, res) => {
  res.json(req.user);
});

app.get("/api/runs", authenticate, requirePermission("runs:read"), (req, res) => {
  audit(req, "LIST_RUNS");
  res.json(labRuns);
});

// ---- requires runs:create (granted to manager, admin via permissions.js) ----
app.post("/api/runs", authenticate, requirePermission("runs:create"), (req, res) => {
  const run = {
    id: labRuns.length + 1,
    instrument: req.body.instrument || "UNKNOWN",
    status: "queued",
    result: null,
  };
  labRuns.push(run);
  audit(req, "CREATE_RUN", { runId: run.id, instrument: run.instrument });
  res.status(201).json(run);
});

// ---- requires audit:read (granted to admin via permissions.js) ----
app.get("/api/audit", authenticate, requirePermission("audit:read"), (req, res) => {
  audit(req, "VIEW_AUDIT_LOG");
  res.json(auditLog);
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`API listening on http://localhost:${PORT}`));
