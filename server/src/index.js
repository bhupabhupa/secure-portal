import express from "express";
import cors from "cors";
import { authenticate, requireRole, audit, auditLog } from "./auth.js";

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

// ---- Any authenticated user (viewer and above) ----
app.get("/api/me", authenticate, (req, res) => {
  res.json(req.user);
});

app.get("/api/runs", authenticate, requireRole("viewer", "manager", "admin"), (req, res) => {
  audit(req, "LIST_RUNS");
  res.json(labRuns);
});

// ---- manager + admin ----
app.post("/api/runs", authenticate, requireRole("manager", "admin"), (req, res) => {
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

// ---- admin only ----
app.get("/api/audit", authenticate, requireRole("admin"), (req, res) => {
  audit(req, "VIEW_AUDIT_LOG");
  res.json(auditLog);
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`API listening on http://localhost:${PORT}`));
