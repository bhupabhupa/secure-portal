import { useEffect, useState } from "react";
import { keycloak, hasRole } from "./keycloak.js";
import { api } from "./api.js";

const box = { border: "1px solid #ddd", borderRadius: 10, padding: 16, marginBottom: 16, fontFamily: "system-ui" };
const btn = { padding: "8px 14px", borderRadius: 8, border: "1px solid #333", background: "#fff", cursor: "pointer" };
const badge = (r) => ({ display: "inline-block", padding: "2px 10px", borderRadius: 999, marginRight: 6, fontSize: 12, background: { admin: "#FBEAEA", manager: "#F5EBDD", viewer: "#E7EFEA" }[r] || "#eee" });

export default function App() {
  const [me, setMe] = useState(null);
  const [runs, setRuns] = useState([]);
  const [auditRows, setAuditRows] = useState([]);
  const [error, setError] = useState(null);
  const [instrument, setInstrument] = useState("");

  useEffect(() => {
    api("/api/me").then(setMe).catch((e) => setError(e.message));
    loadRuns();
  }, []);

  const loadRuns = () => api("/api/runs").then(setRuns).catch((e) => setError(e.message));

  const createRun = async () => {
    setError(null);
    try {
      await api("/api/runs", { method: "POST", body: JSON.stringify({ instrument }) });
      setInstrument("");
      loadRuns();
    } catch (e) {
      setError(e.message); // a viewer calling this gets 403 — try it!
    }
  };

  const loadAudit = () => api("/api/audit").then(setAuditRows).catch((e) => setError(e.message));

  return (
    <div style={{ maxWidth: 720, margin: "40px auto", fontFamily: "system-ui", padding: "0 16px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h1 style={{ fontSize: 24 }}>🔐 Secure Portal</h1>
        <button style={btn} onClick={() => keycloak.logout()}>Logout</button>
      </div>

      {me && (
        <div style={box}>
          <b>{me.username}</b> ({me.email})<br />
          <div style={{ marginTop: 6 }}>
            {me.roles.filter((r) => ["admin", "manager", "viewer"].includes(r)).map((r) => (
              <span key={r} style={badge(r)}>{r}</span>
            ))}
          </div>
        </div>
      )}

      {error && <div style={{ ...box, background: "#FBEAEA", borderColor: "#c66" }}>⛔ {error}</div>}

      <div style={box}>
        <h2 style={{ fontSize: 18 }}>Lab Runs <span style={{ fontSize: 12, color: "#777" }}>(any authenticated role)</span></h2>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead><tr style={{ textAlign: "left", color: "#777" }}><th>ID</th><th>Instrument</th><th>Status</th><th>Result</th></tr></thead>
          <tbody>
            {runs.map((r) => (
              <tr key={r.id}><td>{r.id}</td><td>{r.instrument}</td><td>{r.status}</td><td>{r.result || "—"}</td></tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* UI-level RBAC: this section renders only for manager/admin.
          But the REAL enforcement is on the server — hiding a button is UX, not security. */}
      {(hasRole("manager") || hasRole("admin")) && (
        <div style={box}>
          <h2 style={{ fontSize: 18 }}>Create Run <span style={{ fontSize: 12, color: "#777" }}>(manager / admin)</span></h2>
          <input
            value={instrument}
            onChange={(e) => setInstrument(e.target.value)}
            placeholder="Instrument name e.g. HPLC-02"
            style={{ padding: 8, borderRadius: 8, border: "1px solid #ccc", marginRight: 8 }}
          />
          <button style={btn} onClick={createRun}>Queue run</button>
        </div>
      )}

      {hasRole("admin") && (
        <div style={box}>
          <h2 style={{ fontSize: 18 }}>Audit Log <span style={{ fontSize: 12, color: "#777" }}>(admin only)</span></h2>
          <button style={btn} onClick={loadAudit}>Load audit log</button>
          <pre style={{ fontSize: 12, overflow: "auto", maxHeight: 240 }}>
            {auditRows.map((a) => `${a.ts}  ${a.user.padEnd(16)} ${a.action.padEnd(16)} ${a.path}`).join("\n")}
          </pre>
        </div>
      )}
    </div>
  );
}
