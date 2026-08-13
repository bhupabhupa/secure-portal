// Persistent, append-only audit store (FR-9).
//
// SQLite via better-sqlite3: a real file on disk, so audit history survives
// restarts and deploys — the defining property of an audit log. Append-only
// is enforced by construction: this module exposes an INSERT and SELECTs;
// no UPDATE or DELETE statement exists anywhere in the codebase.
//
// better-sqlite3 is synchronous, which is exactly right here: audit writes
// must not be dropped on process exit, and a single prepared INSERT costs
// microseconds — far cheaper than losing the security trail.

import Database from "better-sqlite3";
import fs from "node:fs";
import path from "node:path";

const DATA_DIR = process.env.AUDIT_DB_DIR || path.join(process.cwd(), "data");
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, "audit.db"));
db.pragma("journal_mode = WAL"); // safe concurrent reads while writing

db.exec(`
  CREATE TABLE IF NOT EXISTS audit_log (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT NOT NULL,
    user   TEXT NOT NULL,
    action TEXT NOT NULL,
    path   TEXT NOT NULL,
    ip     TEXT,
    extra  TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log (action);
  CREATE INDEX IF NOT EXISTS idx_audit_user   ON audit_log (user);
  CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_log (ts);
`);

const insertEntry = db.prepare(`
  INSERT INTO audit_log (ts, user, action, path, ip, extra)
  VALUES (@ts, @user, @action, @path, @ip, @extra)
`);

export function appendAudit({ ts, user, action, path: reqPath, ip, ...extra }) {
  insertEntry.run({
    ts,
    user,
    action,
    path: reqPath,
    ip: ip ?? null,
    extra: Object.keys(extra).length ? JSON.stringify(extra) : null,
  });
}

/**
 * queryAudit — filtered, newest-first.
 * Filters: user (exact), action (exact), from/to (ISO timestamps, inclusive).
 */
export function queryAudit({ user, action, from, to, limit = 200 } = {}) {
  const where = [];
  const params = {};
  if (user)   { where.push("user = @user");     params.user = user; }
  if (action) { where.push("action = @action"); params.action = action; }
  if (from)   { where.push("ts >= @from");      params.from = from; }
  if (to)     { where.push("ts <= @to");        params.to = to; }

  const sql = `
    SELECT ts, user, action, path, ip, extra
    FROM audit_log
    ${where.length ? "WHERE " + where.join(" AND ") : ""}
    ORDER BY id DESC
    LIMIT @limit
  `;
  params.limit = Math.min(Number(limit) || 200, 1000);

  return db.prepare(sql).all(params).map((row) => ({
    ts: row.ts,
    user: row.user,
    action: row.action,
    path: row.path,
    ip: row.ip,
    ...(row.extra ? JSON.parse(row.extra) : {}),
  }));
}
