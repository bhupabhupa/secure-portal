import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";

const KEYCLOAK_URL = process.env.KEYCLOAK_URL || "http://localhost:8080";
const REALM = process.env.KEYCLOAK_REALM || "secure-portal";
const ISSUER = `${KEYCLOAK_URL}/realms/${REALM}`;

// Keycloak publishes its public keys at a JWKS endpoint.
// We verify tokens OFFLINE using these keys — no round-trip to Keycloak per request.
const jwks = jwksClient({
  jwksUri: `${ISSUER}/protocol/openid-connect/certs`,
  cache: true,          // cache keys in memory
  cacheMaxAge: 600000,  // 10 min
  rateLimit: true,
});

function getKey(header, callback) {
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key.getPublicKey());
  });
}

/**
 * authenticate — verifies the Bearer token's signature, issuer, and expiry.
 * On success, attaches { sub, username, email, roles } to req.user.
 */
export function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: "Missing bearer token" });
  }

  jwt.verify(token, getKey, { issuer: ISSUER, algorithms: ["RS256"] }, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: "Invalid or expired token", detail: err.message });
    }
    req.user = {
      sub: decoded.sub,
      username: decoded.preferred_username,
      email: decoded.email,
      roles: decoded.realm_access?.roles || [],
    };
    next();
  });
}

/**
 * requireRole — RBAC guard. Usage: app.get("/x", authenticate, requireRole("admin"), handler)
 * 401 = we don't know who you are. 403 = we know you, and you're not allowed.
 */
export function requireRole(...allowed) {
  return (req, res, next) => {
    const roles = req.user?.roles || [];
    const ok = allowed.some((r) => roles.includes(r));
    if (!ok) {
      audit(req, "ACCESS_DENIED", { required: allowed });
      return res.status(403).json({ error: `Requires role: ${allowed.join(" or ")}` });
    }
    next();
  };
}

/**
 * audit — append-only audit log (in-memory for demo; DB table in production).
 * The habit of logging who-did-what-when comes from regulated pharma software.
 */
export const auditLog = [];
export function audit(req, action, extra = {}) {
  auditLog.push({
    ts: new Date().toISOString(),
    user: req.user?.username || "anonymous",
    action,
    path: req.originalUrl,
    ip: req.ip,
    ...extra,
  });
}
