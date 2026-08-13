import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";

const KEYCLOAK_URL = process.env.KEYCLOAK_URL || "http://localhost:8080";
const REALM = process.env.KEYCLOAK_REALM || "secure-portal";
const ISSUER = `${KEYCLOAK_URL}/realms/${REALM}`;

// The audience our API expects in access tokens. Keycloak stamps it via the
// "api-audience" protocol mapper on the portal-web client (realm-export.json).
// Tokens minted for OTHER clients in the realm won't carry it → rejected.
const AUDIENCE = process.env.OIDC_AUDIENCE || "secure-portal-api";

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
