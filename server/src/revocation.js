// Revoked-session store (FR-13).
//
// When Keycloak tells us a session ended (back-channel logout), we blacklist
// its session id. A sid only needs to stay blacklisted until the last access
// token minted for that session would have expired anyway — after that,
// normal expiry rejects it. So entries carry a TTL slightly above the
// access-token lifespan, and the store stays tiny.
//
// In-process Map is fine for a single API instance; multiple instances would
// share this via Redis or similar (same interface, different backing).

const ACCESS_TOKEN_LIFESPAN_S = Number(process.env.ACCESS_TOKEN_LIFESPAN || 300);
const CLOCK_SKEW_S = 30;
const TTL_MS = (ACCESS_TOKEN_LIFESPAN_S + CLOCK_SKEW_S) * 1000;

const revoked = new Map(); // sid -> expiresAt (ms epoch)

function prune() {
  const now = Date.now();
  for (const [sid, expiresAt] of revoked) {
    if (expiresAt <= now) revoked.delete(sid);
  }
}

export function revokeSession(sid) {
  prune();
  revoked.set(sid, Date.now() + TTL_MS);
}

export function isSessionRevoked(sid) {
  if (!sid) return false;
  const expiresAt = revoked.get(sid);
  if (!expiresAt) return false;
  if (expiresAt <= Date.now()) {
    revoked.delete(sid);
    return false;
  }
  return true;
}

// visible for tests / debugging
export function revokedCount() {
  prune();
  return revoked.size;
}
