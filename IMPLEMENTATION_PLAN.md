# Implementation Plan — Secure Portal

Tracks FR status against docs/SPEC.md. Update after every change.

## v1 — implemented (baseline)

- [x] FR-1: OIDC login (Auth Code + PKCE) → client/src/keycloak.js, main.jsx
- [x] FR-2: Offline JWT verification via JWKS → server/src/auth.js
- [x] FR-3: RBAC middleware requireRole + audit on deny → server/src/auth.js
- [x] FR-4: Role-gated endpoints → server/src/index.js
- [x] FR-5: Role-aware UI → client/src/App.jsx
- [x] FR-6: Silent token refresh → client/src/keycloak.js
- [x] FR-7: Realm-as-code (incl. explicit token lifespans) → keycloak/realm-export.json, docker-compose.yml

## v2 — to build

- [x] FR-12: OIDC discovery + audience validation → server/src/auth.js (discovery + `aud` check), server/.env.example, api-audience mapper in realm-export.json
- [x] FR-13: Back-channel logout + session revocation → server/src/revocation.js (new), server/src/index.js (POST /api/backchannel-logout), server/src/auth.js (sid check + verifyLogoutToken), keycloak/realm-export.json (backchannel URL on portal-web client)
      Note: verified for RP-initiated (user) logout. Keycloak's ADMIN-initiated
      user logout does not send OIDC backchannel logout tokens in this setup —
      admin revocation propagates via not-before policy / token expiry instead.
- [x] FR-8: Permission layer (roles → permissions) → server/src/permissions.js (new), server/src/auth.js (requirePermission replaces requireRole), server/src/index.js
- [x] FR-9: Persistent audit (SQLite) → server/src/audit-store.js (new, better-sqlite3), GET /api/audit?user=&action=&from=&to=&limit=
- [ ] FR-11: Tests per Test Plan (T-1..T-7) → server/__tests__/, local RSA-signed JWTs + stubbed JWKS/discovery
- [ ] FR-10 (optional): Admin user panel via Keycloak Admin API → new confidential service-account client in realm-export.json, server endpoint, client page

## Recommended order & rationale

1. **FR-12** — small; upgrades the verification core that everything else touches; discovery/JWKS stubs built here are reused by tests.
2. **FR-13** — builds directly on FR-12's verifier; closes the documented revocation-lag tradeoff (the project's best story).
3. **FR-8** — permission layer slots between authenticate and handlers; endpoints then declare permissions, not roles.
4. **FR-9** — audit store swap (in-memory → SQLite); interface stays `audit(req, action, extra)`.
5. **FR-11** — tests cover T-1..T-7; written per-FR where practical, completed here.
6. **FR-10** — optional garnish, only if time permits.

## Shared foundations (build in FR-12)

- server/.env.example: KEYCLOAK_URL, KEYCLOAK_REALM, OIDC_AUDIENCE
- Discovery-document fetch + TTL cache (reused by FR-13's logout-token verification and FR-11's test stubs)

## Design notes / assumptions

- FR-8: role→permission map lives in server/src/permissions.js config (no DB; diffable).
- FR-9: better-sqlite3; DB file server/data/audit.db (gitignored).
- FR-13: Keycloak runs in Docker, so the backchannel logout URL must be
  `http://host.docker.internal:4000/...` — the container cannot reach the
  host's localhost. Revoked-sid store is in-process with TTL = access token
  lifespan (a sid only needs blacklisting until its last token would expire).
- FR-10: separate confidential client with service account (view-users role
  only); SPA client never gets admin permissions.
