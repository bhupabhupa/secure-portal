# SPEC — Secure Portal (Keycloak SSO + RBAC) — v1 built, v2 enhancements

Base app already exists (secure-portal.zip). This spec documents it formally
and defines v2 enhancements — ideal first practice project for the Claude Code
workflow: run /spec-review against this file inside the existing repo.

## 1. URS
- URS-1: As a user, I sign in once via the organization's identity provider (Keycloak) — no app-specific passwords.
- URS-2: As a user, I only see and do what my role permits (viewer/manager/admin).
- URS-3: As a security officer, permission checks are enforced on the server, and denied attempts are audit-logged.
- URS-4: As a user, my session refreshes silently; I'm not logged out mid-work.
- URS-5: As a security officer, when a session is terminated at the identity provider (logout, admin revocation), the API stops accepting its tokens immediately — not after token expiry.

## 2. Functional Requirements — v1 (implemented)
- FR-1 OIDC login: Authorization Code Flow + PKCE via keycloak-js; unauthenticated users are redirected to Keycloak login.
- FR-2 Token verification: API verifies JWT signature offline against Keycloak JWKS (cached), checks issuer + expiry; 401 on failure.
- FR-3 RBAC middleware: requireRole(...roles); 403 with audit entry on insufficient role.
- FR-4 Role-gated endpoints: GET /api/runs (any role), POST /api/runs (manager+), GET /api/audit (admin).
- FR-5 Role-aware UI: sections render per role; UI hiding documented as UX-not-security.
- FR-6 Silent refresh: access token auto-refreshed before expiry.
- FR-7 Realm-as-code: realm, clients, roles, demo users auto-imported from realm-export.json via docker compose.

## 3. Functional Requirements — v2 (to build with Claude Code)
- FR-8 Fine-grained permissions: map roles→permissions (runs:read, runs:create, audit:read) in one config; middleware checks permissions, not roles (adding a role stops requiring code changes).
- FR-9 Persistent audit: move audit log from memory to SQLite, append-only, with GET /api/audit?user=&action=&from=&to= filtering.
- FR-10 User admin panel: admin-only page listing realm users + their roles via Keycloak Admin REST API (read-only).
- FR-11 Tests: cover the Test Plan below (v1 had none — realistic legacy situation).
- FR-12 OIDC discovery + audience validation: API resolves endpoints (JWKS, issuer) from /.well-known/openid-configuration instead of hardcoded URLs (cached with TTL); JWT verification additionally validates the audience/authorized-party claim so tokens minted for other clients are rejected with 401.
- FR-13 Back-channel logout + session revocation: implement the OIDC Back-Channel Logout spec — Keycloak POSTs a signed logout token to the API on session end; API verifies it (signature, iss, aud, events claim), extracts sid, and adds it to a revocation store; authenticate rejects any access token whose sid is revoked (401 "Session has been revoked") + audit entry SESSION_REVOKED. Closes the offline-verification revocation-lag tradeoff documented in the README.

## 4. Design Spec
- Stack: Keycloak 24 (Docker) | Node 20 + Express + jsonwebtoken/jwks-rsa | React 18 + Vite + keycloak-js.
- 401 vs 403 semantics preserved everywhere; permission layer sits between authenticate and handlers.
- Keycloak Admin API access via confidential service-account client (add to realm export) — never the SPA client.
- FR-12: use the standard discovery document; cache it and JWKS keys in-process with a TTL (~10 min). No new dependency needed beyond a fetch.
- FR-13: revocation store is an in-process Set of revoked sids with expiry (a sid needs to stay blacklisted only until the last access token for that session would have expired anyway — max token lifetime). Register the API's backchannel-logout URL on the portal-web client in realm-export.json. Requires access tokens to carry sid (Keycloak includes it by default when backchannel logout is configured).

## 5. Test Plan
- T-1 (FR-2): request without token → 401; with expired/garbage token → 401.
- T-2 (FR-3/8): viewer token on POST /api/runs → 403 AND audit row ACCESS_DENIED.
- T-3 (FR-8): manager has runs:create → 201; permission config change (remove it) flips same call to 403 without code change.
- T-4 (FR-9): audit rows survive server restart; filter by action=ACCESS_DENIED returns only those.
- T-5 (FR-4): each endpoint's happy path returns expected data per role matrix in README.
- T-6 (FR-12): token with wrong audience → 401; JWKS/issuer URLs come from a stubbed discovery document in tests.
- T-7 (FR-13): valid logout token → 200 and sid stored; subsequent request with an otherwise-valid access token carrying that sid → 401 + SESSION_REVOKED audit row; logout token with bad signature or missing events claim → 400.
(Mock Keycloak in unit tests by signing JWTs with a local RSA key and stubbing the JWKS endpoint.)
