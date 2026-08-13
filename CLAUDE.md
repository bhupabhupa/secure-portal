# CLAUDE.md — Secure Portal

## What this project is
Secure Portal: a minimal but production-shaped enterprise auth demo — React SPA
+ Node/Express API secured by Keycloak (OpenID Connect, Authorization Code Flow
with PKCE), with role-based access control enforced server-side and an
append-only audit log. Portfolio project demonstrating auth patterns used in
regulated-industry platforms (pharma, finance).

## Stack
- Frontend: React 18 + Vite (port 5173), keycloak-js
- Backend: Node 20+ + Express (port 4000), offline JWT verification via cached JWKS
- Other: Keycloak 24 in Docker (port 8080), realm auto-imported from keycloak/realm-export.json

## How to run
```bash
# 1. Keycloak (auto-imports realm, clients, roles, demo users)
docker compose up -d

# 2. API
cd server && npm install && npm run dev    # http://localhost:4000

# 3. SPA
cd client && npm install && npm run dev    # http://localhost:5173
```
Demo users: admin / manager+001@kc.local / viewer+001@kc.local (password: `password`)

## Source of truth
- docs/SPEC.md contains URS, Functional Requirements (FR-x), Design Spec, Test Plan.
- IMPLEMENTATION_PLAN.md tracks FR status. Keep it updated after every change.

## Working rules
1. Work FR-by-FR. Never implement multiple FRs in one pass.
2. Before writing code, state which FR you're implementing and the files you'll touch.
3. Prefer boring, readable code over clever code — this repo is read by interviewers.
4. Every endpoint that mutates state gets an audit log entry (habit from regulated software).
5. No secrets in code. .env.example documents required vars.
6. After implementing, summarize key decisions in 3 bullets so the owner can explain them.

## Conventions
- Conventional commits referencing FRs: feat(scope): description (FR-n)
- Tests colocated in __tests__/ or *.test.js
- Errors: consistent JSON envelope { error, detail? }
