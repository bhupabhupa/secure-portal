# Deploying Secure Portal

Production-shaped deployment on one VM behind Caddy (TLS + routing). This is
where the README's hardening checklist gets cashed in: Keycloak runs in
**production mode** (`start`) with Postgres, behind real TLS.

Host baseline (Docker, `web` network, firewall, Caddy) is identical to the
companion project's guide — see
[labdocs-ai/docs/DEPLOYMENT.md](https://github.com/bhupabhupa/labdocs-ai/blob/main/docs/DEPLOYMENT.md).

## 1. Configure

```bash
git clone https://github.com/bhupabhupa/secure-portal && cd secure-portal

cat > .env <<'EOF'
DEMO_DOMAIN=<ip-with-dashes>.nip.io
KC_DB_PASSWORD=<random string>
KEYCLOAK_ADMIN_PASSWORD=<STRONG - this admin console is on the internet>
EOF

# Render the production realm (public redirect URIs + container-DNS backchannel URL)
DEMO_DOMAIN=<ip-with-dashes>.nip.io ./scripts/render-prod-realm.sh
```

## 2. Start

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

## 3. Caddy site block

Add to the host's `~/caddy/Caddyfile` (see labdocs guide for the Caddy setup):

```
portal.<IP-DASHED>.nip.io {
  handle /api/* { reverse_proxy portal-api:4000 }
  handle        { reverse_proxy portal-web:80 }
}
auth.<IP-DASHED>.nip.io {
  reverse_proxy keycloak:8080
}
```

## 4. What changed vs. local dev (and why)

| Local dev | Production | Why |
|---|---|---|
| `start-dev`, dev-file DB | `start` + Postgres volume | dev mode is explicitly not for the internet; sessions/users survive restarts |
| `KC_HOSTNAME=localhost` | `KC_HOSTNAME=auth.<domain>`, `KC_PROXY_HEADERS=xforwarded` | issuer must match the public URL; TLS terminates at Caddy |
| backchannel → `host.docker.internal:4000` | → `http://portal-api:4000` | host.docker.internal is Docker-Desktop-only; container DNS is the portable answer |
| client hardcodes localhost | `VITE_AUTH_URL` / `VITE_API_URL` build args | 12-factor config; `""` API base = same-origin via proxy (no CORS) |
| admin/admin | strong `KEYCLOAK_ADMIN_PASSWORD` | the admin console is publicly reachable |

Demo users (`admin`, `manager+001@kc.local`, `viewer+001@kc.local`, password
`password`) are intentionally kept — they ARE the demo. They hold no real data
and the realm is isolated.

## 5. Verify after deploy

1. `https://portal.<domain>` → login as each demo user → role-gated UI
2. Viewer token replayed against `POST /api/runs` → 403 + `ACCESS_DENIED` audit row
3. Logout → replay the still-unexpired admin token → 401 `Session has been revoked`
   (back-channel logout over container DNS)
4. Audit rows survive `docker compose restart portal-api` (SQLite volume)

## Ops

```bash
git pull && docker compose -f docker-compose.prod.yml up -d --build  # update
docker compose -f docker-compose.prod.yml logs -f keycloak           # logs
```
