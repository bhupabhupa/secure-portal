#!/usr/bin/env bash
# Render keycloak/realm-export.prod.json from the dev realm export:
# swaps localhost URLs for the public domain and points back-channel logout
# at the API's container DNS name (host.docker.internal is Docker-Desktop-only).
#
# Usage: DEMO_DOMAIN=<ip-with-dashes>.nip.io ./scripts/render-prod-realm.sh
set -euo pipefail

: "${DEMO_DOMAIN:?Set DEMO_DOMAIN, e.g. DEMO_DOMAIN=141-148-10-20.nip.io}"
SCHEME="${DEMO_SCHEME:-https}"

src="$(dirname "$0")/../keycloak/realm-export.json"
dst="$(dirname "$0")/../keycloak/realm-export.prod.json"

sed \
  -e "s|http://localhost:5173|${SCHEME}://portal.${DEMO_DOMAIN}|g" \
  -e "s|http://host.docker.internal:4000|http://portal-api:4000|g" \
  "$src" > "$dst"

echo "Rendered $dst for ${SCHEME}://portal.${DEMO_DOMAIN}"
