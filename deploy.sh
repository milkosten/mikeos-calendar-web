#!/usr/bin/env bash
# Idempotent deploy of MikeCalendar UI to the 242 box. Builds/starts ONLY
# mikeos-calendar; appends the calendar.osmike.com Caddy block IF missing then
# `caddy reload`. NEVER touches other containers. NEVER sed -i the Caddyfile.
set -euo pipefail
APP_DIR="/opt/mikeos-calendar"
CADDYFILE="/opt/mikephotos/deploy/Caddyfile"
[ -f "${APP_DIR}/.env" ] || { echo "MISSING ${APP_DIR}/.env"; exit 1; }
echo "==> build + up"; cd "${APP_DIR}"; docker compose --env-file .env up -d --build
if ! grep -q "^calendar.osmike.com {" "${CADDYFILE}"; then
  cat >> "${CADDYFILE}" <<'BLK'

calendar.osmike.com {
	encode zstd gzip
	reverse_proxy mikeos-calendar:8096
}
BLK
  echo "   appended calendar.osmike.com"
else echo "   calendar.osmike.com already present"; fi
echo "==> caddy reload"; docker exec deploy-caddy-1 caddy reload --config /etc/caddy/Caddyfile
sleep 3; echo "==> health:"; docker exec mikeos-calendar wget -qO- http://localhost:8096/healthz 2>/dev/null || true; echo
