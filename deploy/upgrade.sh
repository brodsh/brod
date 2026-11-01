#!/usr/bin/env bash
# Upgrade a Brod Compose install to a released version:
#   hold if the release changed compose/Caddy files -> pull images -> backup ->
#   pin BROD_VERSION in .env -> up --wait -> health check -> roll back if unhealthy.
#
#   deploy/upgrade.sh 0.2.0
#
# Run it from (or point BROD_DIR at) the directory holding docker-compose.yml and .env.
# Extra compose files (e.g. deploy/compose.caddy.yml) are taken from COMPOSE_FILE in .env,
# which `docker compose` reads by itself.
#
# Optional environment:
#   BROD_BACKUP_CMD   backup command to run instead of the built-in pg_dump
#   BROD_HEALTH_URL   public URL to check after the stack is up (e.g. https://brod.sh/healthz)
#   BROD_FORCE=1      deploy even if compose/Caddy files changed upstream, or downgrade
#
# A rollback switches the images back; it never restores the database.
# Output lines starting with DEPLOYED / HOLD / FAILED / ROLLED BACK / ROLLBACK UNHEALTHY
# are what the deploy workflow reports.
set -euo pipefail

version="${1:?usage: upgrade.sh <version, e.g. 0.2.0>}"
version="${version#v}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "bad version: $version" >&2; exit 2; }
cd "${BROD_DIR:-$(pwd)}"
[ -f docker-compose.yml ] && [ -f .env ] || { echo "no docker-compose.yml/.env in $(pwd)" >&2; exit 2; }

exec 9>.upgrade.lock
flock -w 600 9 || { echo "FAILED: another upgrade is running" >&2; exit 1; }

log() { echo "$(date -u +%FT%TZ) $*"; }
current() { sed -n 's/^BROD_VERSION=//p' .env | tail -1; }
set_version() {
  if grep -q '^BROD_VERSION=' .env; then
    sed -i "s/^BROD_VERSION=.*/BROD_VERSION=$1/" .env
  else
    printf 'BROD_VERSION=%s\n' "$1" >> .env
  fi
}
healthy() {
  docker compose up -d --wait --wait-timeout 180 >/dev/null 2>&1 || return 1
  [ -n "${BROD_HEALTH_URL:-}" ] || return 0
  for _ in 1 2 3 4 5 6; do
    curl -fsS --max-time 10 -o /dev/null "$BROD_HEALTH_URL" && return 0
    sleep 5
  done
  return 1
}
newer() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$2" ]; }

prev="$(current)"
log "running ${prev:-unpinned}, target $version"
if [ "$prev" = "$version" ]; then log "DEPLOYED $version (already running)"; exit 0; fi
if [ -n "$prev" ] && ! newer "$prev" "$version" && [ "${BROD_FORCE:-}" != 1 ]; then
  log "HOLD $version: older than running $prev (set BROD_FORCE=1 to downgrade)"; exit 1
fi

# Compose and Caddy files on this machine are not updated by this script.
if [ "${BROD_FORCE:-}" != 1 ]; then
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  for f in docker-compose.yml deploy/compose.caddy.yml deploy/Caddyfile; do
    [ -f "$f" ] || continue
    curl -fsS --max-time 20 -o "$tmp/x" "https://raw.githubusercontent.com/brodsh/brod/v$version/$f" || continue
    cmp -s "$tmp/x" "$f" || { log "HOLD $version: $f changed upstream; update $(pwd)/$f by hand, then rerun"; exit 1; }
  done
fi

BROD_VERSION="$version" docker compose pull -q brod runtime

if [ -n "${BROD_BACKUP_CMD:-}" ]; then
  $BROD_BACKUP_CMD >/dev/null || { log "FAILED $version: pre-upgrade backup failed"; exit 1; }
  log "backup: $BROD_BACKUP_CMD ok"
else
  mkdir -p backups
  dump="backups/brod-pre-$version-$(date -u +%Y%m%dT%H%M%SZ).dump"
  docker compose exec -T postgres pg_dump -U brod -Fc brod > "$dump" \
    || { log "FAILED $version: pre-upgrade backup failed"; exit 1; }
  ls -1t backups/brod-pre-*.dump | tail -n +11 | xargs -r rm -f
  log "backup: $dump"
fi

set_version "$version"
if healthy; then
  log "DEPLOYED $version"
  docker image prune -f >/dev/null || true
  exit 0
fi

log "FAILED $version: unhealthy"
docker compose logs --since 5m brod 2>&1 | tail -20
if [ -n "$prev" ]; then
  set_version "$prev"
  if healthy; then log "ROLLED BACK to $prev"; else log "ROLLBACK UNHEALTHY: $prev also failed, restore from the backup"; fi
fi
exit 1
