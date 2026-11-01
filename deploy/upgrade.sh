#!/usr/bin/env bash
# Upgrade a Brod Compose install to a released version, with a database backup
# first and an automatic rollback to the previous version if it doesn't come up
# healthy. Run on the server from the directory holding docker-compose.yml and .env:
#
#   deploy/upgrade.sh 0.2.0
#
# The deploy workflow (.github/workflows/deploy.yml) runs this over SSH.
# A rollback only switches the images back; it never restores the database.
# The dump taken before the upgrade is kept in ./backups if you need it.
set -euo pipefail

version="${1:?usage: upgrade.sh <version, e.g. 0.2.0>}"
version="${version#v}"
dir="${BROD_DIR:-$(pwd)}"
cd "$dir"
[ -f docker-compose.yml ] && [ -f .env ] || { echo "no docker-compose.yml/.env in $dir" >&2; exit 1; }

current() { sed -n 's/^BROD_VERSION=//p' .env | tail -1; }
set_version() {
  if grep -q '^BROD_VERSION=' .env; then
    sed -i.bak "s/^BROD_VERSION=.*/BROD_VERSION=$1/" .env && rm -f .env.bak
  else
    printf '\nBROD_VERSION=%s\n' "$1" >> .env
  fi
}
healthy() {
  # The brod container's own healthcheck calls /healthz on its local listener.
  for _ in $(seq 1 60); do
    id=$(docker compose ps -q brod)
    state=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$id" 2>/dev/null || true)
    [ "$state" = healthy ] && return 0
    sleep 5
  done
  return 1
}

prev="$(current)"
echo "current: ${prev:-latest}  target: $version"
if [ "$prev" = "$version" ]; then echo "already on $version"; exit 0; fi

BROD_VERSION="$version" docker compose pull -q brod runtime

mkdir -p backups
dump="backups/brod-pre-$version-$(date -u +%Y%m%dT%H%M%SZ).dump"
docker compose exec -T postgres pg_dump -U brod -Fc brod > "$dump"
echo "backup: $dump ($(du -h "$dump" | cut -f1))"
# Keep the last 10 pre-upgrade dumps.
ls -1t backups/brod-pre-*.dump 2>/dev/null | tail -n +11 | xargs -r rm -f

set_version "$version"
docker compose up -d
if healthy; then
  echo "OK: brod $version is healthy"
  docker image prune -f >/dev/null || true
  exit 0
fi

echo "FAILED: brod $version did not become healthy; last logs:" >&2
docker compose logs --tail 60 brod >&2 || true
if [ -n "$prev" ]; then
  echo "rolling back to $prev" >&2
  set_version "$prev"
  docker compose up -d
  healthy && echo "rolled back to $prev (healthy)" >&2 || echo "rollback to $prev is NOT healthy either" >&2
fi
exit 1
