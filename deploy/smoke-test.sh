#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Smoke-test the production stack (Brod, Postgres, the runtime, Caddy from deploy/compose.caddy.yml) on this machine,
# with Caddy's local CA instead of Let's Encrypt and brod.test / *.*.apps.brod.test pointed at 127.0.0.1 by curl.
# Needs the images built first:  docker compose build
# Usage: deploy/smoke-test.sh        (leaves the "brodsmoke" project running: see the end)
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
sed 's|^\temail {$ACME_EMAIL}|\temail {$ACME_EMAIL}\n\tlocal_certs|' deploy/Caddyfile > "$work/Caddyfile"
cat > "$work/override.yml" <<EOF
services:
  brod:
    env_file: !reset []
    environment:
      DEV_MODE: "1"
      BROD_PUBLIC_URL: https://brod.test
      APPS_DOMAIN: apps.brod.test
      ADMIN_SECRET: smoke-admin-secret
      IDENTITY_SECRET: smoke-identity-secret
      SECRETS_KEY: smoke-secrets-key-0123456789
      BROD_RUNTIME_SECRET: smoke-runtime-secret-0123456789
  caddy:
    ports: !override
      - "127.0.0.1:443:443"
    volumes: !override
      - $work/Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
      - caddy-config:/config
EOF
export BROD_API_HOST=brod.test APPS_DOMAIN=apps.brod.test ACME_EMAIL=smoke@example.com
compose() { docker compose -f docker-compose.yml -f deploy/compose.caddy.yml -f "$work/override.yml" -p brodsmoke "$@"; }
# docker-compose.yml names an env_file that must exist; the override replaces what it would set.
if [ ! -f .env ]; then touch .env; trap 'rm -f .env' EXIT; fi
compose up -d --no-build --wait

export no_proxy='*' NO_PROXY='*'
fail=0
check() { if [ "$2" = "$3" ]; then echo "PASS  $1"; else echo "FAIL  $1: got [$2], want [$3]"; fail=1; fi; }
R=(--resolve brod.test:443:127.0.0.1)
c() { curl -sk "$@"; }

check "health through Caddy over HTTPS" "$(c "${R[@]}" -o /dev/null -w '%{http_code}' https://brod.test/healthz)" 200
check "internal endpoints are refused through Caddy" "$(c "${R[@]}" -o /dev/null -w '%{http_code}' 'https://brod.test/_caddy/ask?domain=brod.test')" 404
set +e; c --resolve nope.apps.brod.test:443:127.0.0.1 -o /dev/null https://nope.apps.brod.test/; tls=$?; set -e
check "no certificate for an app that does not exist (TLS refused)" "$tls" 35

email="smoke-$RANDOM@acme.test"
token=$(c "${R[@]}" -H 'content-type: application/json' -d "{\"email\":\"$email\"}" https://brod.test/auth/start | grep -o 'token=[0-9a-f]*' | cut -d= -f2)
platform=$(c "${R[@]}" -D - -o /dev/null -H 'origin: https://brod.test' --data "token=$token" https://brod.test/auth/verify | grep -io '__Host-brod_platform=[0-9a-f]*' || true)
check "the platform cookie has the __Host- prefix" "${platform%%=*}" "__Host-brod_platform"
ws=$(c "${R[@]}" -b "$platform" -H 'origin: https://brod.test' -H 'content-type: application/json' -d '{"name":"Smoke","accept_terms":true}' https://brod.test/v1/workspaces | sed -nE 's/.*"workspace": "([^"]+)".*/\1/p' | head -n1)
agent=$(c "${R[@]}" -b "$platform" -H 'origin: https://brod.test' -H 'content-type: application/json' -d '{"name":"smoke"}' https://brod.test/v1/tokens | sed -nE 's/.*"token": "([^"]+)".*/\1/p')
slug=$(c "${R[@]}" -H "authorization: Bearer $agent" -H 'content-type: application/json' \
  -d '{"name":"Hello","files":[{"path":"_worker.js","content":"export default { fetch: r => new Response(\"hi \" + r.headers.get(\"x-brod-user-email\")) }"}]}' \
  https://brod.test/v1/deploys | sed -nE 's/.*"app": "([^"]+)".*/\1/p' | head -n1)
A=(--resolve "$slug.$ws.apps.brod.test:443:127.0.0.1")
check "a new app's host gets a certificate on demand and sends visitors to sign in" "$(c "${A[@]}" -o /dev/null -w '%{http_code}' "https://$slug.$ws.apps.brod.test/")" 302
handoff=$(c "${R[@]}" -b "$platform" -o /dev/null -w '%{redirect_url}' "https://brod.test/auth/app?app=$slug.$ws&return=/")
session=$(c "${A[@]}" -D - -o /dev/null "$handoff" | grep -io '__Host-brod_session=[0-9a-f]*' || true)
check "the app cookie has the __Host- prefix" "${session%%=*}" "__Host-brod_session"
check "the server app answers through Caddy with the signed-in person" "$(c "${A[@]}" -b "$session" "https://$slug.$ws.apps.brod.test/")" "hi $email"
check "an unprefixed cookie planted by another app is ignored" "$(c "${A[@]}" -b "brod_session=${session#*=}" -o /dev/null -w '%{http_code}' "https://$slug.$ws.apps.brod.test/")" 302

compose up -d --no-build --force-recreate --no-deps --wait brod >/dev/null 2>&1
check "server apps still work after Brod's container is recreated" "$(c "${A[@]}" -b "$session" "https://$slug.$ws.apps.brod.test/")" "hi $email"

echo
echo "Stop and remove it with: docker compose -p brodsmoke down -v"
exit $fail
