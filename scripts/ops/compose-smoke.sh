#!/usr/bin/env bash
# Runtime smoke test for the developer Compose stack.
#
# Bootstraps a throwaway stack from .env.example, then proves the things
# static checks cannot see: published ports actually answer, the resolver
# answers a real DoH query end to end, the admin API authenticates and
# mutates, and recreating core-api keeps the generated admin credentials
# (the app-tmp volume contract that regressed once, 2026-10-28).
#
# The stack runs with SAFE_ZONE_ENV=local and empty admin secrets, so
# core-api generates temporary credentials into /app/tmp/local_admin_secrets.txt
# and the script reads them back out of the container. They are never printed.
#
# Usage: bash scripts/ops/compose-smoke.sh
# Exits non-zero on the first failed check; failure diagnostics are written
# to tmp/compose-smoke/ for CI artifact upload.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.dev.yml)
DIAG_DIR="$REPO_ROOT/tmp/compose-smoke"
ENV_FILE="$REPO_ROOT/.env"
ENV_BACKUP="$REPO_ROOT/.env.compose-smoke-backup"

CORE_API_URL="http://127.0.0.1:8080"
RESOLVER_URL="http://127.0.0.1:8081"
# Bounded above by the job timeout; the stack itself must become healthy
# within this window or the smoke has failed its purpose.
WAIT_SECONDS=240

ADMIN_USERNAME="admin"
ADMIN_PASSWORD=""
ADMIN_API_KEY=""

log() { printf '[compose-smoke] %s\n' "$*"; }

collect_diagnostics() {
  mkdir -p "$DIAG_DIR"
  "${COMPOSE[@]}" ps -a >"$DIAG_DIR/ps.txt" 2>&1 || true
  "${COMPOSE[@]}" logs --no-color >"$DIAG_DIR/logs.txt" 2>&1 || true
  "${COMPOSE[@]}" config >"$DIAG_DIR/rendered-config.json" 2>&1 || true
  log "diagnostics written to $DIAG_DIR"
}

restore_env() {
  rm -f "$ENV_FILE"
  if [ -e "$ENV_BACKUP" ]; then
    mv "$ENV_BACKUP" "$ENV_FILE"
  fi
}

teardown_stack() {
  "${COMPOSE[@]}" down -v --remove-orphans --timeout 20 >/dev/null 2>&1 || true
}

cleanup() {
  rc=$?
  if [ "$rc" -ne 0 ]; then
    collect_diagnostics
  fi
  teardown_stack
  restore_env
  exit "$rc"
}
trap cleanup EXIT

wait_http() {
  url=$1
  name=$2
  deadline=$((SECONDS + WAIT_SECONDS))
  # The body is discarded with a shell redirect, not `curl -o /dev/null`: on
  # Windows the native curl build only resolves the /dev/null argument through
  # MSYS path conversion, which an invocation-level MSYS_NO_PATHCONV disables.
  until curl -fsS --max-time 5 "$url" >/dev/null; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      log "TIMEOUT waiting for $name at $url after ${WAIT_SECONDS}s"
      return 1
    fi
    sleep 2
  done
  log "$name ready at $url"
}

http_code() {
  # Prints the HTTP status code; the body is written to the file in $1.
  curl -sS --max-time 20 -o "$1" -w '%{http_code}' "${@:2}"
}

# --- Precondition: the developer stack must exist with a usable .env ----------
if [ ! -f .env.example ]; then
  log "FATAL: .env.example not found; run from the repository root"
  exit 1
fi
docker info >/dev/null 2>&1 || {
  log "FATAL: docker daemon not reachable"
  exit 1
}

if [ -e "$ENV_FILE" ]; then
  mv "$ENV_FILE" "$ENV_BACKUP"
  log "backed up an existing .env; it is restored on exit"
fi
# .env.example keeps the admin secrets empty on purpose: core-api (env=local)
# then generates temporary credentials, which is exactly the persistence path
# the recreate step below verifies.
cp .env.example "$ENV_FILE"
ADMIN_USERNAME="$(sed -n 's/^SAFE_ZONE_ADMIN_USERNAME=//p' "$ENV_FILE")"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"

# --- Boot the developer stack (core services only; no ui-dev, no feed sync) ---
log "building and starting redis + core-api + dns-resolver (this builds the images)"
SECONDS=0
"${COMPOSE[@]}" up -d --build --wait --wait-timeout "$WAIT_SECONDS" redis core-api dns-resolver
log "stack up in ${SECONDS}s"

# --- Health and status endpoints through the published ports ------------------
wait_http "$CORE_API_URL/healthz" "core-api /healthz"
wait_http "$CORE_API_URL/readyz" "core-api /readyz"
wait_http "$RESOLVER_URL/healthz" "dns-resolver /healthz"
wait_http "$RESOLVER_URL/readyz" "dns-resolver /readyz"
wait_http "$RESOLVER_URL/" "dns-resolver status"

# --- Generated admin credentials survived to disk ------------------------------
# The container path is passed through `sh -c` so Git Bash on Windows does not
# rewrite the POSIX path into a host path before docker sees it (MSYS path
# conversion mangles a bare /app/... argument; a quoted one-liner is left alone).
secrets_file=/app/tmp/local_admin_secrets.txt
secrets="$("${COMPOSE[@]}" exec -T core-api sh -c "cat '$secrets_file'")"
ADMIN_PASSWORD="$(printf '%s\n' "$secrets" | sed -n 's/^SAFE_ZONE_ADMIN_PASSWORD=//p')"
ADMIN_API_KEY="$(printf '%s\n' "$secrets" | sed -n 's/^SAFE_ZONE_ADMIN_API_KEY=//p')"
if [ -z "$ADMIN_PASSWORD" ] || [ -z "$ADMIN_API_KEY" ]; then
  log "FATAL: generated admin credentials missing from $secrets_file"
  exit 1
fi
secrets_digest="$("${COMPOSE[@]}" exec -T core-api sh -c "sha256sum '$secrets_file'" | awk '{print $1}')"
log "generated admin credentials present (file digest ${secrets_digest:0:12}...)"

# --- DoH: a real query for example.com through the published port --------------
mkdir -p "$DIAG_DIR"
# DNS wire format: ID 0, RD set, one question, example.com A IN.
printf '\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' \
  >"$DIAG_DIR/doh-query.bin"

code="$(http_code "$DIAG_DIR/doh-post-response.bin" \
  -H 'Content-Type: application/dns-message' \
  --data-binary @"$DIAG_DIR/doh-query.bin" \
  "$RESOLVER_URL/dns-query")"
[ "$code" = "200" ] || {
  log "FATAL: DoH POST returned HTTP $code, expected 200"
  exit 1
}
assert_doh_answer() {
  file=$1
  kind=$2
  [ -s "$file" ] || {
    log "FATAL: DoH $kind response is empty"
    return 1
  }
  rcode=$(( $(od -An -tu1 -j3 -N1 "$file" | tr -d ' ') & 15 ))
  ancount=$(( $(od -An -tu1 -j6 -N1 "$file" | tr -d ' ') * 256 + $(od -An -tu1 -j7 -N1 "$file" | tr -d ' ') ))
  [ "$rcode" -eq 0 ] || {
    log "FATAL: DoH $kind response RCODE=$rcode, expected 0 (NOERROR)"
    return 1
  }
  [ "$ancount" -ge 1 ] || {
    log "FATAL: DoH $kind response carries no answer records"
    return 1
  }
  log "DoH $kind answered example.com with $ancount record(s), RCODE=0"
}
assert_doh_answer "$DIAG_DIR/doh-post-response.bin" POST

b64url="$(base64 -w0 "$DIAG_DIR/doh-query.bin" | tr '+/' '-_' | tr -d '=')"
code="$(http_code "$DIAG_DIR/doh-get-response.bin" "$RESOLVER_URL/dns-query?dns=$b64url")"
[ "$code" = "200" ] || {
  log "FATAL: DoH GET returned HTTP $code, expected 200"
  exit 1
}
assert_doh_answer "$DIAG_DIR/doh-get-response.bin" GET

# --- Admin API: login, authenticate, one mutation + read-back + delete ---------
mkdir -p "$DIAG_DIR"
code="$(http_code "$DIAG_DIR/login.json" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ADMIN_USERNAME\",\"password\":\"$ADMIN_PASSWORD\"}" \
  "$CORE_API_URL/v1/auth/login")"
[ "$code" = "200" ] || {
  log "FATAL: admin login returned HTTP $code, expected 200"
  exit 1
}
log "admin login OK"

code="$(http_code "$DIAG_DIR/status.json" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  "$CORE_API_URL/v1/status")"
[ "$code" = "200" ] || {
  log "FATAL: GET /v1/status with the generated API key returned HTTP $code, expected 200"
  exit 1
}
log "GET /v1/status with generated API key OK"

brand_body='{"name":"compose-smoke","official_domain":"compose-smoke.invalid","alt_domains":[]}'
code="$(http_code "$DIAG_DIR/brand-create.json" \
  -X POST -H "Authorization: Bearer $ADMIN_API_KEY" -H 'Content-Type: application/json' \
  -d "$brand_body" \
  "$CORE_API_URL/v1/brands")"
[ "$code" = "201" ] || {
  log "FATAL: POST /v1/brands returned HTTP $code, expected 201"
  exit 1
}
brand_id="$(sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p' "$DIAG_DIR/brand-create.json")"
[ -n "$brand_id" ] || {
  log "FATAL: POST /v1/brands response has no id"
  exit 1
}
log "created brand id=$brand_id"

code="$(http_code "$DIAG_DIR/brand-read.json" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  "$CORE_API_URL/v1/brands?id=$brand_id")"
[ "$code" = "200" ] || {
  log "FATAL: GET /v1/brands?id=$brand_id returned HTTP $code, expected 200"
  exit 1
}
grep -q '"name":"compose-smoke"' "$DIAG_DIR/brand-read.json" || {
  log "FATAL: brand read-back does not match the created brand"
  exit 1
}
log "brand read-back OK"

code="$(http_code "$DIAG_DIR/brand-delete.json" \
  -X DELETE -H "Authorization: Bearer $ADMIN_API_KEY" \
  "$CORE_API_URL/v1/brands?id=$brand_id")"
[ "$code" = "200" ] || {
  log "FATAL: DELETE /v1/brands?id=$brand_id returned HTTP $code, expected 200"
  exit 1
}
code="$(http_code /dev/null -H "Authorization: Bearer $ADMIN_API_KEY" "$CORE_API_URL/v1/brands?id=$brand_id")"
[ "$code" = "404" ] || {
  log "FATAL: brand still readable after delete (HTTP $code, expected 404)"
  exit 1
}
log "brand delete + read-after-delete OK"

# --- Recreating core-api must not rotate the generated credentials -------------
"${COMPOSE[@]}" up -d --wait --wait-timeout "$WAIT_SECONDS" --force-recreate core-api
wait_http "$CORE_API_URL/readyz" "core-api /readyz after recreate"

secrets_digest_after="$("${COMPOSE[@]}" exec -T core-api sh -c "sha256sum '$secrets_file'" | awk '{print $1}')"
[ "$secrets_digest_after" = "$secrets_digest" ] || {
  log "FATAL: $secrets_file changed across core-api recreation (was ${secrets_digest:0:12}..., now ${secrets_digest_after:0:12}...)"
  exit 1
}
log "generated secrets file unchanged across recreation"

code="$(http_code /dev/null -H "Authorization: Bearer $ADMIN_API_KEY" "$CORE_API_URL/v1/status")"
[ "$code" = "200" ] || {
  log "FATAL: pre-recreate API key rejected after recreation (HTTP $code, expected 200)"
  exit 1
}
log "pre-recreate API key still accepted"

log "SMOKE PASS"
