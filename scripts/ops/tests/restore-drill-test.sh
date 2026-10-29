#!/usr/bin/env bash
# Automated restore drill for the developer Compose stack.
#
# Proves the backup -> mutate -> restore -> verify loop end to end against a
# throwaway stack with its own compose project name, so its volumes never
# touch the developer's: seed data through the admin API, take a backup
# through scripts/ops/safe-zone.sh, verify its checksum manifest, delete the
# seeded data, restore, and confirm both the restored SQLite file / Redis
# state and the live API match the backup.
#
# Requires docker and a network that reaches the configured public DNS
# upstreams. Diagnostics are written to tmp/restore-drill/ on failure; the
# stack is torn down and every stashed file restored in every outcome.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_root"

project='restore-drill'
COMPOSE_STACK=(docker compose -p "$project")
compose_args=(-f docker-compose.yml -f docker-compose.dev.yml)
diag_dir="$repo_root/tmp/restore-drill"

env_file="$repo_root/.env"
env_backup="$repo_root/.env.restore-drill-backup"
host_db="$repo_root/data/safe-zone.db"
host_db_prestine="$repo_root/tmp/restore-drill-host-db.prestine"
backup_root=""

log() { printf '[restore-drill] %s\n' "$*"; }

collect_diagnostics() {
  mkdir -p "$diag_dir"
  "${COMPOSE_STACK[@]}" "${compose_args[@]}" ps -a >"$diag_dir/ps.txt" 2>&1 || true
  "${COMPOSE_STACK[@]}" "${compose_args[@]}" logs --no-color >"$diag_dir/logs.txt" 2>&1 || true
  log "diagnostics written to $diag_dir"
}

cleanup() {
  rc=$?
  if [ "$rc" -ne 0 ]; then
    collect_diagnostics
  fi
  "${COMPOSE_STACK[@]}" "${compose_args[@]}" down -v --remove-orphans --timeout 20 >/dev/null 2>&1 || true
  # The dev stack keeps SQLite in a named volume, but the restore step also
  # writes a host-side copy at data/safe-zone.db; put whatever was there back.
  rm -f "$host_db"
  if [ -f "$host_db_prestine" ]; then
    mv "$host_db_prestine" "$host_db"
  fi
  rm -f "$env_file"
  if [ -e "$env_backup" ]; then
    mv "$env_backup" "$env_file"
  fi
  if [ -n "$backup_root" ] && [ -d "$backup_root" ]; then
    rm -rf "$backup_root"
  fi
  exit "$rc"
}
trap cleanup EXIT

wait_http() {
  url=$1
  name=$2
  local deadline=$((SECONDS + 240))
  until curl -fsS --max-time 5 "$url" >/dev/null; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      log "TIMEOUT waiting for $name at $url"
      return 1
    fi
    sleep 2
  done
  log "$name ready"
}

api_brands() {
  curl -fsS --max-time 20 -H "Authorization: Bearer $1" http://127.0.0.1:8080/v1/brands
}

api_count_brands() {
  # One "id" key per brand object in the items array.
  api_brands "$1" | grep -o '"id":' | wc -l | tr -d ' '
}

# --- Preconditions ---------------------------------------------------------------
docker info >/dev/null 2>&1 || {
  log "FATAL: docker daemon not reachable"
  exit 1
}
mkdir -p "$diag_dir"
if [ -e "$env_file" ]; then
  mv "$env_file" "$env_backup"
  log "backed up an existing .env; it is restored on exit"
fi
cp .env.example "$env_file"
# The drill drives more mutations per minute than the shipped rate limits
# allow a real operator (burst 5 on the override tier covers 3 of the drill's
# 6 back-to-back mutations); the drill is not testing the limiter.
cat >>"$env_file" <<'EOF'
SAFE_ZONE_RATELIMIT_OVERRIDE_RPM=600
SAFE_ZONE_RATELIMIT_OVERRIDE_BURST=50
SAFE_ZONE_RATELIMIT_ANALYZE_RPM=600
SAFE_ZONE_RATELIMIT_ANALYZE_BURST=50
SAFE_ZONE_RATELIMIT_AUTH_RPM=60
SAFE_ZONE_RATELIMIT_AUTH_BURST=20
EOF
if [ -f "$host_db" ]; then
  mkdir -p "$(dirname "$host_db_prestine")"
  cp "$host_db" "$host_db_prestine"
  log "host SQLite file exists; it is put back after the drill"
fi
backup_root="$(mktemp -d)"

# --- Boot an isolated stack -------------------------------------------------------
log "starting an isolated stack (project $project); this builds the images on a cold runner"
"${COMPOSE_STACK[@]}" "${compose_args[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${COMPOSE_STACK[@]}" "${compose_args[@]}" up -d --build --wait --wait-timeout 300 redis core-api dns-resolver
wait_http http://127.0.0.1:8080/readyz "core-api /readyz"

secrets_file=/app/tmp/local_admin_secrets.txt
secrets="$("${COMPOSE_STACK[@]}" "${compose_args[@]}" exec -T core-api sh -c "cat '$secrets_file'")"
admin_api_key="$(printf '%s\n' "$secrets" | sed -n 's/^SAFE_ZONE_ADMIN_API_KEY=//p')"
[ -n "$admin_api_key" ] || {
  log "FATAL: generated admin API key missing from $secrets_file"
  exit 1
}

# --- Seed data through the admin API ----------------------------------------------
# The store ships with built-in brand rules, so every count assertion is a
# delta against the pre-seed baseline rather than an absolute number.
initial_count="$(api_count_brands "$admin_api_key")"
log "baseline brand count: $initial_count"

seeded_ids=()
for pair in 'restore-drill-a restore-drill-a.invalid' \
            'restore-drill-b restore-drill-b.invalid' \
            'restore-drill-c restore-drill-c.invalid'; do
  name=${pair%% *}
  domain=${pair#* }
  code="$(curl -sS --max-time 20 -o "$diag_dir/seed-out.json" -w '%{http_code}' \
    -X POST -H "Authorization: Bearer $admin_api_key" -H 'Content-Type: application/json' \
    -d "{\"name\":\"$name\",\"official_domain\":\"$domain\",\"alt_domains\":[]}" \
    http://127.0.0.1:8080/v1/brands)"
  [ "$code" = "201" ] || {
    log "FATAL: seeding brand $name returned HTTP $code"
    exit 1
  }
  seeded_ids+=("$(sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p' "$diag_dir/seed-out.json")")
done
count="$(api_count_brands "$admin_api_key")"
[ "$count" = "$((initial_count + 3))" ] || {
  log "FATAL: expected $((initial_count + 3)) brands after seeding, saw $count"
  exit 1
}
log "seeded 3 brands through the admin API (ids: ${seeded_ids[*]})"

# One analysis so the Redis state has a durable-looking entry for the drill to
# verify; the threat/analysis cache is the Redis side of the backup.
analyze_code="$(curl -sS --max-time 30 -o "$diag_dir/analyze-out.json" -w '%{http_code}' \
  -X POST -H "Authorization: Bearer $admin_api_key" -H 'Content-Type: application/json' \
  -d '{"domain":"restore-drill-redis-check.example"}' \
  http://127.0.0.1:8080/v1/analyze)"
[ "$analyze_code" = "200" ] || {
  log "FATAL: seeding the analysis cache entry returned HTTP $analyze_code"
  exit 1
}
log "seeded one analysis cache entry in Redis"

# --- Backup through the ops entrypoint ---------------------------------------------
SAFE_ZONE_SKIP_MISE=1 SAFE_ZONE_STACK=dev SAFE_ZONE_COMPOSE="${COMPOSE_STACK[*]}" \
  SAFE_ZONE_BACKUP_DIR="$backup_root" \
  sh scripts/ops/safe-zone.sh backup
backup_path="$(for entry in "$backup_root"/*; do [ -d "$entry" ] && printf '%s\n' "$entry"; done | sort | tail -n 1)"
[ -n "$backup_path" ] && [ -f "$backup_path/safe-zone.db" ] || {
  log "FATAL: backup did not produce a SQLite snapshot under $backup_root"
  exit 1
}
( cd "$backup_path" && sha256sum -c SHA256SUMS ) || {
  log "FATAL: backup checksum manifest does not verify"
  exit 1
}
backup_db_checksum="$(sha256sum "$backup_path/safe-zone.db" | awk '{print $1}')"
log "backup verified at $backup_path (db checksum ${backup_db_checksum:0:12}...)"

# --- Mutate: wipe the seeded state so restore has something to undo -----------------
for id in "${seeded_ids[@]}"; do
  code="$(curl -sS --max-time 20 -o /dev/null -w '%{http_code}' \
    -X DELETE -H "Authorization: Bearer $admin_api_key" \
    "http://127.0.0.1:8080/v1/brands?id=$id")"
  [ "$code" = "200" ] || {
    log "FATAL: deleting brand $id returned HTTP $code"
    exit 1
  }
done
count="$(api_count_brands "$admin_api_key")"
[ "$count" = "$initial_count" ] || {
  log "FATAL: expected $initial_count brands after the destructive mutation, saw $count"
  exit 1
}
log "mutation applied: seeded brands deleted (restore must undo this)"

# --- Restore through the ops entrypoint ---------------------------------------------
SAFE_ZONE_SKIP_MISE=1 SAFE_ZONE_STACK=dev SAFE_ZONE_COMPOSE="${COMPOSE_STACK[*]}" \
  SAFE_ZONE_BACKUP_DIR="$backup_root" \
  sh scripts/ops/safe-zone.sh restore "$backup_path"
wait_http http://127.0.0.1:8080/readyz "core-api /readyz after restore"

# The restored SQLite file is written to the host path before the stack comes
# back, so compare it before any API traffic can append telemetry.
[ -f "$host_db" ] || {
  log "FATAL: restored host SQLite file missing at $host_db"
  exit 1
}
restored_checksum="$(sha256sum "$host_db" | awk '{print $1}')"
[ "$restored_checksum" = "$backup_db_checksum" ] || {
  log "FATAL: restored SQLite checksum $restored_checksum != backup $backup_db_checksum"
  exit 1
}
log "restored SQLite file matches the backup checksum"

redis_keys="$("${COMPOSE_STACK[@]}" "${compose_args[@]}" exec -T redis \
  redis-cli --scan --pattern 'safe-zone:analysis:restore-drill-redis-check.example*' | wc -l | tr -d ' ')"
[ "$redis_keys" -ge 1 ] || {
  log "FATAL: Redis analysis cache entry did not survive the restore"
  exit 1
}
log "Redis analysis cache entry survived the restore"

# --- Verify the live API serves the backup's data ------------------------------------
count="$(api_count_brands "$admin_api_key")"
[ "$count" = "$((initial_count + 3))" ] || {
  log "FATAL: expected $((initial_count + 3)) brands after restore, saw $count"
  exit 1
}
brands="$(api_brands "$admin_api_key")"
for name in restore-drill-a restore-drill-b restore-drill-c; do
  printf '%s' "$brands" | grep -q "\"name\":\"$name\"" || {
    log "FATAL: brand $name missing from the restored API state"
    exit 1
  }
done
log "restored API state matches the backup (3 brands, names verified)"

log "RESTORE DRILL PASS"
