#!/usr/bin/env sh
set -eu

compose="${SAFE_ZONE_COMPOSE:-docker compose}"
project_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
backup_dir="${SAFE_ZONE_BACKUP_DIR:-${project_dir}/backups}"
stack="${SAFE_ZONE_STACK:-production}"

cd "$project_dir"

log_info() {
  printf '%s\n' "$*"
}

log_warn() {
  printf 'WARN: %s\n' "$*" >&2
}

log_error() {
  printf 'ERROR: %s\n' "$*" >&2
}

compose_stack() {
  selected_stack="$1"
  shift
  case "$selected_stack" in
    production)
      $compose -f docker-compose.yml -f docker-compose.production.yml "$@"
      ;;
    dev)
      $compose -f docker-compose.yml -f docker-compose.dev.yml "$@"
      ;;
    *)
      log_error "unknown SAFE_ZONE_STACK: $selected_stack"
      exit 2
      ;;
  esac
}

compose_up_stack() {
  case "$stack" in
    production)
      compose_stack production --profile production-edge up -d
      ;;
    dev)
      compose_stack dev up -d
      ;;
  esac
}

compose_container_id() {
  service="$1"
  compose_stack "$stack" ps -q "$service" 2>/dev/null || true
}

compose_container_id_all() {
  service="$1"
  compose_stack "$stack" ps -aq "$service" 2>/dev/null || true
}

env_value() {
  key="$1"
  eval "value=\${$key:-}"
  if [ -n "$value" ]; then
    printf '%s' "$value"
    return 0
  fi

  if [ -f .env ]; then
    value="$(grep -E "^[[:space:]]*${key}=" .env | tail -n 1 | sed -E "s/^[[:space:]]*${key}=//" | tr -d '\r' || true)"
    value="$(printf '%s' "$value" | sed -E 's/^[[:space:]]*//; s/[[:space:]]*$//; s/^"//; s/"$//')"
    case "$value" in
      \'*\')
        value="${value#\'}"
        value="${value%\'}"
        ;;
    esac
    if [ -n "$value" ]; then
      printf '%s' "$value"
    fi
  fi
}

sqlite_runtime_path() {
  configured="$(env_value SAFE_ZONE_SQLITE_PATH || true)"
  if [ -z "$configured" ]; then
    configured="data/safe-zone.db"
  fi

  case "$configured" in
    /app/data/*)
      printf '%s/%s' "${project_dir}/data" "${configured#/app/data/}"
      ;;
    /*)
      printf '%s' "$configured"
      ;;
    ./*)
      printf '%s/%s' "$project_dir" "${configured#./}"
      ;;
    *)
      printf '%s/%s' "$project_dir" "$configured"
      ;;
  esac
}

quote_sqlite_path() {
  printf '%s' "$1" | sed "s/'/''/g"
}

backup_redis() {
  target="$1"
  log_info "Creating Redis snapshot..."
  compose_stack "$stack" exec -T redis redis-cli SAVE >/dev/null

  container_id="$(compose_container_id redis)"
  if [ -z "$container_id" ]; then
    log_warn "Redis container is not running; skipping Redis snapshot copy"
    return 0
  fi

  docker cp "${container_id}:/data/dump.rdb" "${target}/redis-dump.rdb"
}

backup_sqlite() {
  target="$1"
  source_db="$(sqlite_runtime_path)"
  target_db="${target}/safe-zone.db"

  if [ -f "$source_db" ]; then
    if command -v sqlite3 >/dev/null 2>&1; then
      log_info "Creating SQLite hot backup from ${source_db}..."
      escaped_target="$(quote_sqlite_path "$target_db")"
      sqlite3 "$source_db" ".backup '${escaped_target}'"
    else
      log_warn "sqlite3 CLI not found; copying SQLite database directly"
      cp "$source_db" "$target_db"
    fi
    return 0
  fi

  container_id="$(compose_container_id core-api)"
  if [ -n "$container_id" ]; then
    log_warn "Host SQLite database not found at ${source_db}; copying from core-api container"
    docker cp "${container_id}:/app/data/safe-zone.db" "$target_db" || log_warn "SQLite database not found in core-api container"
    return 0
  fi

  log_warn "SQLite database not found at ${source_db}; skipping SQLite backup"
}

copy_optional_snapshots() {
  target="$1"
  if [ -f .env ]; then
    cp .env "${target}/env.snapshot"
  fi
  if [ -f Caddyfile ]; then
    cp Caddyfile "${target}/Caddyfile.snapshot"
  fi
}

sync_offsite() {
  local_dir="$1"
  ts="$2"
  remote="$(env_value SAFE_ZONE_RCLONE_REMOTE || true)"
  dest="$(env_value SAFE_ZONE_RCLONE_DEST || true)"

  if [ -z "$remote" ]; then
    return 0
  fi
  if [ -z "$dest" ]; then
    dest="safe-zone-backups"
  fi
  if ! command -v rclone >/dev/null 2>&1; then
    log_error "SAFE_ZONE_RCLONE_REMOTE is configured but rclone is not installed; skipping offsite upload"
    return 0
  fi

  remote_name="${remote%:}"
  remote_target="${remote_name}:${dest}/${ts}"
  log_info "Uploading backup to ${remote_target}..."
  if rclone copy "$local_dir" "$remote_target"; then
    log_info "Offsite backup upload completed: ${remote_target}"
  else
    log_error "Offsite backup upload failed: ${remote_target}"
  fi
}

latest_backup_dir() {
  if [ ! -d "$backup_dir" ]; then
    return 1
  fi
  for entry in "$backup_dir"/*; do
    [ -d "$entry" ] || continue
    printf '%s\n' "$entry"
  done | sort | tail -n 1
}

resolve_backup_dir() {
  src="${1:-}"
  if [ -n "$src" ]; then
    if [ -d "$src" ]; then
      (CDPATH= cd -- "$src" && pwd)
      return 0
    fi
    if [ -f "$src" ]; then
      (CDPATH= cd -- "$(dirname -- "$src")" && pwd)
      return 0
    fi
    log_error "backup path not found: $src"
    exit 2
  fi

  latest="$(latest_backup_dir || true)"
  if [ -z "$latest" ]; then
    log_error "no backups found in ${backup_dir}"
    exit 2
  fi
  printf '%s' "$latest"
}

stop_for_restore() {
  log_info "Stopping services that may hold Redis/SQLite locks..."
  compose_stack "$stack" stop core-api dns-resolver feed-syncd redis >/dev/null 2>&1 || true
}

restore_sqlite() {
  src_dir="$1"
  src_db="${src_dir}/safe-zone.db"
  target_db="$(sqlite_runtime_path)"

  if [ ! -f "$src_db" ]; then
    log_warn "No safe-zone.db found in ${src_dir}; skipping SQLite restore"
    return 0
  fi

  mkdir -p "$(dirname -- "$target_db")"
  cp "$src_db" "$target_db"
  log_info "Restored SQLite database to ${target_db}"

  container_id="$(compose_container_id_all core-api)"
  if [ -n "$container_id" ]; then
    docker cp "$src_db" "${container_id}:/app/data/safe-zone.db" || log_warn "Could not copy SQLite database into core-api container volume"
  fi
}

restore_redis() {
  src_dir="$1"
  src_rdb="${src_dir}/redis-dump.rdb"
  if [ ! -f "$src_rdb" ]; then
    src_rdb="${src_dir}/dump.rdb"
  fi

  if [ ! -f "$src_rdb" ]; then
    log_warn "No redis-dump.rdb or dump.rdb found in ${src_dir}; skipping Redis restore"
    return 0
  fi

  container_id="$(compose_container_id_all redis)"
  if [ -z "$container_id" ]; then
    log_warn "Redis container does not exist yet; creating containers before Redis restore"
    compose_stack "$stack" up --no-start redis >/dev/null
    container_id="$(compose_container_id_all redis)"
  fi

  if [ -z "$container_id" ]; then
    log_warn "Could not locate Redis container; skipping Redis restore"
    return 0
  fi

  docker cp "$src_rdb" "${container_id}:/data/dump.rdb"
  log_info "Restored Redis snapshot from ${src_rdb}"
}

restore_env_notice() {
  src_dir="$1"
  if [ -f "${src_dir}/env.snapshot" ]; then
    log_warn "Environment snapshot available at ${src_dir}/env.snapshot. Review it and copy to .env manually if needed."
  fi
}

new_backup() {
  ts="$(date -u +%Y%m%d-%H%M%S)"
  target="${backup_dir}/${ts}"
  mkdir -p "$target"

  backup_redis "$target"
  copy_optional_snapshots "$target"
  backup_sqlite "$target"
  sync_offsite "$target" "$ts"
  log_info "Backup written to ${target}"
}

restore_backup() {
  src_dir="$(resolve_backup_dir "${1:-}")"
  log_info "Restoring backup from ${src_dir}"
  stop_for_restore
  restore_sqlite "$src_dir"
  restore_redis "$src_dir"
  restore_env_notice "$src_dir"
  log_info "Restarting stack..."
  compose_up_stack
  log_info "Restore completed"
}

resolve_feed_sources() {
  if [ -n "${SAFE_ZONE_AGENT_FEED_SOURCES:-}" ]; then
    printf '%s' "$SAFE_ZONE_AGENT_FEED_SOURCES"
    return 0
  fi

  case "${SAFE_ZONE_AGENT_FEED_PRESET:-}" in
    production-free)
      printf '%s' "https://urlhaus.abuse.ch/downloads/csv_recent/,https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
      return 0
      ;;
  esac

  if [ -n "${SAFE_ZONE_THREAT_FEED_SOURCE:-}" ]; then
    printf '%s' "$SAFE_ZONE_THREAT_FEED_SOURCE"
    return 0
  fi

  return 1
}

cmd="${1:-help}"
case "$cmd" in
  deploy)
    compose_stack production --profile production-edge up -d --build
    ;;
  deploy-dev)
    compose_stack dev up -d --build
    ;;
  status)
    compose_stack "$stack" ps
    echo
    wget -qO- http://127.0.0.1:8080/healthz || true
    echo
    wget -qO- http://127.0.0.1:8081/healthz || true
    echo
    ;;
  logs)
    compose_stack "$stack" logs -f --tail="${SAFE_ZONE_LOG_TAIL:-100}"
    ;;
  backup)
    new_backup
    ;;
  restore)
    restore_backup "${2:-}"
    ;;
  feed-sync)
    sources="$(resolve_feed_sources || true)"
    if [ -z "$sources" ]; then
      log_error "No feed sources configured. Set SAFE_ZONE_AGENT_FEED_SOURCES, SAFE_ZONE_AGENT_FEED_PRESET, or SAFE_ZONE_THREAT_FEED_SOURCE."
      exit 2
    fi
    old_ifs="$IFS"
    IFS=","
    for source in $sources; do
      SAFE_ZONE_THREAT_FEED_SOURCE="$source" compose_stack "$stack" --profile feed-sync run --rm feed-sync /app/service -source "$source"
    done
    IFS="$old_ifs"
    ;;
  duckdns)
    scripts/duckdns-update.sh
    ;;
  help|*)
    cat <<'USAGE'
Usage: scripts/safe-zone.sh <command>

Commands:
  deploy       Build and start the production stack with Caddy and loopback-only internal ports.
  deploy-dev   Build and start the local developer stack on loopback ports.
  status       Show compose status and loopback health endpoints for SAFE_ZONE_STACK (default: production).
  logs         Follow compose logs for SAFE_ZONE_STACK (default: production).
  backup       Save Redis, SQLite, env, and Caddy snapshots under backups/<timestamp>/.
  restore      Restore the latest backup directory, or a provided backup directory.
  feed-sync    Sync configured free threat feeds once.
  duckdns      Update DuckDNS record.

Environment:
  SAFE_ZONE_STACK=production|dev      Choose the stack for status/logs/backup/restore/feed-sync.
  SAFE_ZONE_BACKUP_DIR=/path          Override the local backup root.
  SAFE_ZONE_RCLONE_REMOTE=gdrive:     Optional rclone remote for offsite backup upload.
  SAFE_ZONE_RCLONE_DEST=safe-zone-backups
USAGE
    ;;
esac
