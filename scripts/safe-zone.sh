#!/usr/bin/env sh
set -eu

compose="${SAFE_ZONE_COMPOSE:-docker compose}"
project_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
backup_dir="${SAFE_ZONE_BACKUP_DIR:-${project_dir}/backups}"
stack="${SAFE_ZONE_STACK:-production}"
tmp_dir="${project_dir}/tmp"

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

run_mise_task() {
  task_name="$1"
  if [ "${SAFE_ZONE_SKIP_MISE:-}" = "1" ]; then
    return 1
  fi
  if ! command -v mise >/dev/null 2>&1; then
    log_warn "mise not found on PATH; running ${cmd} directly"
    return 1
  fi

  export SAFE_ZONE_SCRIPT_STACK="$stack"
  export SAFE_ZONE_SCRIPT_BACKUP_PATH="${backup_path_override:-}"
  export SAFE_ZONE_SCRIPT_KEEP="${keep_count}"
  export SAFE_ZONE_SCRIPT_LOG_RETENTION_DAYS="${log_retention_days}"
  export SAFE_ZONE_SCRIPT_FEED_SYNC="${feed_sync_enabled}"
  mise run "$task_name"
  exit $?
}

set_build_metadata_env() {
  safe_zone_build_version="${SAFE_ZONE_BUILD_VERSION:-}"
  if [ -z "$safe_zone_build_version" ]; then
    if [ -n "${SAFE_ZONE_RELEASE_VERSION:-}" ]; then
      safe_zone_build_version="${SAFE_ZONE_RELEASE_VERSION}"
    else
      safe_zone_build_version="$(git describe --tags --always --dirty 2>/dev/null || true)"
      if [ -z "$safe_zone_build_version" ]; then
        safe_zone_build_version="$(git rev-parse --short HEAD 2>/dev/null || true)"
      fi
      if [ -z "$safe_zone_build_version" ]; then
        safe_zone_build_version="dev"
      fi
    fi
  fi

  safe_zone_build_git_commit="${SAFE_ZONE_BUILD_GIT_COMMIT:-}"
  if [ -z "$safe_zone_build_git_commit" ]; then
    safe_zone_build_git_commit="$(git rev-parse HEAD 2>/dev/null || true)"
    if [ -z "$safe_zone_build_git_commit" ]; then
      safe_zone_build_git_commit="unknown"
    fi
  fi

  safe_zone_build_short_commit="$(git rev-parse --short HEAD 2>/dev/null || true)"
  if [ -z "$safe_zone_build_short_commit" ]; then
    safe_zone_build_short_commit="$(printf '%.12s' "$safe_zone_build_git_commit")"
  fi

  safe_zone_build_time="${SAFE_ZONE_BUILD_TIME:-}"
  if [ -z "$safe_zone_build_time" ]; then
    safe_zone_build_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  fi

  safe_zone_build_source_repo="${SAFE_ZONE_BUILD_SOURCE_REPO:-}"
  if [ -z "$safe_zone_build_source_repo" ]; then
    safe_zone_build_source_repo="$(git config --get remote.origin.url 2>/dev/null || true)"
    if [ -z "$safe_zone_build_source_repo" ]; then
      safe_zone_build_source_repo="unknown"
    fi
  fi

  safe_zone_build_release_tag="${SAFE_ZONE_BUILD_RELEASE_TAG:-}"
  if [ -z "$safe_zone_build_release_tag" ]; then
    if [ -n "${SAFE_ZONE_RELEASE_VERSION:-}" ]; then
      safe_zone_build_release_tag="${safe_zone_build_version}-${safe_zone_build_short_commit}"
    else
      safe_zone_build_release_tag="${safe_zone_build_version}"
    fi
  fi

  export SAFE_ZONE_BUILD_VERSION="$safe_zone_build_version"
  export SAFE_ZONE_BUILD_GIT_COMMIT="$safe_zone_build_git_commit"
  export SAFE_ZONE_BUILD_TIME="$safe_zone_build_time"
  export SAFE_ZONE_BUILD_SOURCE_REPO="$safe_zone_build_source_repo"
  export SAFE_ZONE_BUILD_RELEASE_TAG="$safe_zone_build_release_tag"

  log_info "Build metadata: version=${SAFE_ZONE_BUILD_VERSION} commit=$(printf '%.12s' "$SAFE_ZONE_BUILD_GIT_COMMIT") tag=${SAFE_ZONE_BUILD_RELEASE_TAG}"
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

secret_value() {
  key="$1"
  value="$(env_value "$key" || true)"
  if [ -n "$value" ]; then
    printf '%s' "$value"
    return 0
  fi

  file_key="${key}_FILE"
  file_path="$(env_value "$file_key" || true)"
  if [ -n "$file_path" ] && [ -f "$file_path" ]; then
    tr -d '\r' < "$file_path"
  fi
}

is_true() {
  value="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    1|true|yes|on)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

encrypt_backups_enabled() {
  is_true "$(env_value SAFE_ZONE_BACKUP_ENCRYPT || true)"
}

keep_plaintext_backup() {
  is_true "$(env_value SAFE_ZONE_BACKUP_KEEP_PLAINTEXT || true)"
}

sha256_file() {
  target="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$target" | awk '{print $1}'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$target" | awk '{print $1}'
    return 0
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$target" | awk '{print $NF}'
    return 0
  fi
  log_error "No SHA-256 utility found (sha256sum, shasum, or openssl)"
  exit 2
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
  container_id="$(compose_container_id redis)"
  if [ -z "$container_id" ]; then
    log_warn "Redis container is not running; skipping Redis snapshot copy"
    return 0
  fi

  log_info "Creating Redis snapshot..."
  if ! compose_stack "$stack" exec -T redis redis-cli SAVE >/dev/null; then
    log_warn "Redis SAVE command failed, attempting to copy current dump anyway"
  fi
  docker cp "${container_id}:/data/dump.rdb" "${target}/redis-dump.rdb" || log_warn "Failed to copy Redis snapshot"
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
  if [ -f scripts/duckdns-update.sh ]; then
    cp scripts/duckdns-update.sh "${target}/duckdns-update.sh.snapshot"
  fi
  if [ -f docker-compose.production.yml ]; then
    cp docker-compose.production.yml "${target}/docker-compose.production.yml.snapshot"
  fi
}

write_checksum_manifest() {
  target="$1"
  manifest="${target}/SHA256SUMS"
  : > "$manifest"
  for entry in "$target"/*; do
    [ -f "$entry" ] || continue
    base="$(basename -- "$entry")"
    [ "$base" = "SHA256SUMS" ] && continue
    checksum="$(sha256_file "$entry")"
    printf '%s  %s\n' "$checksum" "$base" >> "$manifest"
  done
}

verify_backup_snapshot() {
  target="$1"
  found_file=0
  for entry in "$target"/*; do
    [ -f "$entry" ] || continue
    found_file=1
    if [ ! -s "$entry" ]; then
      log_error "Backup artifact is empty: $entry"
      exit 2
    fi
  done
  if [ "$found_file" -eq 0 ]; then
    log_error "Backup directory is empty: $target"
    exit 2
  fi
}

encrypt_backup_bundle() {
  target="$1"
  ts="$2"
  recipient="$(env_value SAFE_ZONE_BACKUP_GPG_RECIPIENT || true)"
  passphrase="$(secret_value SAFE_ZONE_BACKUP_GPG_PASSPHRASE || true)"
  archive="${backup_dir}/${ts}.tar.gz"
  encrypted="${target}/backup.tar.gz.gpg"
  checksum_file="${target}/backup.tar.gz.gpg.sha256"

  if ! command -v gpg >/dev/null 2>&1; then
    log_error "SAFE_ZONE_BACKUP_ENCRYPT is enabled but gpg is not installed"
    exit 2
  fi
  if [ -z "$recipient" ] && [ -z "$passphrase" ]; then
    log_error "Backup encryption requires SAFE_ZONE_BACKUP_GPG_RECIPIENT or SAFE_ZONE_BACKUP_GPG_PASSPHRASE(_FILE)"
    exit 2
  fi

  log_info "Packaging backup into ${archive}..."
  tar -czf "$archive" -C "$target" .

  log_info "Encrypting backup archive with GPG..."
  if [ -n "$recipient" ]; then
    gpg --batch --yes --trust-model always --output "$encrypted" --encrypt --recipient "$recipient" "$archive"
  else
    gpg --batch --yes --pinentry-mode loopback --passphrase "$passphrase" --cipher-algo AES256 --output "$encrypted" --symmetric "$archive"
  fi
  rm -f "$archive"

  printf '%s  %s\n' "$(sha256_file "$encrypted")" "$(basename -- "$encrypted")" > "$checksum_file"

  if ! keep_plaintext_backup; then
    for entry in "$target"/*; do
      [ -e "$entry" ] || continue
      base="$(basename -- "$entry")"
      case "$base" in
        backup.tar.gz.gpg|backup.tar.gz.gpg.sha256)
          continue
          ;;
      esac
      rm -rf "$entry"
    done
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

prune_backups() {
  keep="$1"
  if [ ! -d "$backup_dir" ]; then
    log_info "No backups directory found at ${backup_dir}"
    return 0
  fi

  current_count="$(find "$backup_dir" -mindepth 1 -maxdepth 1 -type d | wc -l | awk '{print $1}')"
  if [ "$current_count" -le "$keep" ]; then
    log_info "Backup retention already satisfied (${current_count} <= ${keep})"
    return 0
  fi

  find "$backup_dir" -mindepth 1 -maxdepth 1 -type d | sort -r | tail -n +"$((keep + 1))" | while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    rm -rf "$entry"
    log_info "Removed backup $(basename -- "$entry")"
  done
}

prune_logs() {
  retention_days="$1"
  if [ ! -d "$tmp_dir" ]; then
    log_info "No tmp directory found at ${tmp_dir}"
    return 0
  fi

  if ! find "$tmp_dir" -maxdepth 1 -type f -name '*.log' -mtime +"$retention_days" -print -delete | while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    log_info "Removed log $(basename -- "$entry")"
  done; then
    log_warn "Log pruning encountered an error"
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

prepare_restore_dir() {
  src_dir="$1"
  encrypted="${src_dir}/backup.tar.gz.gpg"
  archive="${src_dir}/backup.tar.gz"

  if [ ! -f "$encrypted" ] && [ ! -f "$archive" ]; then
    printf '%s' "$src_dir"
    return 0
  fi

  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/safe-zone-restore.XXXXXX")"
  unpacked="${tmp_root}/bundle"
  mkdir -p "$unpacked"

  if [ -f "$encrypted" ]; then
    passphrase="$(secret_value SAFE_ZONE_BACKUP_GPG_PASSPHRASE || true)"
    if ! command -v gpg >/dev/null 2>&1; then
      log_error "Encrypted backup found but gpg is not installed"
      rm -rf "$tmp_root"
      exit 2
    fi
    log_info "Decrypting encrypted backup bundle from ${encrypted}..."
    if [ -n "$passphrase" ]; then
      gpg --batch --yes --pinentry-mode loopback --passphrase "$passphrase" --output "${tmp_root}/backup.tar.gz" --decrypt "$encrypted"
    else
      gpg --batch --yes --output "${tmp_root}/backup.tar.gz" --decrypt "$encrypted"
    fi
    tar -xzf "${tmp_root}/backup.tar.gz" -C "$unpacked"
  else
    log_info "Extracting backup bundle from ${archive}..."
    tar -xzf "$archive" -C "$unpacked"
  fi

  printf '%s' "$unpacked"
}

new_backup() {
  ts="$(date -u +%Y%m%d-%H%M%S)"
  target="${backup_dir}/${ts}"
  mkdir -p "$target"

  backup_redis "$target"
  copy_optional_snapshots "$target"
  backup_sqlite "$target"
  write_checksum_manifest "$target"
  verify_backup_snapshot "$target"
  if encrypt_backups_enabled; then
    encrypt_backup_bundle "$target" "$ts"
  fi
  sync_offsite "$target" "$ts"
  log_info "Backup written to ${target}"
}

restore_backup() {
  src_dir="$(resolve_backup_dir "${1:-}")"
  log_info "Restoring backup from ${src_dir}"
  prepared_dir="$(prepare_restore_dir "$src_dir")"
  stop_for_restore
  restore_sqlite "$prepared_dir"
  restore_redis "$prepared_dir"
  restore_env_notice "$prepared_dir"
  log_info "Restarting stack..."
  compose_up_stack
  if [ "$prepared_dir" != "$src_dir" ]; then
    rm -rf "$(dirname -- "$prepared_dir")"
  fi
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
backup_path_override="${2:-${SAFE_ZONE_SCRIPT_BACKUP_PATH:-}}"
keep_count="${SAFE_ZONE_SCRIPT_KEEP:-7}"
log_retention_days="${SAFE_ZONE_SCRIPT_LOG_RETENTION_DAYS:-7}"
feed_sync_enabled="${SAFE_ZONE_SCRIPT_FEED_SYNC:-0}"
case "$cmd" in
  deploy)
    run_mise_task ops:deploy || true
    ;;
  deploy-dev)
    run_mise_task ops:deploy-dev || true
    ;;
  status)
    run_mise_task ops:status || true
    ;;
  logs)
    run_mise_task ops:logs || true
    ;;
  backup)
    run_mise_task ops:backup || true
    ;;
  restore)
    run_mise_task ops:restore || true
    ;;
  prune)
    run_mise_task ops:prune || true
    ;;
  feed-sync)
    run_mise_task ops:feed-sync || true
    ;;
esac
case "$cmd" in
  deploy)
    set_build_metadata_env
    if is_true "$feed_sync_enabled"; then
      compose_stack production --profile production-edge --profile feed-sync up -d --build
    else
      compose_stack production --profile production-edge up -d --build
    fi
    ;;
  deploy-dev)
    set_build_metadata_env
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
    restore_backup "$backup_path_override"
    ;;
  prune)
    prune_backups "$keep_count"
    prune_logs "$log_retention_days"
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
  prune        Keep the newest backup directories and delete stale tmp/*.log files.
  feed-sync    Sync configured free threat feeds once.
  duckdns      Update DuckDNS record.

Environment:
  SAFE_ZONE_STACK=production|dev      Choose the stack for status/logs/backup/restore/feed-sync.
  SAFE_ZONE_BACKUP_DIR=/path          Override the local backup root.
  SAFE_ZONE_BACKUP_ENCRYPT=1          Package the backup and encrypt it with GPG.
  SAFE_ZONE_BACKUP_GPG_RECIPIENT=id   Encrypt to a GPG recipient key.
  SAFE_ZONE_BACKUP_GPG_PASSPHRASE=... Encrypt symmetrically when no recipient is set.
  SAFE_ZONE_BACKUP_GPG_PASSPHRASE_FILE=/path
  SAFE_ZONE_BACKUP_KEEP_PLAINTEXT=1   Keep plaintext snapshot files after encrypted bundle creation.
  SAFE_ZONE_RCLONE_REMOTE=gdrive:     Optional rclone remote for offsite backup upload.
  SAFE_ZONE_RCLONE_DEST=safe-zone-backups
  SAFE_ZONE_SCRIPT_FEED_SYNC=1        Include the feed-sync profile during deploy.
USAGE
    ;;
esac
