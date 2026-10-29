#!/usr/bin/env sh
set -eu

compose="${SAFE_ZONE_COMPOSE:-docker compose}"
project_dir="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
backup_dir="${SAFE_ZONE_BACKUP_DIR:-${project_dir}/backups}"
stack="${SAFE_ZONE_STACK:-production}"
tmp_dir="${project_dir}/tmp"
dot_override="ops/vps-edge/docker-compose.dot.yml"

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

dot_enabled() {
  is_true "$(env_value SAFE_ZONE_DNS_DOT_ENABLED || true)"
}

host_edge_enabled() {
  case "$(env_value SAFE_ZONE_DEPLOYMENT_TIER || true)" in
    shared-host-edge|shared-host-edge-staging) return 0 ;;
    *) return 1 ;;
  esac
}

# production_compose_files prints the exact -f list a production deploy uses,
# so config validation and up never disagree about the merged file set.
production_compose_files() {
  compose_files="-f docker-compose.yml -f docker-compose.production.yml"
  if host_edge_enabled; then
    compose_files="$compose_files -f ops/vps-edge/docker-compose.host-edge.yml"
  fi
  if dot_enabled; then
    compose_files="$compose_files -f $dot_override"
  fi
  printf '%s' "$compose_files"
}

require_compose_v224() {
  # docker-compose.production.yml uses !reset and the shared-host overlay
  # uses !override; both YAML tags landed in Compose v2.24. Detect the gap
  # before anything builds instead of failing with a YAML parse error after
  # a full image build. An unreadable version is only a warning: the config
  # validation that follows still fails fast on an unsupported Compose.
  version="$($compose version --short 2>/dev/null || true)"
  version="$(printf '%s' "$version" | tail -n 1 | tr -d '[:space:]')"
  version="${version#v}"
  version="${version#V}"
  major="$(printf '%s' "$version" | cut -d. -f1)"
  minor="$(printf '%s' "$version" | cut -d. -f2)"
  case "$major" in
    ''|*[!0-9]*)
      log_warn "cannot parse Docker Compose version output; relying on config validation to catch an unsupported Compose"
      return 0
      ;;
  esac
  case "$minor" in
    ''|*[!0-9]*)
      log_warn "cannot parse Docker Compose version output; relying on config validation to catch an unsupported Compose"
      return 0
      ;;
  esac
  if [ "$major" -lt 2 ] || { [ "$major" -eq 2 ] && [ "$minor" -lt 24 ]; }; then
    log_error "Docker Compose ${major}.${minor} does not support the !override/!reset YAML tags used by the production stack (docker-compose.production.yml, ops/vps-edge/docker-compose.host-edge.yml). Install Docker Compose v2.24 or newer and retry."
    exit 2
  fi
}

# preflight_production fails fast on every condition that would otherwise be
# discovered mid-deploy: an unsupported Compose, a compose file set that does
# not validate, and the production startup guards in the resolver that would
# exit 1 after the images were already built. Best-effort checks that read
# .env stay consistent with cmd/dns-resolver and the env examples; this is a
# gate, not a second source of truth.
preflight_production() {
  log_info "Preflight: checking Docker Compose version (need v2.24+ for !override)..."
  require_compose_v224

  log_info "Preflight: validating compose configuration..."
  # Intentional word splitting: production_compose_files returns a list of
  # relative paths without spaces, and POSIX sh has no arrays.
  # shellcheck disable=SC2046
  if ! $compose $(production_compose_files) --profile production-edge config -q; then
    log_error "docker compose config failed for the file set above; fix the configuration before deploying"
    exit 2
  fi

  configured_env="$(env_value SAFE_ZONE_ENV || true)"
  configured_env="$(printf '%s' "$configured_env" | tr '[:upper:]' '[:lower:]')"
  case "$configured_env" in
    production|prod) ;;
    *)
      log_error "SAFE_ZONE_ENV must be 'production' (or the 'prod' alias) for a production deploy (found: '${configured_env:-<empty>}')"
      exit 2
      ;;
  esac

  block_strategy="$(env_value SAFE_ZONE_DNS_BLOCK_STRATEGY || true)"
  [ -n "$block_strategy" ] || block_strategy="sinkhole"
  block_strategy="$(printf '%s' "$block_strategy" | tr '[:upper:]' '[:lower:]')"
  if [ "$block_strategy" = "sinkhole" ]; then
    block_page_ip="$(env_value SAFE_ZONE_BLOCK_PAGE_IP || true)"
    block_page_ip_lower="$(printf '%s' "$block_page_ip" | tr '[:upper:]' '[:lower:]')"
    case "$block_page_ip_lower" in
      ''|replace-with-*)
        log_error "SAFE_ZONE_BLOCK_PAGE_IP is unset or a placeholder while SAFE_ZONE_DNS_BLOCK_STRATEGY=sinkhole; set the public IP of the block page host"
        exit 2
        ;;
    esac
  fi

  if dot_enabled; then
    dot_certs_dir="$(env_value SAFE_ZONE_DNS_DOT_CERTS_DIR || true)"
    [ -n "$dot_certs_dir" ] || dot_certs_dir="./ops/certs/dot"
    case "$dot_certs_dir" in
      /*) ;;
      *) dot_certs_dir="${project_dir}/${dot_certs_dir#./}" ;;
    esac
    if [ ! -f "${dot_certs_dir}/fullchain.pem" ] || [ ! -f "${dot_certs_dir}/privkey.pem" ]; then
      log_error "DoT is enabled but ${dot_certs_dir} is missing fullchain.pem or privkey.pem; export the pair with scripts/ops/export-dot-cert.sh"
      exit 2
    fi
  fi

  log_info "Preflight passed."
}

compose_stack() {
  selected_stack="$1"
  shift
  case "$selected_stack" in
    production)
      # Intentional word splitting: production_compose_files returns a list
      # of relative paths without spaces, and POSIX sh has no arrays.
      # shellcheck disable=SC2046
      $compose $(production_compose_files) "$@"
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

  # The RDB snapshot alone does not describe the restored state when the
  # container runs with --appendonly yes: on start Redis replays the AOF over
  # dump.rdb, and with no AOF present it starts from an empty dataset
  # entirely (both found by the restore drill, 2026-10-29). Capture the AOF
  # files as the authoritative snapshot: rewrite first so the bundle is
  # compact and complete, then archive the whole appendonlydir. The bundle is
  # a regular file so the checksum manifest and the empty-artifact check see
  # it. Skipped when AOF is disabled — BGREWRITEAOF refuses and there is no
  # directory to copy.
  if compose_stack "$stack" exec -T redis redis-cli BGREWRITEAOF >/dev/null 2>&1; then
    rewrite_done=0
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
      pending="$(compose_stack "$stack" exec -T redis redis-cli info persistence 2>/dev/null | grep -c 'aof_rewrite_in_progress:1' || true)"
      if [ "${pending:-0}" = "0" ]; then
        rewrite_done=1
        break
      fi
      sleep 1
    done
    if [ "$rewrite_done" = "1" ] && docker cp "${container_id}:/data/appendonlydir" - | gzip >"${target}/redis-aof.tar.gz"; then
      log_info "Captured Redis AOF bundle (authoritative for appendonly deployments)"
    else
      log_warn "Could not capture the Redis AOF bundle; an appendonly deployment cannot fully restore from this backup's RDB alone"
    fi
  fi
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
  if [ -f "${project_dir}/scripts/ops/duckdns-update.sh" ]; then
    cp "${project_dir}/scripts/ops/duckdns-update.sh" "${target}/duckdns-update.sh.snapshot"
  fi
  if [ -f docker-compose.production.yml ]; then
    cp docker-compose.production.yml "${target}/docker-compose.production.yml.snapshot"
  fi
  if [ -f ops/vps-edge/docker-compose.host-edge.yml ]; then
    cp ops/vps-edge/docker-compose.host-edge.yml "${target}/docker-compose.host-edge.yml.snapshot"
  fi
  if [ -f ops/vps-edge/docker-compose.dot.yml ]; then
    cp ops/vps-edge/docker-compose.dot.yml "${target}/docker-compose.dot.yml.snapshot"
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

prune_adblock_tmp() {
  # Orphaned *.tmp-* files under data/adblock_sources/ are left behind when a
  # feed sync is interrupted mid-rename. They are gitignored, never read back
  # (the sync only consumes the final names), and safe to delete.
  for dir in "${project_dir}/data/adblock_sources" "${project_dir}/data"; do
    [ -d "$dir" ] || continue
    find "$dir" -maxdepth 1 -type f -name '*.tmp-*' -print -delete | while IFS= read -r entry; do
      [ -n "$entry" ] || continue
      log_info "Removed orphaned adblock tmp $(basename -- "$entry")"
    done
  done
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
      (CDPATH='' cd -- "$src" && pwd)
      return 0
    fi
    if [ -f "$src" ]; then
      (CDPATH='' cd -- "$(dirname -- "$src")" && pwd)
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

  # Redis persistence decides what a restored snapshot means:
  #   appendonly yes: on start Redis replays the AOF over dump.rdb — and with
  #     no AOF present it starts from an EMPTY dataset, ignoring the copied
  #     RDB entirely (found by the restore drill, 2026-10-29).
  #   appendonly no: dump.rdb is loaded directly.
  # The backup captures the AOF directory as redis-aof.tar.gz whenever AOF is
  # enabled, so that bundle is the authoritative state and is restored into
  # the volume instead. The destination is purged either way, because a
  # surviving AOF resurrects every command committed after the backup and
  # silently undoes the restore (a stale Redis-cached list shadowing the
  # restored SQLite for one cache TTL was the drill's first finding).
  # The service container is stopped here; the purge and the extraction both
  # run through one-off containers.
  if ! compose_stack "$stack" run --rm redis sh -c 'rm -rf /data/appendonlydir /data/appendonly.aof /data/dump.rdb'; then
    log_warn "Could not purge the previous Redis persistence files; the restored snapshot may be overridden on start"
  fi

  if [ -f "${src_dir}/redis-aof.tar.gz" ]; then
    unpacked="$(mktemp -d "${TMPDIR:-/tmp}/safe-zone-redis-aof.XXXXXX")"
    if tar -xzf "${src_dir}/redis-aof.tar.gz" -C "$unpacked" &&
      docker cp "${unpacked}/appendonlydir" "${container_id}:/data/appendonlydir"; then
      log_info "Restored Redis AOF bundle from ${src_dir}/redis-aof.tar.gz"
    else
      log_error "Redis AOF bundle restore failed; the RDB snapshot alone cannot restore an appendonly deployment"
      rm -rf "$unpacked"
      return 1
    fi
    rm -rf "$unpacked"
  else
    # No AOF bundle in the backup: pre-AOF-aware backups, or AOF-disabled
    # deployments. For an appendonly deployment this starts Redis empty (see
    # above), so say so instead of implying the RDB was restored into place.
    docker cp "$src_rdb" "${container_id}:/data/dump.rdb"
    log_warn "Backup has no Redis AOF bundle; if this deployment runs with appendonly yes, Redis will start empty — take a fresh backup with the updated helper and re-run the restore"
    log_info "Restored Redis RDB snapshot from ${src_rdb}"
  fi
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

validate_ml_rollout_bundle() {
  mode="$(env_value SAFE_ZONE_ML_MODE || true)"
  case "$(printf '%s' "$mode" | tr '[:upper:]' '[:lower:]')" in
    shadow|enforce)
      bundle_host_dir="$(env_value SAFE_ZONE_ML_BUNDLE_HOST_DIR || true)"
      if [ -z "$bundle_host_dir" ]; then
        bundle_host_dir="./deploy/model-bundle/current"
      fi
      sh "${project_dir}/scripts/ops/ml-bundle.sh" validate "$bundle_host_dir"
      ;;
  esac
}

cmd="${1:-help}"
backup_path_override="${2:-${SAFE_ZONE_SCRIPT_BACKUP_PATH:-}}"
keep_count="${SAFE_ZONE_SCRIPT_KEEP:-7}"
log_retention_days="${SAFE_ZONE_SCRIPT_LOG_RETENTION_DAYS:-7}"
feed_sync_enabled="${SAFE_ZONE_SCRIPT_FEED_SYNC:-1}"
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
    validate_ml_rollout_bundle
    # Fails before anything builds: compose version/config problems, missing
    # production env, placeholder sinkhole IP, or a DoT pair that is not
    # mounted. The resolver's own startup guards would exit 1 anyway, but
    # only after the images were built.
    preflight_production
    # feed-syncd is part of the production stack (the production override
    # removes the developer profile), so a plain up starts it. The opt-out is
    # an explicit stop, not an omission that leaves the previous container
    # running unnoticed.
    compose_stack production --profile production-edge up -d --build
    if ! is_true "$feed_sync_enabled"; then
      log_warn "SAFE_ZONE_SCRIPT_FEED_SYNC=0: stopping the production feed-syncd daemon"
      compose_stack production stop feed-syncd >/dev/null 2>&1 || true
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
    prune_adblock_tmp
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
      SAFE_ZONE_THREAT_FEED_SOURCE="$source" compose_stack "$stack" --profile feed-sync-once run --rm feed-sync /app/service -source "$source"
    done
    IFS="$old_ifs"
    ;;
  duckdns)
    "${project_dir}/scripts/ops/duckdns-update.sh"
    ;;
  help|*)
    cat <<'USAGE'
Usage: scripts/ops/safe-zone.sh <command>

Commands:
  deploy       Build and start the production stack with Caddy and loopback-only internal ports.
  deploy-dev   Build and start the local developer stack on loopback ports.
  status       Show compose status and loopback health endpoints for SAFE_ZONE_STACK (default: production).
  logs         Follow compose logs for SAFE_ZONE_STACK (default: production).
  backup       Save Redis, SQLite, env, and Caddy snapshots under backups/<timestamp>/.
  restore      Restore the latest backup directory, or a provided backup directory.
  prune        Keep the newest backup directories; delete stale tmp/*.log and orphaned adblock *.tmp-* files.
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
  SAFE_ZONE_SCRIPT_FEED_SYNC=1        Run feed-syncd after deploy (the production stack includes it).
                                      0 stops it after a deploy that goes through this helper. A direct
                                      docker compose ... up recreates and starts it, so the opt-out
                                      holds only while every deploy goes through this helper. The
                                      start-up guard cannot see a stopped daemon (it reads
                                      SAFE_ZONE_THREAT_FEED_SOURCE / SAFE_ZONE_AGENT_ENABLED), so an
                                      opted-out deployment with no other writer passes the guard while
                                      nobody syncs. Feed state is observable only through
                                      /v1/status -> feed_sync; alerting on it is not part of this change.
USAGE
    ;;
esac
