#!/usr/bin/env sh
# Rotate the core-api admin password and API key in a Compose .env file.
#
#   sh ./scripts/ops/rotate-admin-secrets.sh [--env-file .env] \
#     [--api-url http://127.0.0.1:8080] [--compose-file docker-compose.yml] \
#     [--service core-api] [--yes]
#
# Backup, rotate, verify (new key 200, old key 401/403 on admin-only
# /metrics), roll back automatically on any failure. Restarting core-api
# also rotates the in-memory session signing secret, so old sessions die.
set -eu

project_root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$project_root"

env_file=".env"
api_url="http://127.0.0.1:8080"
service="core-api"
compose_files=""
assume_yes=0

while [ $# -gt 0 ]; do
  case "$1" in
    --env-file) env_file="$2"; shift 2 ;;
    --api-url) api_url="$2"; shift 2 ;;
    --compose-file) compose_files="$compose_files $1 $2"; shift 2 ;;
    --service) service="$2"; shift 2 ;;
    --yes|-y) assume_yes=1; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) printf 'ERROR: unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

if [ -z "$compose_files" ]; then
  compose_files="-f docker-compose.yml"
fi

log_info() { printf '%s\n' "$*"; }
log_error() { printf 'ERROR: %s\n' "$*" >&2; }

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log_error "required command not found: $1"
    exit 1
  fi
}
need docker
need curl
need awk

if [ ! -f "$env_file" ]; then
  log_error "env file not found: $env_file (run from the checkout that owns the stack)"
  exit 1
fi

# _FILE variants take precedence in the service; editing plain keys would
# silently do nothing, so refuse instead of pretending to rotate.
if grep -Eq '^[[:space:]]*SAFE_ZONE_ADMIN_(PASSWORD|API_KEY)_FILE[[:space:]]*=[^[:space:]#]' "$env_file"; then
  log_error "env file uses SAFE_ZONE_ADMIN_*_FILE variants; rotate the referenced secret files by hand, then recreate $service"
  exit 1
fi

get_key() {
  grep -E "^[[:space:]]*$1[[:space:]]*=" "$env_file" | tail -n 1 | sed -E "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//;s/[[:space:]]*$//;s/\r$//"
}

old_password="$(get_key SAFE_ZONE_ADMIN_PASSWORD || true)"
old_key="$(get_key SAFE_ZONE_ADMIN_API_KEY || true)"

if [ "$assume_yes" != "1" ]; then
  printf 'Rotate admin password + API key in %s and recreate %s? [y/N] ' "$env_file" "$service"
  read -r answer
  case "$answer" in
    [yY]|[yY][eE][sS]) ;;
    *) log_info "aborted; nothing changed"; exit 0 ;;
  esac
fi

backup="backups/rotate-admin-secrets-$(date -u +%Y%m%dT%H%M%SZ).env"
mkdir -p backups
cp "$env_file" "$backup"
chmod 600 "$backup"
log_info "backed up $env_file to $backup"

rand_alnum() {
  # $1 = length. openssl preferred; /dev/urandom fallback. LC_ALL=C keeps
  # byte counts exact for head -c.
  if command -v openssl >/dev/null 2>&1; then
    LC_ALL=C openssl rand -base64 64 | LC_ALL=C tr -dc 'A-Za-z0-9' | head -c "$1"
  else
    LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$1"
  fi
}

new_password="$(rand_alnum 32)"
new_key="$(rand_alnum 40)"
printf '\n'

set_key() {
  # $1 = file, $2 = key, $3 = value (alphanumeric by construction, so awk
  # replacement metacharacters cannot appear).
  tmp="$(mktemp)"
  awk -v k="$2" -v v="$3" '
    BEGIN { done = 0 }
    $0 ~ "^[[:space:]]*" k "[[:space:]]*=" { print k "=" v; done = 1; next }
    { print }
    END { if (!done) print k "=" v }
  ' "$1" > "$tmp" && mv "$tmp" "$1"
}

set_key "$env_file" SAFE_ZONE_ADMIN_PASSWORD "$new_password"
set_key "$env_file" SAFE_ZONE_ADMIN_API_KEY "$new_key"
chmod 600 "$env_file"

# shellcheck disable=SC2086
if ! docker compose $compose_files up -d --force-recreate "$service"; then
  log_error "compose recreate failed; restoring backup"
  cp "$backup" "$env_file"
  exit 1
fi

deadline=$(( $(date +%s) + 90 ))
while :; do
  if curl -fsS -o /dev/null --max-time 3 "$api_url/healthz" 2>/dev/null; then
    break
  fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    log_error "core-api unhealthy after recreate; restoring backup"
    cp "$backup" "$env_file"
    # shellcheck disable=SC2086
    docker compose $compose_files up -d --force-recreate "$service" >/dev/null 2>&1 || true
    exit 1
  fi
  sleep 2
done

code() {
  curl -s -o /dev/null -w "%{http_code}" --max-time 10 -H "Authorization: Bearer $1" "$api_url/metrics" 2>/dev/null || printf '000'
}

rollback() {
  log_error "$1; restoring backup"
  cp "$backup" "$env_file"
  # shellcheck disable=SC2086
  docker compose $compose_files up -d --force-recreate "$service" >/dev/null 2>&1 || true
  exit 1
}

if [ "$(code "$new_key")" != "200" ]; then
  rollback "new API key did not authenticate (want 200)"
fi
if [ -n "$old_key" ]; then
  case "$(code "$old_key")" in
    401|403) ;;
    *) rollback "old API key still authenticates (want 401/403)" ;;
  esac
fi

log_info "rotation verified: new key 200, old key rejected"
printf '\n'
log_info "NEW ADMIN CREDENTIALS (store in the password manager now, this is the only display):"
printf '  username: admin\n'
printf '  password: %s\n' "$new_password"
printf '  api key:  %s\n' "$new_key"
printf '\n'
log_info "All previous admin sessions were invalidated by the restart."
