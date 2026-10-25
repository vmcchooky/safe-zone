#!/usr/bin/env bash
set -euo pipefail

host="${SAFE_ZONE_CERT_MONITOR_HOST:-localhost}"
warn_days="${SAFE_ZONE_CERT_WARN_DAYS:-14}"
dot_port=""
dot_flag=""

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
project_dir="$(CDPATH= cd -- "$script_dir/../.." && pwd)"

usage() {
  cat <<'USAGE'
Usage: scripts/ops/monitor-certs.sh [--dot|--no-dot]

Environment:
  SAFE_ZONE_CERT_MONITOR_HOST   Hostname to check (default: localhost)
  SAFE_ZONE_CERT_WARN_DAYS      Warning threshold in days (default: 14)
  SAFE_ZONE_DNS_DOT_ENABLED     Check DoT when true
  SAFE_ZONE_DNS_DOT_PUBLISHED_PORT  DoT host port (default: 853)

Without --dot/--no-dot, the script follows SAFE_ZONE_DNS_DOT_ENABLED from the
environment or .env.
USAGE
}

env_value() {
  local key="$1"
  local value="${!key:-}"
  if [[ -n "$value" ]]; then
    printf '%s' "$value"
    return 0
  fi

  local env_file="${SAFE_ZONE_ENV_FILE:-$project_dir/.env}"
  if [[ -f "$env_file" ]]; then
    value="$(grep -E "^[[:space:]]*${key}=" "$env_file" | tail -n 1 | sed -E "s/^[[:space:]]*${key}=//" | tr -d '\r' || true)"
    value="$(printf '%s' "$value" | sed -E 's/^[[:space:]]*//; s/[[:space:]]*$//; s/^"//; s/"$//')"
    case "$value" in
      \'*\')
        value="${value#\'}"
        value="${value%\'}"
        ;;
    esac
    if [[ -n "$value" ]]; then
      printf '%s' "$value"
    fi
  fi
}

is_true() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dot)
      dot_flag="true"
      shift
      ;;
    --no-dot)
      dot_flag="false"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "ERROR: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      echo "ERROR: unexpected argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -n "$dot_flag" ]]; then
  dot_enabled="$dot_flag"
elif is_true "$(env_value SAFE_ZONE_DNS_DOT_ENABLED || true)"; then
  dot_enabled="true"
else
  dot_enabled="false"
fi

dot_port="${SAFE_ZONE_DNS_DOT_PUBLISHED_PORT:-}"
if [[ -z "$dot_port" ]]; then
  dot_port="$(env_value SAFE_ZONE_DNS_DOT_PUBLISHED_PORT || true)"
fi
dot_port="${dot_port:-853}"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $1" >&2
    exit 2
  fi
}

epoch_from_openssl_date() {
  local openssl_date="$1"
  if date -u -d "$openssl_date" +%s >/dev/null 2>&1; then
    date -u -d "$openssl_date" +%s
    return 0
  fi
  if date -j -u -f "%b %e %T %Y %Z" "$openssl_date" +%s >/dev/null 2>&1; then
    date -j -u -f "%b %e %T %Y %Z" "$openssl_date" +%s
    return 0
  fi
  echo "ERROR: unable to parse certificate date: $openssl_date" >&2
  exit 2
}

check_cert() {
  local label="$1"
  local port="$2"
  local server_name="$host"
  local enddate raw_date expiry_epoch now_epoch seconds_left days_left

  enddate="$(
    openssl s_client -connect "${host}:${port}" -servername "${server_name}" </dev/null 2>/dev/null |
      openssl x509 -noout -enddate 2>/dev/null || true
  )"

  if [[ -z "$enddate" ]]; then
    echo "ERROR: unable to read certificate for ${label} on ${host}:${port}" >&2
    return 1
  fi

  raw_date="${enddate#notAfter=}"
  expiry_epoch="$(epoch_from_openssl_date "$raw_date")"
  now_epoch="$(date -u +%s)"
  seconds_left=$((expiry_epoch - now_epoch))
  days_left=$((seconds_left / 86400))

  echo "${label} certificate on ${host}:${port} expires in ${days_left} day(s)"
  if (( days_left < warn_days )); then
    echo "WARNING: Certificate expiring soon"
  fi
}

main() {
  require_command openssl
  require_command date

  check_cert "HTTPS" 443
  if [[ "$dot_enabled" == "true" ]]; then
    check_cert "DoT" "$dot_port"
  else
    echo "DoT disabled; skipping DoT certificate check."
  fi
}

main "$@"
