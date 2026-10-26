#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
project_dir="$(CDPATH='' cd -- "$script_dir/../.." && pwd)"

fail_on_warning="false"
dot_flag=""

usage() {
  cat <<'USAGE'
Usage: scripts/ops/monitor-certs.sh [--dot|--no-dot] [--fail-on-warning]

Environment:
  SAFE_ZONE_CERT_MONITOR_HOST       Hostname to check (default: SAFE_ZONE_PUBLIC_HOST,
                                    then localhost)
  SAFE_ZONE_CERT_WARN_DAYS          Warning threshold in days (default: 14)
  SAFE_ZONE_CERT_FAIL_ON_WARN=true  Same as --fail-on-warning (default: false)
  SAFE_ZONE_DNS_DOT_ENABLED         Check DoT when true
  SAFE_ZONE_DNS_DOT_PUBLISHED_PORT  DoT host port (default: 853)

An expired or unreadable certificate always exits 1. --fail-on-warning also
exits 1 while a certificate is inside the warning window.

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
    --fail-on-warning)
      fail_on_warning="true"
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

# Read the monitor settings only after option parsing: --help must not depend
# on a readable .env. env_value checks the environment first and then .env, so
# both `VAR=... script` and a cron `. ./.env` (which does not export) work.
host="$(env_value SAFE_ZONE_CERT_MONITOR_HOST || true)"
if [[ -z "$host" ]]; then
  host="$(env_value SAFE_ZONE_PUBLIC_HOST || true)"
fi
host="${host:-localhost}"

warn_days="$(env_value SAFE_ZONE_CERT_WARN_DAYS || true)"
warn_days="${warn_days:-14}"
case "$warn_days" in
  ''|*[!0-9]*)
    echo "ERROR: SAFE_ZONE_CERT_WARN_DAYS must be a non-negative integer (found: '$warn_days')" >&2
    exit 2
    ;;
esac
# Bash reads a leading zero as octal in arithmetic contexts. 08 and 09 are not
# valid octal, and an arithmetic error inside an if-condition is silently
# false, which would skip the warning window entirely. Normalize once, in
# decimal, so 010 means ten days just like strconv.Atoi in the Go config.
warn_days=$((10#$warn_days))

if [[ -n "$dot_flag" ]]; then
  dot_enabled="$dot_flag"
elif is_true "$(env_value SAFE_ZONE_DNS_DOT_ENABLED || true)"; then
  dot_enabled="true"
else
  dot_enabled="false"
fi

if [[ "$fail_on_warning" == "false" ]] && is_true "$(env_value SAFE_ZONE_CERT_FAIL_ON_WARN || true)"; then
  fail_on_warning="true"
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

  # Do not swallow a failed s_client/x509 read. With pipefail, either command
  # failing makes the assignment fail; an empty but successful output is
  # caught separately below.
  if ! enddate="$(
    openssl s_client -connect "${host}:${port}" -servername "${server_name}" </dev/null 2>/dev/null |
      openssl x509 -noout -enddate 2>/dev/null
  )"; then
    echo "ERROR: unable to read certificate for ${label} on ${host}:${port}" >&2
    return 1
  fi

  if [[ -z "$enddate" ]]; then
    echo "ERROR: unable to read certificate for ${label} on ${host}:${port}" >&2
    return 1
  fi

  raw_date="${enddate#notAfter=}"
  expiry_epoch="$(epoch_from_openssl_date "$raw_date")"
  now_epoch="$(date -u +%s)"
  seconds_left=$((expiry_epoch - now_epoch))
  days_left=$((seconds_left / 86400))

  # Expiry is not a warning-window decision: an expired certificate is a
  # broken public endpoint and must fail even when --fail-on-warning is not
  # passed. The warning window starts strictly before expiry.
  if (( seconds_left <= 0 )); then
    echo "ERROR: ${label} certificate on ${host}:${port} has expired (notAfter=${raw_date})" >&2
    return 1
  fi

  echo "${label} certificate on ${host}:${port} expires in ${days_left} day(s)"
  if (( days_left < warn_days )); then
    echo "WARNING: ${label} certificate on ${host}:${port} expires in ${days_left} day(s), inside the ${warn_days}-day warning window"
    return 2
  fi
  return 0
}

main() {
  require_command openssl
  require_command date

  # check_cert returns 1 when the certificate cannot be read or has expired
  # (always fatal), and 2 when it is inside the warning window (fatal only
  # with fail_on_warning).
  local rc=0 warned=0
  check_cert 'HTTPS' 443 || rc=$?
  case "$rc" in
    0) ;;
    1) exit 1 ;;
    2) warned=1 ;;
    *)
      echo "ERROR: unexpected HTTPS certificate check status ${rc}" >&2
      exit 1
      ;;
  esac

  if [[ "$dot_enabled" == "true" ]]; then
    rc=0
    check_cert 'DoT' "$dot_port" || rc=$?
    case "$rc" in
      0) ;;
      1) exit 1 ;;
      2) warned=1 ;;
      *)
        echo "ERROR: unexpected DoT certificate check status ${rc}" >&2
        exit 1
        ;;
    esac
  else
    echo "DoT disabled; skipping DoT certificate check."
  fi

  if [[ "$warned" -eq 1 && "$fail_on_warning" == "true" ]]; then
    exit 1
  fi
  exit 0
}

main "$@"
