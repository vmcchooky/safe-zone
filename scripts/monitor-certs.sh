#!/usr/bin/env bash
set -euo pipefail

host="${SAFE_ZONE_CERT_MONITOR_HOST:-localhost}"
warn_days="${SAFE_ZONE_CERT_WARN_DAYS:-14}"

usage() {
  cat <<'USAGE'
Usage: scripts/monitor-certs.sh

Environment:
  SAFE_ZONE_CERT_MONITOR_HOST   Hostname to check (default: localhost)
  SAFE_ZONE_CERT_WARN_DAYS      Warning threshold in days (default: 14)
USAGE
}

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
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  require_command openssl
  require_command date

  check_cert "HTTPS" 443
  check_cert "DoT" 853
}

main "$@"
