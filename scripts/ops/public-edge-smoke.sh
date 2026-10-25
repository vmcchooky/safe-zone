#!/usr/bin/env sh
set -eu

usage() {
  cat <<'USAGE'
Usage: scripts/ops/public-edge-smoke.sh [--dot|--no-dot] <host>

Checks public HTTPS, the analyze API, DoH, and (when DoT is enabled) the
DoT handshake/query path. Without --dot/--no-dot, the script follows
SAFE_ZONE_DNS_DOT_ENABLED from the environment or .env.
USAGE
}

host=""
dot_flag=""
while [ $# -gt 0 ]; do
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
      if [ -n "$host" ]; then
        echo "ERROR: only one host argument is accepted" >&2
        exit 2
      fi
      host="$1"
      shift
      ;;
  esac
done

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
project_dir="$(CDPATH= cd -- "$script_dir/../.." && pwd)"

env_value() {
  key="$1"
  eval "value=\${$key:-}"
  if [ -n "${value:-}" ]; then
    printf '%s' "$value"
    return 0
  fi

  env_file="${SAFE_ZONE_ENV_FILE:-$project_dir/.env}"
  if [ -f "$env_file" ]; then
    value="$(grep -E "^[[:space:]]*${key}=" "$env_file" | tail -n 1 | sed -E "s/^[[:space:]]*${key}=//" | tr -d '\r' || true)"
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

is_true() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

host="${host:-${SAFE_ZONE_PUBLIC_HOST:-}}"
dot_port="${SAFE_ZONE_DNS_DOT_PUBLISHED_PORT:-}"
if [ -z "$dot_port" ]; then
  dot_port="$(env_value SAFE_ZONE_DNS_DOT_PUBLISHED_PORT || true)"
fi
dot_port="${dot_port:-853}"

if [ -z "$host" ]; then
  usage >&2
  exit 2
fi

if [ -n "$dot_flag" ]; then
  dot_enabled="$dot_flag"
elif is_true "$(env_value SAFE_ZONE_DNS_DOT_ENABLED || true)"; then
  dot_enabled="true"
else
  dot_enabled="false"
fi

tmp_dns="$(mktemp)"
trap 'rm -f "$tmp_dns"' EXIT INT TERM

echo "Checking public HTTPS health..."
curl -fsS "https://${host}/healthz" >/dev/null

echo "Checking public analyze API..."
curl -fsS "https://${host}/v1/analyze?domain=example.com" >/dev/null

echo "Checking public DoH endpoint..."
# POSIX `sh` does not require printf's non-portable `\xNN` escape.  Keep the
# probe runnable on the minimal `/bin/sh` implementations used by VPS images.
printf '\022\064\001\000\000\001\000\000\000\000\000\000\007example\003com\000\000\001\000\001' |
  curl -fsS \
    -H "accept: application/dns-message" \
    -H "content-type: application/dns-message" \
    --data-binary @- \
    "https://${host}/dns-query" \
    -o "$tmp_dns"
[ -s "$tmp_dns" ]

if [ "$dot_enabled" = "true" ]; then
  if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: DoT is enabled but openssl is not installed; cannot verify the handshake." >&2
    exit 2
  fi
  echo "Checking DoT TLS certificate..."
  openssl s_client \
    -connect "${host}:${dot_port}" \
    -servername "${host}" \
    -verify_return_error \
    </dev/null >/dev/null 2>&1

  if command -v kdig >/dev/null 2>&1; then
    echo "Checking DoT query path with kdig..."
    kdig @"${host}" -p "${dot_port}" +tls example.com >/dev/null
  elif command -v dog >/dev/null 2>&1; then
    echo "Checking DoT query path with dog..."
    dog example.com @"tls://${host}:${dot_port}" >/dev/null
  else
    echo "No DoT query tool found; verified TLS handshake only."
  fi
else
  echo "DoT disabled; skipping DoT checks."
fi

echo "Public edge smoke checks passed for ${host}."
