#!/usr/bin/env sh
set -eu

host="${1:-${SAFE_ZONE_PUBLIC_HOST:-}}"
dot_port="${SAFE_ZONE_DNS_DOT_PUBLISHED_PORT:-853}"

if [ -z "$host" ]; then
  echo "usage: scripts/public-edge-smoke.sh safe.example.com" >&2
  echo "or set SAFE_ZONE_PUBLIC_HOST." >&2
  exit 2
fi

tmp_dns="$(mktemp)"
trap 'rm -f "$tmp_dns"' EXIT INT TERM

echo "Checking public HTTPS health..."
curl -fsS "https://${host}/healthz" >/dev/null

echo "Checking public analyze API..."
curl -fsS "https://${host}/v1/analyze?domain=example.com" >/dev/null

echo "Checking public DoH endpoint..."
printf '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' |
  curl -fsS \
    -H "accept: application/dns-message" \
    -H "content-type: application/dns-message" \
    --data-binary @- \
    "https://${host}/dns-query" \
    -o "$tmp_dns"
[ -s "$tmp_dns" ]

if command -v openssl >/dev/null 2>&1; then
  echo "Checking DoT TLS certificate..."
  openssl s_client \
    -connect "${host}:${dot_port}" \
    -servername "${host}" \
    -verify_return_error \
    </dev/null >/dev/null 2>&1
fi

if command -v kdig >/dev/null 2>&1; then
  echo "Checking DoT query path with kdig..."
  kdig @"${host}" -p "${dot_port}" +tls example.com >/dev/null
elif command -v dog >/dev/null 2>&1; then
  echo "Checking DoT query path with dog..."
  dog example.com @"tls://${host}:${dot_port}" >/dev/null
else
  echo "No DoT query tool found; verified TLS handshake only."
fi

echo "Public edge smoke checks passed for ${host}."
