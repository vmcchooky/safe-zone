#!/usr/bin/env sh
set -eu

public_host="${1:-${SAFE_ZONE_PUBLIC_HOST:-}}"
public_ip="${2:-${SAFE_ZONE_BLOCK_PAGE_IP:-}}"
blocked_domain="${3:-blocked.example.test}"

if [ -z "$public_host" ] || [ -z "$public_ip" ]; then
  echo "usage: scripts/check-block-page.sh safe.example.com 203.0.113.10 [blocked.example.test]" >&2
  echo "or set SAFE_ZONE_PUBLIC_HOST and SAFE_ZONE_BLOCK_PAGE_IP." >&2
  exit 2
fi

tmp_html="$(mktemp)"
trap 'rm -f "$tmp_html"' EXIT INT TERM

echo "Checking HTTP sinkhole block page..."
curl -fsS \
  -H "Host: ${blocked_domain}" \
  "http://${public_ip}/" \
  -o "$tmp_html"
grep -q "This site was blocked" "$tmp_html"
grep -q "$blocked_domain" "$tmp_html"

echo "Checking HTTPS canonical block page..."
curl -fsS \
  "https://${public_host}/block?domain=${blocked_domain}&path=%2F" \
  -o "$tmp_html"
grep -q "This site was blocked" "$tmp_html"
grep -q "$blocked_domain" "$tmp_html"

echo "Block page checks passed for ${blocked_domain}."
echo "Note: direct HTTPS to arbitrary blocked third-party domains still shows a certificate warning before any block page can render."
