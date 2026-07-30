#!/usr/bin/env sh
set -eu

project_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
domain="${SAFE_ZONE_DUCKDNS_DOMAIN:-}"
token="${SAFE_ZONE_DUCKDNS_TOKEN:-}"
token_file="${SAFE_ZONE_DUCKDNS_TOKEN_FILE:-}"

if [ -z "$domain" ] && [ -f "${project_dir}/.env" ]; then
  domain="$(grep -E '^SAFE_ZONE_DUCKDNS_DOMAIN=' "${project_dir}/.env" | head -n1 | cut -d= -f2- | tr -d '\r' || true)"
fi
if [ -z "$token" ] && [ -f "${project_dir}/.env" ]; then
  token="$(grep -E '^SAFE_ZONE_DUCKDNS_TOKEN=' "${project_dir}/.env" | head -n1 | cut -d= -f2- | tr -d '\r' || true)"
fi
if [ -z "$token_file" ] && [ -f "${project_dir}/.env" ]; then
  token_file="$(grep -E '^SAFE_ZONE_DUCKDNS_TOKEN_FILE=' "${project_dir}/.env" | head -n1 | cut -d= -f2- | tr -d '\r' || true)"
fi

if [ -z "$token" ] && [ -n "$token_file" ]; then
  case "$token_file" in
    /*) ;;
    *) token_file="${project_dir}/${token_file#./}" ;;
  esac
  token="$(tr -d '\r\n' < "$token_file")"
fi

if [ -z "$domain" ] || [ -z "$token" ]; then
  echo "SAFE_ZONE_DUCKDNS_DOMAIN and SAFE_ZONE_DUCKDNS_TOKEN or SAFE_ZONE_DUCKDNS_TOKEN_FILE are required" >&2
  exit 2
fi

response="$(wget -qO- "https://www.duckdns.org/update?domains=${domain}&token=${token}&ip=")"
if [ "$response" != "OK" ]; then
  echo "DuckDNS update failed: ${response}" >&2
  exit 1
fi

echo "DuckDNS record updated for ${domain}.duckdns.org"
