#!/usr/bin/env sh
set -eu

project_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cert_src="${1:-${SAFE_ZONE_DOT_CERT_SOURCE:-}}"
key_src="${2:-${SAFE_ZONE_DOT_KEY_SOURCE:-}}"
target_dir="${SAFE_ZONE_DOT_CERT_TARGET_DIR:-${project_dir}/ops/certs/dot}"

if [ -z "$cert_src" ] || [ -z "$key_src" ]; then
  echo "usage: scripts/export-dot-cert.sh /path/to/fullchain.pem /path/to/privkey.pem" >&2
  echo "or set SAFE_ZONE_DOT_CERT_SOURCE and SAFE_ZONE_DOT_KEY_SOURCE." >&2
  exit 2
fi

if [ ! -f "$cert_src" ]; then
  echo "certificate source not found: $cert_src" >&2
  exit 1
fi
if [ ! -f "$key_src" ]; then
  echo "key source not found: $key_src" >&2
  exit 1
fi

mkdir -p "$target_dir"
install -m 0644 "$cert_src" "$target_dir/fullchain.pem"
install -m 0600 "$key_src" "$target_dir/privkey.pem"

echo "DoT certificate bundle written to $target_dir"
