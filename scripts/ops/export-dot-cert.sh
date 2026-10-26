#!/usr/bin/env sh
set -eu

project_dir="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cert_src="${1:-${SAFE_ZONE_DOT_CERT_SOURCE:-}}"
key_src="${2:-${SAFE_ZONE_DOT_KEY_SOURCE:-}}"
target_dir="${SAFE_ZONE_DOT_CERT_TARGET_DIR:-${project_dir}/ops/certs/dot}"
key_group="${SAFE_ZONE_DOT_KEY_GROUP:-101}"

if [ -z "$cert_src" ] || [ -z "$key_src" ]; then
  echo "usage: scripts/ops/export-dot-cert.sh /path/to/fullchain.pem /path/to/privkey.pem" >&2
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
install -m 0640 "$key_src" "$target_dir/privkey.pem"

# The resolver runs as the unprivileged app user (UID 100 / GID 101 on
# Alpine 3.24). The key must be group-readable, and the directory must be
# traversable by that group, or DoT startup fails with a permission error.
if ! chgrp "$key_group" "$target_dir/privkey.pem" 2>/dev/null; then
  echo "ERROR: cannot set group ${key_group} on ${target_dir}/privkey.pem." >&2
  echo "Run as root, or run:" >&2
  echo "  sudo chgrp ${key_group} ${target_dir}/privkey.pem" >&2
  echo "  sudo chmod 0640 ${target_dir}/privkey.pem" >&2
  exit 1
fi
chmod 0640 "$target_dir/privkey.pem"

if ! chgrp "$key_group" "$target_dir" 2>/dev/null; then
  echo "ERROR: cannot set group ${key_group} on ${target_dir}." >&2
  echo "Run: sudo chgrp ${key_group} ${target_dir} && sudo chmod 0750 ${target_dir}" >&2
  exit 1
fi
chmod 0750 "$target_dir"

echo "DoT certificate bundle written to $target_dir (key group: $key_group, mode: 0640)"
