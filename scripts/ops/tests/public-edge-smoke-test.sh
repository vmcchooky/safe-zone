#!/usr/bin/env bash
# Tests for scripts/ops/public-edge-smoke.sh.
#
# A stub curl serves a controlled DoH payload, so the suite checks the
# response validator without a public host or network access. It covers the
# header fields the validator must reject: short/empty bodies, QR=0, and a
# non-zero RCODE.
set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
project_dir="$(CDPATH='' cd -- "$script_dir/../../.." && pwd)"
source_smoke="${project_dir}/scripts/ops/public-edge-smoke.sh"

if [[ ! -f "$source_smoke" ]]; then
  echo "FATAL: cannot find public-edge-smoke.sh: $source_smoke" >&2
  exit 2
fi

work_root="$(mktemp -d "${TMPDIR:-/tmp}/safe-zone-public-edge-smoke-test.XXXXXX")"
trap 'rm -rf "$work_root"' EXIT

stub_dir="$work_root/bin"
mkdir -p "$stub_dir"
stub_curl="$stub_dir/curl"
curl_log="$work_root/curl.log"
stdout_log="$work_root/stdout.log"
stderr_log="$work_root/stderr.log"
empty_env="$work_root/empty.env"
: > "$empty_env"

cat > "$stub_curl" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >> "${SZ_STUB_CURL_LOG:?}"
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-o" ]; then
    out="$arg"
  fi
  prev="$arg"
done
# Drain a request body only when curl was asked to read one from stdin.
case " $* " in
  *" --data-binary "*) cat >/dev/null ;;
esac
if [ "${SZ_STUB_CURL_FAIL:-}" = "1" ]; then
  exit 1
fi
if [ -n "$out" ]; then
  cp "${SZ_STUB_DOH_PAYLOAD:?}" "$out"
fi
exit 0
STUB
chmod +x "$stub_curl"

passed=0
failed=0

pass() {
  printf 'ok: %s\n' "$1"
  passed=$((passed + 1))
}

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  failed=$((failed + 1))
}

require_stdout_contains() {
  if grep -Fq -- "$1" "$stdout_log"; then
    pass "$2"
  else
    fail "$2: stdout is missing: $1"
    sed 's/^/  out: /' "$stdout_log" >&2
  fi
}

require_stderr_contains() {
  if grep -Fq -- "$1" "$stderr_log"; then
    pass "$2"
  else
    fail "$2: stderr is missing: $1"
    sed 's/^/  err: /' "$stderr_log" >&2
  fi
}

require_curl_log_contains() {
  if grep -Fq -- "$1" "$curl_log"; then
    pass "$2"
  else
    fail "$2: curl log is missing: $1"
    sed 's/^/  log: /' "$curl_log" >&2
  fi
}

make_payload() {
  local path="$1" payload="$2"
  printf '%b' "$payload" > "$path"
}

valid_payload="$work_root/valid.bin"
short_payload="$work_root/short.bin"
qr0_payload="$work_root/qr0.bin"
rcode3_payload="$work_root/rcode3.bin"
empty_payload="$work_root/empty.bin"

# 12-byte DNS header: ID 0, flags 0x8180 (QR=1, RCODE=0), one question.
make_payload "$valid_payload" '\000\000\201\200\000\001\000\000\000\000\000\000'
# 11 bytes: one short of the minimum DNS header.
make_payload "$short_payload" '\000\000\201\200\000\001\000\000\000\000\000'
# QR=0: a query or a proxy body, not an answer.
make_payload "$qr0_payload" '\000\000\001\200\000\001\000\000\000\000\000\000'
# RCODE=3 (NXDOMAIN): still not a successful DoH answer.
make_payload "$rcode3_payload" '\000\000\201\203\000\001\000\000\000\000\000\000'
: > "$empty_payload"

valid_size="$(wc -c < "$valid_payload" | awk '{print $1}')"
if [[ "$valid_size" -ne 12 ]]; then
  echo "FATAL: valid fixture is $valid_size bytes, want 12" >&2
  exit 2
fi

curl_fail=""

run_smoke() {
  local label="$1" want="$2" payload="$3" env_file="$4"
  shift 4
  : > "$curl_log"
  local status=0
  (
    cd /
    PATH="$stub_dir:$PATH"
    export PATH
    export SAFE_ZONE_ENV_FILE="$env_file"
    export SZ_STUB_CURL_LOG="$curl_log"
    export SZ_STUB_DOH_PAYLOAD="$payload"
    export SZ_STUB_CURL_FAIL="$curl_fail"
    sh "$source_smoke" --no-dot "$@"
  ) >"$stdout_log" 2>"$stderr_log" || status=$?
  if [[ "$status" -eq "$want" ]]; then
    pass "$label (exit $status)"
  else
    fail "$label: exit $status, want $want"
    sed 's/^/  out: /' "$stdout_log" >&2
    sed 's/^/  err: /' "$stderr_log" >&2
  fi
}

### 1. A valid NOERROR answer passes.

run_smoke 'valid DoH response' 0 "$valid_payload" "$empty_env" example.test
require_stdout_contains 'Public edge smoke checks passed for example.test' 'valid: reports success'
require_curl_log_contains 'https://example.test/dns-query' 'valid: queries the DoH endpoint'
require_curl_log_contains '--data-binary' 'valid: sends a DNS message'

### 2. A body shorter than the DNS header fails.

run_smoke 'short DoH response' 2 "$short_payload" "$empty_env" example.test
require_stderr_contains 'not a DNS message' 'short: explains the size failure'

### 3. An empty body fails with the same clear message.

run_smoke 'empty DoH response' 2 "$empty_payload" "$empty_env" example.test
require_stderr_contains 'not a DNS message' 'empty: explains the size failure'

### 4. QR=0 is not an answer.

run_smoke 'QR=0 DoH response' 2 "$qr0_payload" "$empty_env" example.test
require_stderr_contains 'QR=0' 'QR=0: names the failed flag'

### 5. A non-zero RCODE is not a successful answer.

run_smoke 'RCODE=3 DoH response' 2 "$rcode3_payload" "$empty_env" example.test
require_stderr_contains 'RCODE=3' 'RCODE=3: names the failed rcode'

### 6. The host can come from SAFE_ZONE_PUBLIC_HOST in .env.

host_env="$work_root/host.env"
printf '%s\n' 'SAFE_ZONE_PUBLIC_HOST=fallback.test' > "$host_env"
run_smoke 'host fallback' 0 "$valid_payload" "$host_env"
require_stdout_contains 'Public edge smoke checks passed for fallback.test' 'host fallback: uses SAFE_ZONE_PUBLIC_HOST'

### 7. A failed curl exits non-zero instead of reporting success.

curl_fail="1"
run_smoke 'curl failure' 1 "$valid_payload" "$empty_env" example.test
curl_fail=""

printf '\n%s passed, %s failed\n' "$passed" "$failed"
if [[ "$failed" -ne 0 ]]; then
  exit 1
fi
