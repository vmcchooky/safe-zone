#!/usr/bin/env bash
# Tests for scripts/ops/monitor-certs.sh.
#
# The monitor is driven through stub `openssl` and `date` commands so the
# suite needs no network, no real certificate, and no wall-clock dependency.
# It covers the regressions that matter operationally:
#   - settings come from .env even when cron did not export them
#   - an expired certificate is fatal without --fail-on-warning
#   - an unreadable certificate is fatal
#   - the warning window and --fail-on-warning behave as documented
set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
source_monitor="${script_dir}/../monitor-certs.sh"

if [[ ! -f "$source_monitor" ]]; then
  echo "FATAL: cannot find monitor-certs.sh next to the test: $source_monitor" >&2
  exit 2
fi

work_root="$(mktemp -d "${TMPDIR:-/tmp}/safe-zone-monitor-certs-test.XXXXXX")"
trap 'rm -rf "$work_root"' EXIT

stub_dir="$work_root/bin"
mkdir -p "$stub_dir"
stub_openssl="$stub_dir/openssl"
stub_date="$stub_dir/date"
stdout_log="$work_root/stdout.log"
stderr_log="$work_root/stderr.log"
openssl_log="$work_root/openssl.log"

cat > "$stub_openssl" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >> "${SZ_STUB_OPENSSL_LOG:?}"
case "${SZ_STUB_OPENSSL_FAIL:-}" in
  all) exit 1 ;;
  x509)
    if [ "$1" = "x509" ]; then
      exit 1
    fi
    ;;
esac
if [ "$1" = "x509" ]; then
  # The monitor only asks for the end date; drain the certificate bytes.
  cat >/dev/null
  printf 'notAfter=%s\n' "${SZ_STUB_ENDDATE:?}"
fi
exit 0
STUB
chmod +x "$stub_openssl"

# The monitor only uses "date -u +%s" and "date -u -d <openssl date> +%s".
# Both are deterministic here so the suite never depends on the clock.
cat > "$stub_date" <<'STUB'
#!/bin/sh
case " $* " in
  *" -d "*) printf '%s\n' "${SZ_STUB_EXPIRY_EPOCH:?}" ;;
  *) printf '%s\n' "${SZ_STUB_NOW_EPOCH:?}" ;;
esac
STUB
chmod +x "$stub_date"

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

require_log_contains() {
  if grep -Fq -- "$1" "$openssl_log"; then
    pass "$2"
  else
    fail "$2: openssl log is missing: $1"
    sed 's/^/  log: /' "$openssl_log" >&2
  fi
}

make_project() {
  local env_content="$1"
  local proj="$work_root/proj"
  rm -rf "$proj"
  mkdir -p "$proj/scripts/ops"
  cp "$source_monitor" "$proj/scripts/ops/monitor-certs.sh"
  printf '%s\n' "$env_content" > "$proj/.env"
  printf '%s' "$proj"
}

now_epoch=1000000000
expiry_epoch=$((now_epoch + 30 * 86400))
enddate="stub-cert-date"
openssl_fail=""

run_monitor() {
  local proj="$1" label="$2" want="$3"
  shift 3
  : > "$openssl_log"
  local status=0
  (
    cd /
    PATH="$stub_dir:$PATH"
    export PATH
    export SAFE_ZONE_ENV_FILE="$proj/.env"
    export SZ_STUB_OPENSSL_LOG="$openssl_log"
    export SZ_STUB_NOW_EPOCH="$now_epoch"
    export SZ_STUB_EXPIRY_EPOCH="$expiry_epoch"
    export SZ_STUB_ENDDATE="$enddate"
    export SZ_STUB_OPENSSL_FAIL="$openssl_fail"
    bash "$proj/scripts/ops/monitor-certs.sh" "$@"
  ) >"$stdout_log" 2>"$stderr_log" || status=$?
  if [[ "$status" -eq "$want" ]]; then
    pass "$label (exit $status)"
  else
    fail "$label: exit $status, want $want"
    sed 's/^/  out: /' "$stdout_log" >&2
    sed 's/^/  err: /' "$stderr_log" >&2
  fi
}

### 1. Healthy certificate: host and threshold come from .env.

proj="$(make_project 'SAFE_ZONE_CERT_MONITOR_HOST=example.test
SAFE_ZONE_CERT_WARN_DAYS=14
SAFE_ZONE_DNS_DOT_ENABLED=false')"
now_epoch=1000000000
expiry_epoch=$((now_epoch + 30 * 86400))
openssl_fail=""
run_monitor "$proj" 'healthy certificate' 0
require_stdout_contains 'example.test:443' 'healthy: host is read from .env'
require_log_contains '-connect example.test:443' 'healthy: openssl checks the .env host'

### 2. Inside the warning window without the flag: log, exit 0.

proj="$(make_project 'SAFE_ZONE_CERT_MONITOR_HOST=example.test
SAFE_ZONE_CERT_WARN_DAYS=30
SAFE_ZONE_DNS_DOT_ENABLED=false')"
expiry_epoch=$((now_epoch + 20 * 86400))
run_monitor "$proj" 'warning without --fail-on-warning' 0
require_stdout_contains 'WARNING: HTTPS certificate on example.test:443' 'warning: reports the host and window'

### 3. Inside the warning window with --fail-on-warning: exit 1.

run_monitor "$proj" 'warning with --fail-on-warning' 1 --fail-on-warning

### 4. .env can turn the failure on; no CLI flag needed.

proj="$(make_project 'SAFE_ZONE_CERT_MONITOR_HOST=example.test
SAFE_ZONE_CERT_WARN_DAYS=30
SAFE_ZONE_CERT_FAIL_ON_WARN=true
SAFE_ZONE_DNS_DOT_ENABLED=false')"
run_monitor "$proj" 'warning with .env fail switch' 1

### 5. Expired certificate is fatal even without the flag.

proj="$(make_project 'SAFE_ZONE_CERT_MONITOR_HOST=example.test
SAFE_ZONE_CERT_WARN_DAYS=14
SAFE_ZONE_DNS_DOT_ENABLED=false')"
expiry_epoch=$((now_epoch - 86400))
run_monitor "$proj" 'expired certificate' 1
require_stderr_contains 'has expired' 'expired: names the condition'

### 6. An unreadable certificate is fatal.

openssl_fail="all"
run_monitor "$proj" 'unreadable certificate' 1
require_stderr_contains 'unable to read certificate' 'unreadable: names the failure'

### 7. A non-numeric warning threshold is rejected before any connection.

openssl_fail=""
proj="$(make_project 'SAFE_ZONE_CERT_MONITOR_HOST=example.test
SAFE_ZONE_CERT_WARN_DAYS=fourteen
SAFE_ZONE_DNS_DOT_ENABLED=false')"
expiry_epoch=$((now_epoch + 30 * 86400))
run_monitor "$proj" 'invalid warning threshold' 2
require_stderr_contains 'non-negative integer' 'invalid threshold: explains the expected value'

### 8. Without a monitor host, fall back to SAFE_ZONE_PUBLIC_HOST.

proj="$(make_project 'SAFE_ZONE_PUBLIC_HOST=fallback.test
SAFE_ZONE_CERT_WARN_DAYS=14
SAFE_ZONE_DNS_DOT_ENABLED=false')"
run_monitor "$proj" 'public host fallback' 0
require_stdout_contains 'fallback.test:443' 'fallback: uses SAFE_ZONE_PUBLIC_HOST'

printf '\n%s passed, %s failed\n' "$passed" "$failed"
if [[ "$failed" -ne 0 ]]; then
  exit 1
fi
