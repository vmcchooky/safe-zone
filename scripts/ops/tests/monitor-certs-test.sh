#!/usr/bin/env bash
# Tests for scripts/ops/monitor-certs.sh.
#
# The monitor is driven through stub `openssl` and `date` commands so the
# suite needs no network, no real certificate, and no wall-clock dependency.
# It covers the regressions that matter operationally:
#   - settings come from .env even when cron did not export them
#   - an expired certificate is fatal without --fail-on-warning
#   - a certificate that is not valid yet is fatal
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
  empty)
    if [ "$1" = "x509" ]; then
      # Successful exit with no enddate: the monitor must not treat this as
      # a usable certificate.
      cat >/dev/null
      exit 0
    fi
    ;;
esac
if [ "$1" = "x509" ]; then
  # The monitor asks for both validity bounds; drain the certificate bytes.
  cat >/dev/null
  printf 'notBefore=%s\nnotAfter=%s\n' "${SZ_STUB_STARTDATE:?}" "${SZ_STUB_ENDDATE:?}"
fi
exit 0
STUB
chmod +x "$stub_openssl"

# The monitor only uses "date -u +%s" and "date -u -d <openssl date> +%s".
# Both are deterministic here so the suite never depends on the clock. The
# start/end dates are distinguished so notBefore is parsed independently.
cat > "$stub_date" <<'STUB'
#!/bin/sh
case " $* " in
  *" -d "*)
    case " $* " in
      *"${SZ_STUB_STARTDATE:?}"*) printf '%s\n' "${SZ_STUB_START_EPOCH:?}" ;;
      *) printf '%s\n' "${SZ_STUB_EXPIRY_EPOCH:?}" ;;
    esac
    ;;
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

require_log_empty() {
  if [[ -s "$openssl_log" ]]; then
    fail "$1: openssl log should be empty"
    sed 's/^/  log: /' "$openssl_log" >&2
  else
    pass "$1"
  fi
}

require_stderr_not_contains() {
  if grep -Fq -- "$1" "$stderr_log"; then
    fail "$2: stderr must not contain: $1"
    sed 's/^/  err: /' "$stderr_log" >&2
  else
    pass "$2"
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
start_epoch=$((now_epoch - 86400))
expiry_epoch=$((now_epoch + 30 * 86400))
startdate="stub-start-date"
enddate="stub-end-date"
openssl_fail=""
env_file_override=""

run_monitor() {
  local proj="$1" label="$2" want="$3"
  shift 3
  : > "$openssl_log"
  local status=0
  (
    cd /
    PATH="$stub_dir:$PATH"
    export PATH
    export SAFE_ZONE_ENV_FILE="${env_file_override:-$proj/.env}"
    export SZ_STUB_OPENSSL_LOG="$openssl_log"
    export SZ_STUB_NOW_EPOCH="$now_epoch"
    export SZ_STUB_START_EPOCH="$start_epoch"
    export SZ_STUB_EXPIRY_EPOCH="$expiry_epoch"
    export SZ_STUB_STARTDATE="$startdate"
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
require_log_empty 'invalid threshold: does not open a connection'

### 8. Without a monitor host, fall back to SAFE_ZONE_PUBLIC_HOST.

proj="$(make_project 'SAFE_ZONE_PUBLIC_HOST=fallback.test
SAFE_ZONE_CERT_WARN_DAYS=14
SAFE_ZONE_DNS_DOT_ENABLED=false')"
run_monitor "$proj" 'public host fallback' 0
require_stdout_contains 'fallback.test:443' 'fallback: uses SAFE_ZONE_PUBLIC_HOST'

### 9. A leading zero is decimal, not octal: 010 means ten days.

proj="$(make_project 'SAFE_ZONE_CERT_MONITOR_HOST=example.test
SAFE_ZONE_CERT_WARN_DAYS=010
SAFE_ZONE_DNS_DOT_ENABLED=false')"
expiry_epoch=$((now_epoch + 9 * 86400))
run_monitor "$proj" 'leading-zero threshold 010' 1 --fail-on-warning
require_stdout_contains 'inside the 10-day warning window' '010: is read as ten days'

### 10. A leading-zero value that is not valid octal must still work.

proj="$(make_project 'SAFE_ZONE_CERT_MONITOR_HOST=example.test
SAFE_ZONE_CERT_WARN_DAYS=08
SAFE_ZONE_DNS_DOT_ENABLED=false')"
expiry_epoch=$((now_epoch + 4 * 86400))
run_monitor "$proj" 'leading-zero threshold 08' 1 --fail-on-warning
require_stdout_contains 'inside the 8-day warning window' '08: is read as eight days'
require_stderr_not_contains 'value too great for base' '08: no octal arithmetic error'

### 11. 09 follows the same decimal rule.

proj="$(make_project 'SAFE_ZONE_CERT_MONITOR_HOST=example.test
SAFE_ZONE_CERT_WARN_DAYS=09
SAFE_ZONE_DNS_DOT_ENABLED=false')"
expiry_epoch=$((now_epoch + 5 * 86400))
run_monitor "$proj" 'leading-zero threshold 09' 1 --fail-on-warning
require_stdout_contains 'inside the 9-day warning window' '09: is read as nine days'
require_stderr_not_contains 'value too great for base' '09: no octal arithmetic error'

### 12. s_client succeeds but x509 fails: fatal through pipefail.

proj="$(make_project 'SAFE_ZONE_CERT_MONITOR_HOST=example.test
SAFE_ZONE_CERT_WARN_DAYS=14
SAFE_ZONE_DNS_DOT_ENABLED=false')"
expiry_epoch=$((now_epoch + 30 * 86400))
openssl_fail="x509"
run_monitor "$proj" 'x509 failure' 1
require_stderr_contains 'unable to read certificate' 'x509 failure: names the failure'

### 13. x509 exits successfully with empty output: fatal.

openssl_fail="empty"
run_monitor "$proj" 'empty certificate output' 1
require_stderr_contains 'unable to read certificate' 'empty output: names the failure'
openssl_fail=""

### 14. DoT enabled checks the configured DoT host and port as well.

proj="$(make_project 'SAFE_ZONE_CERT_MONITOR_HOST=example.test
SAFE_ZONE_CERT_WARN_DAYS=14
SAFE_ZONE_DNS_DOT_ENABLED=true
SAFE_ZONE_DNS_DOT_PUBLISHED_PORT=8853')"
expiry_epoch=$((now_epoch + 30 * 86400))
run_monitor "$proj" 'DoT certificate check' 0
require_log_contains '-connect example.test:443' 'DoT: still checks HTTPS'
require_log_contains '-connect example.test:8853' 'DoT: openssl checks the DoT host and port'
require_stdout_contains 'DoT certificate on example.test:8853' 'DoT: reports the DoT certificate'

### 15. --help does not require a readable .env and never connects.

env_file_override="$work_root/missing.env"
run_monitor "$proj" '--help without .env' 0 --help
require_stdout_contains 'Usage:' '--help: prints usage'
require_log_empty '--help: does not open a connection'
env_file_override=""

### 16. A certificate that is not valid yet is fatal, even without the flag.

proj="$(make_project 'SAFE_ZONE_CERT_MONITOR_HOST=example.test
SAFE_ZONE_CERT_WARN_DAYS=14
SAFE_ZONE_DNS_DOT_ENABLED=false')"
start_epoch=$((now_epoch + 86400))
expiry_epoch=$((now_epoch + 30 * 86400))
run_monitor "$proj" 'not-yet-valid certificate' 1
require_stderr_contains 'is not valid yet' 'not-yet-valid: names the condition'
start_epoch=$((now_epoch - 86400))

printf '\n%s passed, %s failed\n' "$passed" "$failed"
if [[ "$failed" -ne 0 ]]; then
  exit 1
fi
