#!/usr/bin/env bash
# Preflight tests for scripts/ops/safe-zone.sh.
#
# Runs the real deploy path against a stub SAFE_ZONE_COMPOSE inside a
# throwaway project skeleton, so the .env the helper reads is fully
# controlled and nothing ever touches Docker. Covers the three file-set
# combinations (production, shared-host, shared-host+DoT) plus the failure
# gates: old Compose, wrong SAFE_ZONE_ENV, placeholder block IP, missing DoT
# certificates.
set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
source_safe_zone="${script_dir}/../safe-zone.sh"

if [ ! -f "$source_safe_zone" ]; then
  echo "FATAL: cannot find safe-zone.sh next to the test: $source_safe_zone" >&2
  exit 2
fi

work_root="$(mktemp -d "${TMPDIR:-/tmp}/safe-zone-preflight-test.XXXXXX")"
trap 'rm -rf "$work_root"' EXIT

stub_dir="$work_root/bin"
mkdir -p "$stub_dir"
stub_compose="$stub_dir/sz-stub-compose"
stub_log="$work_root/stub.log"
stderr_log="$work_root/stderr.log"

# The stub records every invocation (one line each, args joined by spaces)
# and answers `version --short` with SZ_STUB_COMPOSE_VERSION so the version
# gate can be driven up and down.
cat > "$stub_compose" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >> "$SZ_STUB_LOG"
case "$1" in
  version)
    case " $* " in
      *" --short "*) printf '%s\n' "${SZ_STUB_COMPOSE_VERSION:-v2.39.2}" ;;
      *) printf 'Docker Compose version %s\n' "${SZ_STUB_COMPOSE_VERSION:-v2.39.2}" ;;
    esac
    exit 0
    ;;
esac
exit 0
STUB
chmod +x "$stub_compose"

passed=0
failed=0

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  failed=$((failed + 1))
}

pass() {
  printf 'ok: %s\n' "$1"
  passed=$((passed + 1))
}

require_log_contains() {
  local log="$1" needle="$2" label="$3"
  if grep -Fq -- "$needle" "$log"; then
    pass "$label"
  else
    fail "$label: stub log is missing: $needle"
    sed 's/^/  log: /' "$log" >&2
  fi
}

require_log_not_contains() {
  local log="$1" needle="$2" label="$3"
  if grep -Fq -- "$needle" "$log"; then
    fail "$label: stub log unexpectedly contains: $needle"
    sed 's/^/  log: /' "$log" >&2
  else
    pass "$label"
  fi
}

require_stderr_contains() {
  local needle="$1" label="$2"
  if grep -Fq -- "$needle" "$stderr_log"; then
    pass "$label"
  else
    fail "$label: stderr is missing: $needle"
    sed 's/^/  err: /' "$stderr_log" >&2
  fi
}

# make_project writes a controlled project skeleton: the helper resolves its
# project dir relative to its own location, so the copy also isolates the
# .env it falls back to.
make_project() {
  local env_content="$1" with_certs="$2"
  local proj="$work_root/proj"
  rm -rf "$proj"
  mkdir -p "$proj/scripts/ops" "$proj/ops/vps-edge"
  cp "$source_safe_zone" "$proj/scripts/ops/safe-zone.sh"
  printf '%s\n' "$env_content" > "$proj/.env"
  if [ "$with_certs" = "certs" ]; then
    mkdir -p "$proj/ops/certs/dot"
    : > "$proj/ops/certs/dot/fullchain.pem"
    : > "$proj/ops/certs/dot/privkey.pem"
  fi
  printf '%s' "$proj"
}

# run_deploy executes the deploy path against the stub compose and returns
# the deploy exit code. Artifacts land in the fixed $stub_log and
# $stderr_log paths.
run_deploy() {
  local proj="$1" compose_version="$2"
  : > "$stub_log"
  : > "$stderr_log"
  local status=0
  (
    cd /
    SAFE_ZONE_SKIP_MISE=1 \
      SAFE_ZONE_COMPOSE="$stub_compose" \
      SZ_STUB_LOG="$stub_log" \
      SZ_STUB_COMPOSE_VERSION="$compose_version" \
      sh "$proj/scripts/ops/safe-zone.sh" deploy >/dev/null 2>"$stderr_log"
  ) || status=$?
  return "$status"
}

run_deploy_ok() {
  local proj="$1" compose_version="$2" label="$3"
  if run_deploy "$proj" "$compose_version"; then
    pass "$label: deploy succeeded"
  else
    fail "$label: deploy should succeed"
    sed 's/^/  err: /' "$stderr_log" >&2
  fi
}

run_deploy_fail() {
  local proj="$1" compose_version="$2" label="$3"
  local status=0
  run_deploy "$proj" "$compose_version" || status=$?
  if [ "$status" -eq 0 ]; then
    fail "$label: deploy must fail"
  else
    pass "$label: deploy failed with exit $status"
  fi
  require_log_not_contains "$stub_log" "up -d --build" "$label: never reaches up -d --build"
}

### 1. Plain production: base files only, version check, config -q before up.

proj="$(make_project 'SAFE_ZONE_ENV=production
SAFE_ZONE_BLOCK_PAGE_IP=93.184.216.34
SAFE_ZONE_DNS_DOT_ENABLED=false
SAFE_ZONE_DNS_BLOCK_STRATEGY=sinkhole' nocerts)"

run_deploy_ok "$proj" v2.39.2 "production"
require_stderr_empty="production: deploy stderr is clean"
if [ -s "$stderr_log" ]; then
  fail "$require_stderr_empty"
  sed 's/^/  err: /' "$stderr_log" >&2
else
  pass "$require_stderr_empty"
fi

if [ "$(sed -n '1p' "$stub_log")" = "version --short" ]; then
  pass "production: compose version is checked first"
else
  fail "production: first compose call should be 'version --short'"
  sed 's/^/  log: /' "$stub_log" >&2
fi
require_log_contains "$stub_log" "-f docker-compose.yml -f docker-compose.production.yml --profile production-edge config -q" \
  "production: config -q runs on the exact file set"
require_log_contains "$stub_log" "-f docker-compose.yml -f docker-compose.production.yml --profile production-edge up -d --build" \
  "production: up -d --build uses the same file set"
require_log_not_contains "$stub_log" "docker-compose.host-edge.yml" "production: no host-edge overlay"
require_log_not_contains "$stub_log" "docker-compose.dot.yml" "production: no DoT overlay"
require_log_not_contains "$stub_log" "stop feed-syncd" "production: feed-syncd keeps running"

if [ "$(sed -n '2p' "$stub_log")" = "-f docker-compose.yml -f docker-compose.production.yml --profile production-edge config -q" ] &&
  [ "$(sed -n '3p' "$stub_log")" = "-f docker-compose.yml -f docker-compose.production.yml --profile production-edge up -d --build" ]; then
  pass "production: config -q runs before up"
else
  fail "production: expected order version -> config -q -> up"
  sed 's/^/  log: /' "$stub_log" >&2
fi

### 2. shared-host-edge: host overlay merged, still config -q first, still no Caddy change.

proj="$(make_project 'SAFE_ZONE_ENV=production
SAFE_ZONE_DEPLOYMENT_TIER=shared-host-edge
SAFE_ZONE_BLOCK_PAGE_IP=93.184.216.34
SAFE_ZONE_DNS_DOT_ENABLED=false' nocerts)"

run_deploy_ok "$proj" v2.39.2 "shared-host"
require_log_contains "$stub_log" "-f docker-compose.yml -f docker-compose.production.yml -f ops/vps-edge/docker-compose.host-edge.yml --profile production-edge config -q" \
  "shared-host: config -q includes the host-edge overlay"
require_log_contains "$stub_log" "-f docker-compose.yml -f docker-compose.production.yml -f ops/vps-edge/docker-compose.host-edge.yml --profile production-edge up -d --build" \
  "shared-host: up includes the host-edge overlay"
require_log_not_contains "$stub_log" "docker-compose.dot.yml" "shared-host: no DoT overlay"

### 3. shared-host-edge + DoT: dot overlay merged, certificate files required.

proj="$(make_project 'SAFE_ZONE_ENV=production
SAFE_ZONE_DEPLOYMENT_TIER=shared-host-edge
SAFE_ZONE_BLOCK_PAGE_IP=93.184.216.34
SAFE_ZONE_DNS_DOT_ENABLED=true
SAFE_ZONE_DNS_DOT_CERTS_DIR=./ops/certs/dot' certs)"

run_deploy_ok "$proj" v2.39.2 "shared-host+DoT"
require_log_contains "$stub_log" "-f docker-compose.yml -f docker-compose.production.yml -f ops/vps-edge/docker-compose.host-edge.yml -f ops/vps-edge/docker-compose.dot.yml --profile production-edge config -q" \
  "shared-host+DoT: config -q includes the DoT overlay"
require_log_contains "$stub_log" "-f ops/vps-edge/docker-compose.dot.yml --profile production-edge up -d --build" \
  "shared-host+DoT: up includes the DoT overlay"

### 4. Compose too old for !override/!reset: clear error, never builds.

proj="$(make_project 'SAFE_ZONE_ENV=production
SAFE_ZONE_BLOCK_PAGE_IP=93.184.216.34
SAFE_ZONE_DNS_DOT_ENABLED=false' nocerts)"

run_deploy_fail "$proj" v2.20.0 "compose v2.20"
require_stderr_contains "v2.24" "compose v2.20: error names the required version"

### 5. Placeholder block page IP with the default sinkhole strategy.

proj="$(make_project 'SAFE_ZONE_ENV=production
SAFE_ZONE_BLOCK_PAGE_IP=replace-with-vps-public-ip
SAFE_ZONE_DNS_BLOCK_STRATEGY=sinkhole
SAFE_ZONE_DNS_DOT_ENABLED=false' nocerts)"

run_deploy_fail "$proj" v2.39.2 "placeholder block IP"
require_stderr_contains "SAFE_ZONE_BLOCK_PAGE_IP" "placeholder block IP: error names the variable"

### 6. SAFE_ZONE_ENV not production.

proj="$(make_project 'SAFE_ZONE_ENV=local
SAFE_ZONE_BLOCK_PAGE_IP=93.184.216.34
SAFE_ZONE_DNS_DOT_ENABLED=false' nocerts)"

run_deploy_fail "$proj" v2.39.2 "SAFE_ZONE_ENV=local"
require_stderr_contains "SAFE_ZONE_ENV" "SAFE_ZONE_ENV=local: error names the variable"

### 7. DoT enabled but certificate pair missing.

proj="$(make_project 'SAFE_ZONE_ENV=production
SAFE_ZONE_BLOCK_PAGE_IP=93.184.216.34
SAFE_ZONE_DNS_DOT_ENABLED=true
SAFE_ZONE_DNS_DOT_CERTS_DIR=./ops/certs/dot' nocerts)"

run_deploy_fail "$proj" v2.39.2 "missing DoT certs"
require_stderr_contains "fullchain.pem" "missing DoT certs: error names the certificate"

### 8. Non-sinkhole strategy does not require a block page IP.

proj="$(make_project 'SAFE_ZONE_ENV=production
SAFE_ZONE_DNS_BLOCK_STRATEGY=nxdomain
SAFE_ZONE_BLOCK_PAGE_IP=replace-with-vps-public-ip
SAFE_ZONE_DNS_DOT_ENABLED=false' nocerts)"

run_deploy_ok "$proj" v2.39.2 "nxdomain"

### 9. The app accepts the "prod" alias, so preflight must too.

proj="$(make_project 'SAFE_ZONE_ENV=prod
SAFE_ZONE_BLOCK_PAGE_IP=93.184.216.34
SAFE_ZONE_DNS_DOT_ENABLED=false' nocerts)"

run_deploy_ok "$proj" v2.39.2 "prod alias"

### 10. Strategy and placeholder matching are case-insensitive, like the app.

proj="$(make_project 'SAFE_ZONE_ENV=production
SAFE_ZONE_BLOCK_PAGE_IP=REPLACE-WITH-vps-public-ip
SAFE_ZONE_DNS_BLOCK_STRATEGY=SINKHOLE
SAFE_ZONE_DNS_DOT_ENABLED=false' nocerts)"

run_deploy_fail "$proj" v2.39.2 "uppercase sinkhole placeholder"
require_stderr_contains "SAFE_ZONE_BLOCK_PAGE_IP" "uppercase sinkhole placeholder: error names the variable"

printf '\n%s passed, %s failed\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
