#!/usr/bin/env sh
# Coverage gate for the Go test suite. Runs the suite with -race and a
# -coverprofile, then fails when total statement coverage drops below
# SAFE_ZONE_COVER_THRESHOLD (default 50).
#
#   SAFE_ZONE_COVER_THRESHOLD=60 sh ./scripts/ops/coverage.sh
#   SAFE_ZONE_COVER_PKGS="./internal/store/..." sh ./scripts/ops/coverage.sh
set -eu

threshold="${SAFE_ZONE_COVER_THRESHOLD:-65}"
profile="${SAFE_ZONE_COVER_PROFILE:-coverage.out}"
# Mirrors the go:test package list in mise.toml (research CLIs under tools/
# are covered separately by research:test, without a coverage gate).
pkgs="${SAFE_ZONE_COVER_PKGS:-./cmd/... ./internal/... ./ml/...}"

if [ "${SAFE_ZONE_COVER_RUN_TESTS:-1}" = "1" ]; then
  # Intentional word splitting: pkgs is a space-separated package list.
  # shellcheck disable=SC2086
  go test -race -coverprofile="$profile" $pkgs
fi

total="$(go tool cover -func="$profile" | awk '/^total:/ {gsub(/%/, "", $3); print $3}')"
if [ -z "$total" ]; then
  printf 'coverage gate FAILED: could not parse total coverage from %s (run the test suite with -coverprofile first)\n' "$profile" >&2
  exit 1
fi
if awk -v total="$total" -v threshold="$threshold" 'BEGIN { exit !((total + 0) < (threshold + 0)) }'; then
  printf 'coverage gate FAILED: total %.1f%% < threshold %.1f%% (%s)\n' "$total" "$threshold" "$profile" >&2
  exit 1
fi
printf 'coverage gate passed: total %.1f%% >= threshold %.1f%% (%s)\n' "$total" "$threshold" "$profile"
