#!/usr/bin/env sh
set -eu

go test -run='^$' -bench=. -benchmem ./internal/analysis ./internal/risk ./cmd/dns-resolver
