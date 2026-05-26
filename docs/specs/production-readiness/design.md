# Design: Production Readiness

## Overview

This milestone set keeps Safe Zone local-first while adding the minimum operational surface needed for a real deployment: visibility, repeatable feed ingestion, container health, and test-backed contracts.

## Observability Design

- Use an in-memory registry inside each HTTP service.
- Capture request counts, response bytes, and latency by method, route, and status code.
- Expose the snapshot as JSON from `/metrics`.
- Keep the registry dependency-free so it works in every environment.

## Feed Sync Design

- Keep parsing and Redis writes in `internal/feed`.
- Make `cmd/feed-sync` a one-shot wrapper around the shared sync implementation.
- Make `cmd/feed-syncd` a loop around the same sync implementation.
- Support local files, HTTP/HTTPS URLs, and gzip-compressed feeds.
- Allow `--once` for manual or scheduled single-run execution.

## Container Design

- Use the same runtime image for all binaries.
- Configure the internal healthcheck endpoint through environment variables.
- Keep `core-api` on port 8080 and `dns-resolver` on port 8081.
- Add an optional Compose profile for the feed-sync daemon so local dev does not start it accidentally.

## Testing Design

- HTTP status endpoints should be tested through a real `httptest.NewServer`.
- Metrics should be validated through actual HTTP requests against the service mux.
- Feed sync should be tested at the library layer, not by shelling into the command.
- A small number of integration tests should protect the milestone boundaries instead of broad end-to-end duplication.

## 2026-05-26 Sync Design

- `cmd/load-test` is the reproducible local load path for HTTP API and DoH scenarios. It reports success/error counts, rate-limit outcomes, throughput, and latency percentiles.
- `scripts/safe-zone.sh` and `scripts/safe-zone.ps1` are the operator backup/restore entrypoints. They snapshot Redis, SQLite, `.env`, and Caddy config, then optionally upload the backup directory with `rclone` when `SAFE_ZONE_RCLONE_REMOTE` is configured.
- `scripts/check-production-ports.sh` and `scripts/public-edge-smoke.sh` are the release-gate scripts for the public edge.
- DoT keeps self-signed cert generation for local zero-config runs only. If an operator configures `SAFE_ZONE_DNS_DOT_CERT_FILE` or `SAFE_ZONE_DNS_DOT_KEY_FILE` and loading fails, startup exits immediately.
- DNS blocking strategy is operator-selectable: `sinkhole` returns the configured block-page IP, `nxdomain` returns name error, `refused` returns DNS refused, and `nullip` returns `0.0.0.0` or `::`.
- Panic recovery records HTTP 500 metrics inside the recovery middleware and marks a shared `*bool` in request context so outer request logging does not observe the same panic twice.

## Non-Goals

- Prometheus, OpenTelemetry, or external tracing systems.
- Queue-based scheduling or a database-backed job runner.
- Production orchestration beyond Docker Compose.
- Broad feature expansion beyond the four milestones.
