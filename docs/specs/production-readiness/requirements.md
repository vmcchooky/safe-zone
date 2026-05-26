# Requirements: Production Readiness

## Goal

Turn the current local-first Safe Zone stack into a production-capable, low-cost service with clear operational boundaries, measurable behavior, and tightly scoped future work.

## Milestones

### Milestone 1: Observability Baseline

- Every HTTP service must expose a machine-readable `/metrics` endpoint.
- Metrics must include request counts, bytes, and latency summaries by route and status code.
- Request logging must include method, path, status, bytes, and duration.
- Metrics must be in-memory and dependency-free.

### Milestone 2: Automated Threat Feed Sync

- Threat feed sync must be reusable by both a one-shot CLI and a long-running daemon.
- The daemon must support interval-based sync and a one-shot mode for manual runs.
- The daemon must reuse the same parsing and Redis write path as the CLI.
- Feed sync must remain fail-fast for invalid input and fail-open for runtime analysis.

### Milestone 3: Container Hardening

- Runtime containers must ship with an internal HTTP healthcheck.
- Healthcheck port and path must be configurable by environment.
- The compose stack must include an optional `feed-syncd` profile for scheduled sync.
- Service images must run non-root.

### Milestone 4: Integration Coverage

- Core HTTP status endpoints must be covered by integration tests through `httptest.NewServer`.
- Metrics endpoints must be validated through HTTP requests.
- Feed sync must be covered by tests for dry-run, gzip sources, and Redis writes.
- The full repository must continue to pass `go test ./...` and `go build ./...`.

### Milestone 5: Production Readiness Sync

- Operators must have a reproducible local HTTP/DoH load-test CLI for cache-hit, cache-miss, concurrency, rate-limit, and latency-summary runs.
- Backup/restore helpers must cover Redis RDB, SQLite hot backups, `.env` snapshots, Caddy config snapshots, and optional `rclone` offsite upload.
- Public-edge checks must be scriptable for intended ports and smoke checks before production release.
- Configured DoT TLS certificate/key failures must fail fast instead of silently falling back to self-signed certificates.
- DNS blocking behavior must be configurable between `sinkhole`, `nxdomain`, `refused`, and `nullip`.
- Panic recovery metrics must be observed exactly once per recovered HTTP panic.

## Functional Requirements

- `/metrics` must be available on `core-api` and `dns-resolver`.
- `cmd/feed-sync` and `cmd/feed-syncd` must share the same sync implementation.
- `cmd/load-test` must support HTTP API and DoH load paths with latency/error summaries.
- `docker-compose.yml` must support the optional feed sync daemon without forcing it on local development.
- Existing API response shapes and DNS behavior must stay compatible.

## Non-Functional Requirements

- No paid observability or feed dependency.
- No database, queue, or external scheduler is required for the first pass.
- Default local development must still work with Redis disabled.
- Changes must stay small and milestone-scoped.

## Acceptance Criteria

- `go test ./...` passes.
- `go build ./...` passes.
- `/metrics` returns JSON for both HTTP services.
- `feed-syncd` can run in one-shot mode and interval mode.
- Docker images validate health through the configured healthcheck endpoint.
- The spec docs in this folder are detailed enough to gate future work without reopening scope.
