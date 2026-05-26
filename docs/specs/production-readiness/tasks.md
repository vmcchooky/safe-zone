# Tasks: Production Readiness

## Milestone 1: Observability Baseline

- [x] Add an in-memory request metrics registry.
- [x] Expose `/metrics` on `core-api`.
- [x] Expose `/metrics` on `dns-resolver`.
- [x] Expand request logging with status, bytes, and duration.
- [x] Add HTTP tests for the status and metrics endpoints.

## Milestone 2: Automated Threat Feed Sync

- [x] Extract reusable sync logic into `internal/feed`.
- [x] Keep the one-shot `cmd/feed-sync` wrapper thin.
- [x] Add `cmd/feed-syncd` for interval-based sync.
- [x] Support gzip-compressed feed sources in the shared sync path.
- [x] Add tests for dry-run, gzip sources, and Redis writes.

## Milestone 3: Container Hardening

- [x] Add an internal Docker healthcheck with configurable port/path.
- [x] Run the runtime image as a non-root user.
- [x] Remove container-specific Compose healthcheck duplication.
- [x] Add an optional Compose profile for `feed-syncd`.
- [x] Add environment defaults for healthcheck and sync interval settings.

## Milestone 4: Integration Coverage

- [x] Convert `core-api` status validation into HTTP integration coverage.
- [x] Add `dns-resolver` root status integration coverage.
- [x] Add metrics endpoint integration coverage.
- [x] Add feed sync library integration coverage.
- [x] Verify the full repository with `go test ./...` and `go build ./...`.

## Milestone 5: Production Readiness Sync

- [x] Add local HTTP/DoH load testing CLI for cache-hit, cache-miss, concurrency, rate-limit, and latency-summary scenarios (`cmd/load-test`).
- [x] Add comprehensive backup and restore helpers for Redis RDB, SQLite hot backup via `.backup`, `.env` snapshots, Caddy config snapshots, and optional `rclone` offsite upload.
- [x] Add audited public-edge validation helpers: `scripts/check-production-ports.sh` and `scripts/public-edge-smoke.sh`.
- [x] Make configured DoT TLS key loading fail fast when the configured cert/key paths are invalid, while preserving self-signed fallback only when no cert/key is configured.
- [x] Add configurable DNS blocking strategies: `sinkhole`, `nxdomain`, `refused`, and `nullip`.
- [x] Fix panic recovery double metrics observation by sharing a mutable `*bool` panic-observed marker through request context.

## Completion Rule

Do not add new production-readiness work outside these milestones unless it first gets a new spec entry here.
