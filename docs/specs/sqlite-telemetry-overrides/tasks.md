# Tasks: SQLite Telemetry & Local Overrides

## Milestone 1: SQLite Store Package

- [x] Add `modernc.org/sqlite` dependency (pure Go, CGO_ENABLED=0 compatible).
- [x] Create `internal/store/sqlite.go` with DB struct, schema auto-migration, and WAL pragmas.
- [x] Implement async telemetry writer with buffered channel and drain-on-close.
- [x] Implement periodic cleanup goroutine (hourly, configurable retention).
- [x] Implement override CRUD with parent-domain matching.
- [x] Create `internal/store/sqlite_test.go` with 22 unit tests.
- [x] All store tests pass.

## Milestone 2: Pipeline Integration

- [x] Add `Store *store.DB` to `risk.Options` and `risk.Service`.
- [x] Add Local Overrides as first step in `analyze()` pipeline.
- [x] Add async telemetry recording at end of `Analyze()` method.
- [x] Update `risk.Close()` to close both Redis and SQLite.
- [x] Add override and telemetry wrapper methods to `risk.Service`.
- [x] Update `internal/risk/env.go` with `SAFE_ZONE_SQLITE_PATH` and `SAFE_ZONE_TELEMETRY_RETENTION_DAYS`.
- [x] Add 5 new tests in `service_test.go` (override block, allow, beats whitelist, nil fail-open, delete-then-analyze).
- [x] All risk tests pass (16/16).

## Milestone 3: API & Configuration

- [x] Add `GET/POST/DELETE /v1/overrides` handler to `core-api`.
- [x] Add `GET /v1/telemetry/recent` handler with pagination.
- [x] Add `GET /v1/telemetry/stats` handler with period filter.
- [x] Update status endpoint with new routes.
- [x] Update `.env.example` with new env vars.
- [x] Update `docker-compose.yml` with `app-data` volume for SQLite persistence.

## Milestone 4: Verification

- [x] `go test ./...` — all packages pass.
- [x] `go build ./...` — all binaries compile.

## Completion Rule

No telemetry or override feature should be added outside this spec without a documented design update.
