# Requirements: SQLite Telemetry & Local Overrides

## Goal

Add persistent local storage (SQLite) to Safe Zone for two purposes:
1. **Telemetry**: Record long-term domain analysis history for reporting and dashboard visualization.
2. **Local Overrides**: Allow administrators to manually block or allow specific domains through a REST API, without restarting the service.

## Milestones

### Milestone 1: SQLite Store Package

- A new `internal/store` package provides all SQLite operations.
- Uses `modernc.org/sqlite` (pure Go, no CGo) to maintain `CGO_ENABLED=0` builds.
- Database auto-migrates on startup (creates tables and indexes if missing).
- WAL mode enabled for concurrent read/write performance.
- Disabled gracefully when path is empty (nil-safe, fail-open).

### Milestone 2: Telemetry

- Every domain analysis is recorded asynchronously via a buffered channel.
- If the channel buffer is full, entries are silently dropped (never blocks DNS resolution).
- Retention is configurable (default 30 days) with automatic hourly cleanup.
- Query API supports pagination (limit/offset) and aggregate statistics (total, safe, suspicious, malicious, cache_hits).

### Milestone 3: Local Overrides

- Admin can create, update, list, and delete domain overrides via REST API.
- Overrides support parent-domain matching (block `example.com` also blocks `mail.example.com`).
- Override pipeline priority: **Local Overrides > Whitelist > Cache > Threat Feed > Lexical > AI**.
- Admin block overrides always produce MALICIOUS verdict with score 100.
- Admin allow overrides always produce SAFE verdict with score 0.

### Milestone 4: API & Configuration

- Five new REST endpoints: overrides CRUD (GET/POST/DELETE) + telemetry query (recent + stats).
- Configuration via two new environment variables (`SAFE_ZONE_SQLITE_PATH`, `SAFE_ZONE_TELEMETRY_RETENTION_DAYS`).
- Docker Compose updated with persistent volume for SQLite data.

## Non-Functional Requirements

- SQLite must not slow down DNS resolution (async telemetry writes).
- SQLite failure must not crash the service (fail-open behavior).
- Database file size must stay manageable (retention-based cleanup).
- No CGo dependency introduced.

## Acceptance Criteria

- All existing tests continue to pass.
- New override and telemetry tests pass.
- Override blocks/allows domain correctly in the analysis pipeline.
- Override takes priority over Tranco whitelist.
- Service operates normally when SQLite is disabled or unavailable.
