# Design: SQLite Telemetry & Local Overrides

## Architecture

SQLite runs **alongside Redis**, not replacing it. Each does what it's best at:
- **Redis**: Fast cache, threat feed set lookups, recent analysis list (ephemeral, lost on restart).
- **SQLite**: Long-term telemetry history, admin-managed overrides (persistent, survives restarts).

## Store Package (`internal/store`)

### Database Configuration
```sql
PRAGMA journal_mode=WAL;        -- Concurrent reads/writes
PRAGMA synchronous=NORMAL;      -- Balance speed vs safety
PRAGMA cache_size=-8000;        -- 8MB in-memory cache
PRAGMA busy_timeout=5000;       -- Wait 5s if DB locked
PRAGMA foreign_keys=ON;
```

### Schema
Two tables: `analysis_log` (telemetry) and `local_overrides` (admin rules).
Indexes on domain, analyzed_at, and verdict for fast queries.

### Async Telemetry Writer
- Buffered channel (1000 entries) between caller and writer goroutine.
- Non-blocking send: if buffer full, entry is silently dropped.
- On shutdown, remaining entries are drained before closing DB.

### Cleanup Goroutine
- Runs every hour.
- Deletes `analysis_log` entries older than `retentionDays`.

## Pipeline Change

```
Before: Whitelist → Cache → Threat Feed → Lexical → AI
After:  Local Overrides → Whitelist → Cache → Threat Feed → Lexical → AI → Telemetry
```

Local Overrides checked first because admin intent is highest priority.
Telemetry recorded last (async, non-blocking).

## Override Parent-Domain Matching

When checking overrides, the system tries exact match first, then walks up the domain hierarchy:
- Query: `mail.example.com`
- Checks: `mail.example.com` → `example.com` → `com`

## API Design

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/overrides?action=allow\|block` | List overrides |
| POST | `/v1/overrides` | Create/update override |
| DELETE | `/v1/overrides?domain=x.com` | Remove override |
| GET | `/v1/telemetry/recent?limit=50&offset=0` | Paginated history |
| GET | `/v1/telemetry/stats?period=24h\|7d\|30d` | Aggregate stats |

## What This Design Excludes

- Prometheus, OpenTelemetry, or external tracing systems.
- Web-based admin UI (deferred to Dashboard feature).
- SQLite replication or backup automation.
