# Data retention and privacy policy

This document defines how long Safe Zone should keep telemetry and cache-derived analysis data in SQLite and Redis.

## Goals

- keep enough data for operations and incident review
- minimize retention of client-linked analysis data
- make deletion windows explicit and configurable

## Data classes

| Data class | Store | Purpose | Default retention | Control |
| --- | --- | --- | --- | --- |
| `analysis_log` telemetry | SQLite | Recent analysis history, dashboard stats, incident review | 30 days | `SAFE_ZONE_TELEMETRY_RETENTION_DAYS` |
| Cached analysis results | Redis | Fast repeated lookups for domain analysis | 1h suspicious, 3h allowed, 6h blocked | `SAFE_ZONE_CACHE_TTL_*` |
| Recent dashboard analysis list | Redis | Short operator convenience cache | 24 hours and max 25 entries by default | `SAFE_ZONE_RECENT_ANALYSIS_TTL_SECONDS`, `SAFE_ZONE_DASHBOARD_RECENT_LIMIT` |
| Threat-feed domain set | Redis | Threat intelligence matching | Until next feed refresh or explicit replacement | feed sync process |
| OSINT cached evidence | Redis / SQLite evidence store | Public warning evidence for suspicious domains | Redis cache TTL defaults to 6 hours; SQLite evidence should only hold non-expired items | `SAFE_ZONE_OSINT_CACHE_TTL_SECONDS` plus expiry timestamps |

## SQLite policy

Telemetry retention policy:

- Keep `analysis_log` for 30 days by default.
- Do not increase beyond 90 days without explicit approval.
- For stricter privacy environments, reduce to 7 or 14 days.

Operational data policy:

- Overrides, client groups, mappings, brands, and audit events are operational records, not short-lived telemetry.
- Keep them until changed, deleted, or replaced by operators.
- If a customer or environment requires stricter audit retention, define that separately from telemetry retention.

## Redis policy

Redis should remain a short-lived cache, not a long-term source of truth.

- Analysis cache entries must expire automatically.
- Recent dashboard entries must expire automatically and remain count-bounded.
- Redis should not be used as the only retained copy of operator-critical history.

## Privacy handling

Telemetry may contain:

- analyzed domain
- verdict, score, reasons
- analyzed timestamp
- client IP
- client ID

Therefore:

- restrict dashboard and telemetry API access to admins only
- avoid exporting telemetry outside the protected environment unless required for incident handling
- keep backups encrypted when they contain SQLite or `.env` snapshots

## Recommended production defaults

| Setting | Recommended value |
| --- | --- |
| `SAFE_ZONE_TELEMETRY_RETENTION_DAYS` | `30` |
| `SAFE_ZONE_RECENT_ANALYSIS_TTL_SECONDS` | `86400` |
| `SAFE_ZONE_DASHBOARD_RECENT_LIMIT` | `25` |
| `SAFE_ZONE_CACHE_TTL_ALLOWED_SECONDS` | `10800` |
| `SAFE_ZONE_CACHE_TTL_SUSPICIOUS_SECONDS` | `3600` |
| `SAFE_ZONE_CACHE_TTL_BLOCKED_SECONDS` | `21600` |

## Deletion expectations

- SQLite telemetry cleanup runs automatically based on retention days.
- Redis analysis cache and recent dashboard entries should age out automatically by TTL.
- Operators should purge old backup sets according to the backup retention policy and ensure encrypted artifacts are used for offsite copies.

## Review cadence

Review this policy:

- before major production releases
- whenever telemetry fields change
- whenever retention defaults change
- whenever a new external integration starts storing analysis data elsewhere
