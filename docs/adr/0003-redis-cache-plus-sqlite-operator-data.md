# ADR 0003: Redis cache plus SQLite operator data

Date: 2026-05-21

## Status

Accepted

## Decision

Use Redis for high-churn cache and threat-feed set operations, and keep operator-owned records in SQLite.

## Rationale

Redis fits short-lived analysis cache entries, feed sets, and simple in-memory-first lookups. SQLite fits telemetry retention, overrides, client groups, and agent audit history without requiring a separate managed database.

## Consequences

- Redis stays optional for availability; cache-dependent paths fail open.
- SQLite becomes the local source of truth for operator workflows.
- Backup procedures must cover both Redis snapshots and SQLite data.
- Runtime analysis-config hot reload is process-local today; a multi-node deployment will need a broadcast path such as Redis Pub/Sub so every `core-api` node refreshes in-memory analyzers after config changes.
