# ADR 0002: Single-VPS baseline

Date: 2026-05-21

## Status

Accepted

## Decision

The default production target remains a single budget VPS that runs `core-api`, `dns-resolver`, Redis, SQLite-backed operator data, and Caddy.

## Rationale

The project optimizes for low operational cost, simple deployment, and community maintainability. A single node keeps the release path understandable while still supporting DoH, DoT, dashboard access, and scheduled feed work.

## Consequences

- All runbooks assume single-host operations first.
- New features should justify any move toward split-node or HA deployments.
- Disaster recovery and backups matter more than premature orchestration complexity.
