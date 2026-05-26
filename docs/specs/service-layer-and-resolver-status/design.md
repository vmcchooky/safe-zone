# Design: Shared Risk Service and Resolver Status

## Overview

The current binaries both implement the same sequence:

1. Normalize domain.
2. Check Redis for `safe-zone:analysis:<domain>`.
3. Analyze locally on miss or cache failure.
4. Write the result back with verdict-specific TTL.
5. Return result plus cache-hit metadata.

This design moves that sequence into `internal/risk`. The command packages stay responsible for HTTP routing, request parsing, and DNS wire-format handling.

## Internal Package

Add `internal/risk`.

### Types

- `Service`
  - Owns the Redis cache wrapper and cache policy configuration.
  - Exposes methods needed by both binaries.

- `Options`
  - `Redis *cache.Redis`
  - `RedisTimeout time.Duration`
  - `TTLAllowed time.Duration`
  - `TTLSuspicious time.Duration`
  - `TTLBlocked time.Duration`
  - `RecentLimit int64`

- `Analysis`
  - Embeds `analysis.Result`.
  - Adds `cache_hit` and `analyzed_at`.
  - This keeps `core-api` response JSON compatible.

- `Policy`
  - Contains `domain`, `policy`, `result`, and `cache_hit`.
  - Used by `dns-resolver` to avoid duplicating policy rules.

- `Status`
  - Reports whether Redis is configured and whether a ping succeeds within timeout.

### Methods

- `Analyze(ctx, domain) Analysis`
- `Policy(ctx, domain) Policy`
- `RecordRecent(ctx, Analysis)`
- `Recent(ctx) []Analysis`
- `CacheStatus(ctx) Status`
- `Close() error`

## Cache Keys

- Analysis result: `safe-zone:analysis:<normalized-domain>`
- Recent analysis list: `safe-zone:analysis:recent`

## Policy Rule

For this slice, only `analysis.VerdictMalicious` maps to `block`. All other verdicts map to `allow`. Suspicious behavior remains a future configuration item.

## Resolver Root Status

`GET /` on `dns-resolver` returns:

- `service`
- `status`
- `mode`
- `upstream_doh`
- `redis`
- `endpoints`
- `time`

This is intentionally JSON, not HTML, because the resolver is an infrastructure service rather than a user dashboard.

## Error Handling

- Redis errors are logged and do not fail requests.
- Invalid domains still return deterministic `INVALID` analysis results.
- Existing HTTP method handling remains explicit per endpoint.
