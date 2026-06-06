# Design: Redis Pub/Sub Analysis Config Reload

## Overview

Today `analysis_config` is persisted in SQLite, then loaded into each process-local `risk.Service` as an in-memory analyzer. That is correct for single-node deployments, but in a multi-node topology only the writer node reloads immediately.

This design adds a small coordination layer:

1. SQLite remains the source of truth.
2. The writer node publishes a lightweight Redis Pub/Sub event after a successful config write.
3. Every node running `risk.Service` subscribes to that channel and hot-reloads from SQLite when a newer revision appears.
4. A low-frequency SQLite reconciliation loop closes the gap if a Pub/Sub event is missed.

The result is near-real-time reload in healthy Redis conditions, with eventual consistency even across reconnects.

## Scope

In scope:

- `internal/risk.Service` reload orchestration
- Redis Pub/Sub wrapper support in `internal/cache`
- config revision comparison and local reload application
- startup/shutdown lifecycle for subscriber and reconciliation goroutines
- logging and lightweight observability around active config revision

Out of scope:

- distributed locking
- cross-region replication
- general-purpose config service
- changing the public JSON shape of existing config endpoints

## Current State

- `cmd/core-api` writes analysis config through `risk.Service.UpdateAnalysisConfig`.
- `risk.Service` persists the config to SQLite, updates `analysisConfig`, recomputes `configRevision`, and swaps the in-memory analyzer under `analyzerMu`.
- `cmd/dns-resolver` also uses `risk.Service`, so it can benefit from the same reload mechanism even though it does not expose config-write endpoints.

## Proposed Components

### Redis Channel

Use one dedicated channel:

- `safe-zone:config:analysis:updated`

Publish a compact JSON message:

```json
{
  "type": "analysis_config_updated",
  "revision": "abcd1234ef567890",
  "updated_at": "2026-06-06T05:00:00Z",
  "source": "core-api"
}
```

Notes:

- `revision` is the existing hash derived from the normalized config payload.
- `updated_at` is informational for logs and debugging.
- `source` helps operators distinguish writer origin in mixed fleets.

### `internal/cache.Redis` Additions

Add minimal Pub/Sub helpers instead of leaking the raw Redis client everywhere:

- `PublishJSON(ctx, channel string, value any) error`
- `Subscribe(ctx, channel string) (<-chan string, func() error, error)`

The wrapper should keep the current fail-open posture:

- return `ErrDisabled` when Redis is not configured
- return subscription errors to the caller so `risk.Service` can decide whether to log, retry, or disable the listener

### `risk.Service` Lifecycle Additions

Extend `Options` with:

- `ConfigReloadChannel string`
- `ConfigReloadPollInterval time.Duration`
- `NodeRole string`

Extend `Service` with:

- current config reload channel
- subscriber cancel/cleanup handles
- optional reconciliation ticker loop
- subscriber retry/backoff state
- last successful remote reload timestamp for observability

Startup behavior:

1. Build the service from SQLite as today.
2. If both Redis and SQLite are enabled, start:
   - a Pub/Sub listener goroutine
   - a reconciliation goroutine that periodically re-reads SQLite
3. If Redis is disabled, skip Pub/Sub and optionally skip reconciliation for single-node simplicity.

Shutdown behavior:

- Close subscriber before closing Redis.
- Stop reconciliation ticker via existing lifecycle context.
- Make subscriber retry sleep interruptible via the existing lifecycle context so shutdown is never blocked waiting on backoff.

## Write Path

### `UpdateAnalysisConfig`

1. Validate config.
2. Persist to SQLite.
3. Apply config locally under `analyzerMu`.
4. Best-effort publish the new revision event to Redis.
5. Return success with the current config payload.

Why publish after the SQLite write:

- subscribers must be able to read the new source-of-truth config immediately
- the event becomes an invalidation signal, not the payload of record

Why not make publish strictly transactional:

- Redis Pub/Sub and SQLite cannot be committed atomically in the current architecture
- the fallback reconciliation loop covers missed publishes without introducing an outbox table

### `ResetAnalysisConfig`

No special case. It should call `UpdateAnalysisConfig` and therefore publish the same reload event automatically.

## Read/Reload Path

### Subscriber Flow

Run the subscriber inside a reconnect loop:

1. Subscribe to the Redis channel.
2. Process messages until the subscription errors, closes, or the service lifecycle context is cancelled.
3. On disconnect, log the cause and retry with bounded exponential backoff.
4. Reset backoff after a healthy resubscribe.

Recommended retry policy:

- start at `250ms`
- double on consecutive failures
- cap at `5s`
- abort immediately on service shutdown

For each incoming event:

1. Decode JSON.
2. Ignore messages with empty revision or wrong type.
3. Compare `event.revision` against `currentConfigRevision()`.
4. If equal, ignore immediately as duplicate or self-originated echo without touching SQLite.
5. If different, call `reloadAnalysisConfigFromStore(ctx, reason)`:
   - read latest config from SQLite
   - compute revision
   - if revision still differs, swap analyzer/config under lock
   - log success with old and new revision

Important detail:

- Subscribers should reload from SQLite, not trust the Pub/Sub payload as the config body. That keeps one source of truth and avoids duplicate validation logic in the event path.

### Reconciliation Loop

Every `ConfigReloadPollInterval`:

1. Read `analysis_config` from SQLite.
2. Compute its revision.
3. Compare with local `configRevision`.
4. If different, apply it and log a self-heal event.

Recommended default:

- `SAFE_ZONE_CONFIG_RELOAD_POLL_SECONDS=30`

This is intentionally low frequency because Pub/Sub is the fast path and SQLite polling only heals drift.

## Concurrency Model

Existing `analyzerMu` remains the only lock guarding:

- `analyzer`
- `analysisConfig`
- `configRevision`

Add one helper to centralize mutation:

- `applyAnalysisConfigLocked(cfg config.AnalysisConfig)`

That keeps write, subscriber reload, startup load, and reconciliation on the same code path.

## Failure Handling

### SQLite Write Succeeds, Publish Fails

Behavior:

- request still succeeds
- writer node is updated immediately
- warning log records publish failure
- other nodes catch up through reconciliation

Reasoning:

- the source of truth has already changed
- failing the request would not roll back SQLite and would create misleading operator behavior

### Subscriber Loses Redis Connection

Behavior:

- log warning
- rely on reconciliation loop for eventual convergence
- retry subscription with bounded exponential backoff until service shutdown

Why this matters:

- Go Redis Pub/Sub subscriptions can terminate on transport churn
- a reconnect loop keeps the fast path alive without requiring operator intervention

### Invalid Stored Config

Behavior:

- keep current in-memory config
- log an error
- do not swap analyzer on malformed data

This should be rare because all normal writes already go through `Validate()`.

## Observability

Add logs for:

- publish success/failure
- remote reload applied
- duplicate/stale event ignored
- reconciliation self-heal applied
- subscription disconnect/retry

Add lightweight state in status/metrics if convenient:

- current `config_revision`
- last config reload timestamp
- reload source: `startup`, `local_write`, `pubsub`, `reconcile`

This can surface later in `/metrics` or debug status without changing the operator-facing config APIs.

## Environment Variables

Suggested additions:

- `SAFE_ZONE_CONFIG_RELOAD_CHANNEL` default `safe-zone:config:analysis:updated`
- `SAFE_ZONE_CONFIG_RELOAD_POLL_SECONDS` default `30`
- `SAFE_ZONE_CONFIG_RELOAD_ENABLED` default `true`

Enablement rule:

- feature is active only when `SAFE_ZONE_CONFIG_RELOAD_ENABLED=true`, Redis is enabled, and SQLite store is enabled

## Implementation Notes

- Keep the subscriber in `internal/risk`, not `cmd/core-api`, so both `core-api` and `dns-resolver` inherit the behavior automatically.
- Reuse the existing `configRevision` hash to avoid introducing a second versioning scheme.
- Prefer one small reload event over publishing the full config payload.
- Do not block analysis requests on reconciliation work.
