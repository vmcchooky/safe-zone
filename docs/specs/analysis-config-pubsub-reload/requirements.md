# Requirements: Multi-Node Analysis Config Reload

## Goal

Keep `analysis_config` consistent across multiple `core-api` and `dns-resolver` processes without requiring process restarts after an operator changes scoring settings.

## Functional Requirements

- When an operator updates analysis scoring through `PUT /v1/config/analysis`, the writing node must still persist the config to SQLite and apply it locally in memory.
- Other running nodes that use `internal/risk.Service` must reload the new analysis config automatically.
- The propagation path must use Redis Pub/Sub when Redis is configured.
- Nodes must ignore stale or duplicate reload events.
- On startup, a node must still load the latest stored analysis config from SQLite before serving traffic.
- If a node misses a Pub/Sub event during reconnect or transient Redis outage, it must converge back to the latest SQLite config without a restart.
- `ResetAnalysisConfig` must use the same propagation mechanism as `UpdateAnalysisConfig`.
- Existing API shapes for `/v1/config/analysis` and `/v1/config/analysis/reset` must stay compatible.

## Non-Functional Requirements

- Redis remains optional. Single-node deployments without Redis must continue to work exactly as today.
- Redis outages must remain fail-open for request serving. Domain analysis must continue with the last known in-memory config.
- The implementation should stay local-first and lightweight: no new external broker, no scheduler dependency, and no migration away from SQLite as operator source of truth.
- The design must not require synchronous fan-out RPC between application nodes.
- Reload work must remain concurrency-safe with the existing `analyzerMu` protections.

## Operational Requirements

- Operators must have one obvious channel/key name to inspect when debugging config propagation.
- Logs must make it clear when a node publishes, receives, ignores, or self-heals a config revision.
- The system should expose enough internal state to confirm which revision a node currently has loaded.

## Acceptance Criteria

- In a two-node setup sharing the same SQLite and Redis, updating analysis config on Node A causes Node B to serve the new config without restart.
- Repeating the same config update does not thrash reloads or corrupt in-memory state.
- Restarting Node B after a config change still loads the latest stored config from SQLite.
- Temporarily disconnecting Node B from Redis, updating config on Node A, then restoring Redis causes Node B to converge back to the latest config via the fallback sync path.
- `go test ./internal/risk ./internal/cache ./cmd/core-api ./cmd/dns-resolver` passes after implementation.
