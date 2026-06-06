# Tasks: Redis Pub/Sub Analysis Config Reload

- [x] Write requirements for multi-node analysis-config reload and Redis Pub/Sub behavior.
- [x] Write design for `risk.Service` subscriber, reconciliation loop, and Redis channel contract.
- [x] Add Redis Pub/Sub helpers to `internal/cache/redis.go`.
- [x] Extend `risk.Options` and `risk.Service` with config-reload channel, enablement, and poll interval.
- [x] Refactor config swapping into a shared internal apply/reload helper guarded by `analyzerMu`.
- [x] Publish a config-updated event after successful `UpdateAnalysisConfig` and `ResetAnalysisConfig`.
- [x] Start a Redis subscription loop from `risk.NewService` when Redis and SQLite are both enabled.
- [x] Make the subscriber reconnect with bounded exponential backoff and interruptible shutdown.
- [x] Add a reconciliation ticker that re-reads SQLite and self-heals revision drift.
- [x] Ignore duplicate or self-originated revision events before touching SQLite.
- [x] Expose config revision and reload-source state through logs and, if low-cost, metrics/debug status.
- [x] Add tests for duplicate-event ignore, remote reload apply, missed-event reconciliation, and publish failure fail-open behavior.
- [x] Add a shutdown/backoff regression test so service stop does not hang during reconnect sleep.
- [x] Update deployment/runbook docs with new environment variables and multi-node operator notes.
- [x] Run `gofmt` and targeted tests for `internal/cache`, `internal/risk`, `cmd/core-api`, and `cmd/dns-resolver`.
