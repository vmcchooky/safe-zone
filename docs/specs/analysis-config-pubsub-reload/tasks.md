# Tasks: Redis Pub/Sub Analysis Config Reload

- [x] Write requirements for multi-node analysis-config reload and Redis Pub/Sub behavior.
- [x] Write design for `risk.Service` subscriber, reconciliation loop, and Redis channel contract.
- [ ] Add Redis Pub/Sub helpers to `internal/cache/redis.go`.
- [ ] Extend `risk.Options` and `risk.Service` with config-reload channel, enablement, and poll interval.
- [ ] Refactor config swapping into a shared internal apply/reload helper guarded by `analyzerMu`.
- [ ] Publish a config-updated event after successful `UpdateAnalysisConfig` and `ResetAnalysisConfig`.
- [ ] Start a Redis subscription loop from `risk.NewService` when Redis and SQLite are both enabled.
- [ ] Make the subscriber reconnect with bounded exponential backoff and interruptible shutdown.
- [ ] Add a reconciliation ticker that re-reads SQLite and self-heals revision drift.
- [ ] Ignore duplicate or self-originated revision events before touching SQLite.
- [ ] Expose config revision and reload-source state through logs and, if low-cost, metrics/debug status.
- [ ] Add tests for duplicate-event ignore, remote reload apply, missed-event reconciliation, and publish failure fail-open behavior.
- [ ] Add a shutdown/backoff regression test so service stop does not hang during reconnect sleep.
- [ ] Update deployment/runbook docs with new environment variables and multi-node operator notes.
- [ ] Run `gofmt` and targeted tests for `internal/cache`, `internal/risk`, `cmd/core-api`, and `cmd/dns-resolver`.
