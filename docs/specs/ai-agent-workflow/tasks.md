# Tasks: AI Agent Workflow

Synced with repository state on 2026-05-26. Code-backed items are checked; the remaining open smoke test requires a live Agent cycle and recorded environment output.

## Milestone 1: Agent Engine

- [x] Thêm bảng `agent_audit_log` vào schema SQLite (`internal/store/sqlite.go`).
- [x] Thêm methods `RecordAgentEvent`, `QueryAgentEvents`, `QuerySuspiciousDomains` vào `store.DB`.
- [x] Viết tests cho các store methods mới.
- [x] Tạo package `internal/agent/engine.go` — Task interface, Engine struct, Register, Start, Stop, Trigger.
- [x] Viết `engine_test.go` — test lifecycle, scheduling, manual trigger, timeout, disabled skip.
- [x] Expose `StoreDB()`, `AIClient()`, `RedisCache()` trên `risk.Service`.
- [x] Thêm API routes `/v1/agent/status` và `POST /v1/agent/trigger` vào `cmd/core-api/main.go`.
- [x] Cập nhật `.env.example` với `SAFE_ZONE_AGENT_ENABLED` và env vars Engine.

## Milestone 2: Telemetry Audit Task

- [x] Tạo `internal/agent/audit.go` — AuditTask struct, implement Task interface.
- [x] Logic: query suspicious domains → check override → enrich (TLS+WHOIS) → AI refine (optional) → auto-block.
- [x] Viết `audit_test.go` — test full flow với in-memory SQLite, mock enrichment.
- [x] Cập nhật `.env.example` với env vars Audit (interval, timeout, min_occurrences, max_per_cycle, confidence_threshold).

## Milestone 3: Multi-Source Feed Sync Task

- [x] Tạo `internal/agent/feedsync.go` — FeedSyncTask struct, implement Task interface.
- [x] Logic: parse comma-separated sources → call `feed.Sync()` cho mỗi source → additive SADD → audit log.
- [x] Viết `feedsync_test.go` — test multi-source, partial failure, audit log recording.
- [x] Cập nhật `.env.example` với `SAFE_ZONE_AGENT_FEED_SOURCES` và env vars FeedSync.

## Milestone 4: Webhook Alert Task

- [x] Tạo `internal/agent/alert.go` — AlertTask struct, implement Task interface.
- [x] Logic: query recent agent events → build payload → detect Discord format → POST webhook.
- [x] Viết `alert_test.go` — test payload format, Discord detect, empty skip, HTTP errors.
- [x] Cập nhật `.env.example` với `SAFE_ZONE_AGENT_WEBHOOK_URL` và env vars Alert.

## Milestone 5: Dashboard Integration

- [x] Cập nhật `internal/api/views/dashboard.html` tab System: hiển thị Agent status, task list, trigger buttons.

## Milestone 6: Verification

- [x] `go build ./...` pass.
- [x] `go test ./...` pass.
- [x] `go test -race ./internal/agent/...` pass.
- [ ] Smoke test: bật Agent, chờ audit cycle, kiểm tra auto-block trong overrides.
- [x] Cập nhật README với Agent Workflow documentation.

## Completion Rule

Không thêm task mới ngoài danh sách này trừ khi có spec entry mới được tạo.
