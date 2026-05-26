# Design: AI Agent Workflow

## Overview

AI Agent Workflow là một hệ thống autonomous chạy nền bên trong tiến trình `core-api`, gồm 3 thành phần chính:

```
┌─────────────────────────────────────────────────────────────────┐
│                       core-api process                          │
│                                                                 │
│  ┌──────────┐   ┌──────────────────────────────────────────┐    │
│  │ HTTP Mux │   │          Agent Engine (goroutine)         │    │
│  │          │   │                                          │    │
│  │ /v1/...  │   │  ┌─────────┐ ┌──────────┐ ┌───────────┐ │    │
│  │ /agent/* │──▶│  │  Audit  │ │FeedSync  │ │  Alert    │ │    │
│  │          │   │  │  Task   │ │  Task    │ │  Task     │ │    │
│  └──────────┘   │  └────┬────┘ └────┬─────┘ └─────┬─────┘ │    │
│                 │       │           │              │        │    │
│                 └───────┼───────────┼──────────────┼────────┘    │
│                         ▼           ▼              ▼             │
│                 ┌───────────┐ ┌──────────┐ ┌────────────────┐   │
│                 │  SQLite   │ │  Redis   │ │ Webhook (HTTP) │   │
│                 │ store.DB  │ │ cache.R  │ │   (optional)   │   │
│                 └───────────┘ └──────────┘ └────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Package Structure

```
internal/
  agent/
    engine.go          # Scheduler, TaskRegistry, run loop
    engine_test.go     # Unit tests cho Engine
    audit.go           # Telemetry Audit Task
    audit_test.go      # Unit tests cho Audit
    feedsync.go        # Multi-source Feed Sync Task
    feedsync_test.go   # Unit tests cho FeedSync
    alert.go           # Webhook Alert Task
    alert_test.go      # Unit tests cho Alert
```

## 1. Agent Engine (`engine.go`)

### Core Types

```go
// TaskStatus tracks the runtime state of a registered task.
type TaskStatus struct {
    Name        string    `json:"name"`
    Enabled     bool      `json:"enabled"`
    State       string    `json:"state"`       // "idle", "running", "failed"
    Interval    string    `json:"interval"`     // human-readable, e.g. "1h"
    LastRun     string    `json:"last_run"`     // RFC3339 or ""
    NextRun     string    `json:"next_run"`     // RFC3339 or ""
    LastError   string    `json:"last_error"`   // empty if last run succeeded
    RunCount    int64     `json:"run_count"`
    ErrorCount  int64     `json:"error_count"`
}

// Task is the interface every agent task must implement.
type Task interface {
    Name() string
    Run(ctx context.Context) error
}

// Engine is the central scheduler that manages and runs Tasks.
type Engine struct {
    mu          sync.Mutex
    tasks       []registeredTask   // ordered list of tasks
    statusMap   map[string]*TaskStatus
    triggerCh   chan string         // manual trigger channel
    done        chan struct{}
    wg          sync.WaitGroup
}

type registeredTask struct {
    task     Task
    interval time.Duration
    timeout  time.Duration
    enabled  bool
}
```

### Lifecycle

1. **Khởi tạo:** `NewEngine()` tạo Engine trống.
2. **Đăng ký:** `engine.Register(task, interval, timeout, enabled)` thêm task vào registry.
3. **Chạy:** `engine.Start()` khởi động goroutine scheduler.
4. **Dừng:** `engine.Stop()` gửi tín hiệu dừng và chờ goroutine thoát.

### Scheduler Loop

```
┌──────────────────────────────────────────────────┐
│ for each registered task (sequential):           │
│   if !enabled → skip                             │
│   if time.Since(lastRun) < interval → skip       │
│   set state = "running"                          │
│   ctx, cancel = context.WithTimeout(timeout)     │
│   err = task.Run(ctx)                            │
│   cancel()                                       │
│   if err → state = "failed", log error           │
│   else   → state = "idle"                        │
│   update lastRun, nextRun, runCount, errorCount  │
│                                                  │
│ select:                                          │
│   case <-triggerCh:  → run specified task now     │
│   case <-ticker.C:   → check all tasks           │
│   case <-done:       → return                    │
└──────────────────────────────────────────────────┘
```

- Tick interval: **30 giây** (kiểm tra xem task nào đến lượt).
- Tasks chạy **tuần tự** trong 1 goroutine (tránh tranh chấp trên VPS 2 vCPU).

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/agent/status` | Trả về `{"enabled": bool, "tasks": [TaskStatus...]}` |
| `POST` | `/v1/agent/trigger?task=<name>` | Trigger task chạy ngay, trả về `{"triggered": "<name>"}` |

## 2. Telemetry Audit Task (`audit.go`)

### Dependencies

- `*store.DB` — đọc `analysis_log`, đọc/ghi `local_overrides`, ghi `agent_audit_log`.
- `*ai.Client` — (optional) AI refinement cho domain nghi ngờ.
- `*cache.Redis` — (optional) xóa cache của domain bị auto-block.
- TLS/WHOIS module — enrichment trực tiếp.

### Flow

```
1. Query SQLite: SELECT domain, COUNT(*) as cnt
                 FROM analysis_log
                 WHERE verdict = 'SUSPICIOUS'
                   AND analyzed_at >= ?  (since last audit run)
                 GROUP BY domain
                 HAVING cnt >= ?  (min_occurrences threshold)
                 ORDER BY cnt DESC
                 LIMIT ?  (max_audit_per_cycle)

2. For each domain:
   a. Check if domain already has an override → skip if yes.
   b. Run TLS Inspect → collect score + reasons.
   c. Run WHOIS Lookup → collect score + reasons.
   d. Merge scores with original lexical score.
   e. If AI client enabled AND merged score in [40, 85]:
      → Run AI Refine for final verdict.
   f. Determine final verdict + confidence.
   g. If verdict == MALICIOUS && confidence >= threshold:
      → UpsertOverride(domain, "block", "agent: auto-block (enriched)")
      → Delete Redis cache key for domain.
      → Record event in agent_audit_log.
   h. Else:
      → Record "reviewed, no action" in agent_audit_log.

3. Return summary: audited count, auto-blocked count, skipped count, errors.
```

### SQLite Schema Addition

```sql
CREATE TABLE IF NOT EXISTS agent_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_name TEXT NOT NULL,            -- 'audit', 'feedsync', 'alert'
    event_type TEXT NOT NULL,           -- 'auto_block', 'reviewed', 'feed_synced',
                                       --   'feed_error', 'alert_sent', 'alert_failed'
    domain TEXT,                        -- nullable, chỉ có cho audit events
    details TEXT,                       -- JSON chi tiết
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_task ON agent_audit_log(task_name);
CREATE INDEX IF NOT EXISTS idx_audit_created ON agent_audit_log(created_at);
```

### Config

| Env Var | Default | Description |
|---------|---------|-------------|
| `SAFE_ZONE_AGENT_AUDIT_INTERVAL_SECONDS` | `3600` (1h) | Chu kỳ chạy audit |
| `SAFE_ZONE_AGENT_AUDIT_TIMEOUT_SECONDS` | `300` (5m) | Timeout mỗi lần chạy |
| `SAFE_ZONE_AGENT_AUDIT_MIN_OCCURRENCES` | `3` | Số lần xuất hiện tối thiểu |
| `SAFE_ZONE_AGENT_AUDIT_MAX_PER_CYCLE` | `50` | Giới hạn domain/chu kỳ |
| `SAFE_ZONE_AGENT_AUDIT_CONFIDENCE_THRESHOLD` | `0.7` | Ngưỡng confidence auto-block |

## 3. Multi-Source Feed Sync Task (`feedsync.go`)

### Dependencies

- `internal/feed.Sync()` — tái sử dụng hoàn toàn logic sync đã có.
- `*store.DB` — ghi audit log.

### Flow

```
1. Parse SAFE_ZONE_AGENT_FEED_SOURCES → []string URLs.
2. For each source URL:
   a. Call feed.Sync() with DryRun=false, Replace=false (additive).
   b. If error → log, record in agent_audit_log, continue next source.
   c. If success → record SyncReport in agent_audit_log.
3. Return summary: sources_total, sources_ok, sources_failed, domains_added.
```

### Config

| Env Var | Default | Description |
|---------|---------|-------------|
| `SAFE_ZONE_AGENT_FEED_SOURCES` | `""` | Comma-separated feed URLs |
| `SAFE_ZONE_AGENT_FEED_INTERVAL_SECONDS` | `86400` (24h) | Chu kỳ sync |
| `SAFE_ZONE_AGENT_FEED_TIMEOUT_SECONDS` | `120` (2m) | Timeout mỗi lần sync |

### Tích hợp với feed-syncd hiện có

- `cmd/feed-syncd` vẫn tồn tại và hoạt động với **1 nguồn** duy nhất (`-source`).
- Agent Feed Sync Task hỗ trợ **nhiều nguồn** và chạy trong `core-api`.
- Hai cơ chế có thể cùng tồn tại: `feed-syncd` cho backward-compat, Agent cho multi-source.
- Nếu cùng chạy cả hai, kết quả là additive (SADD vào Redis Set).

## 4. Webhook Alert Task (`alert.go`)

### Dependencies

- `*store.DB` — đọc `agent_audit_log` để tìm events chưa gửi alert.
- `net/http` — gửi HTTP POST webhook.

### Flow

```
1. Query agent_audit_log:
   SELECT * FROM agent_audit_log
   WHERE created_at > ?  (since last alert run)
     AND event_type IN ('auto_block', 'feed_error')
   ORDER BY created_at ASC

2. If no events → return (nothing to alert).

3. Build payload:
   {
     "timestamp": "...",
     "event_type": "safe_zone_agent_alert",
     "summary": "Safe Zone: 3 domains auto-blocked, 1 feed sync error",
     "events": [
       {"type": "auto_block", "domain": "evil.com", "time": "..."},
       ...
     ]
   }

4. If webhook URL contains "discord.com/api/webhooks":
   → Wrap payload in Discord embed format.

5. POST to webhook URL with Content-Type: application/json.
   → Timeout: 10 seconds.
   → If error → log, record alert_failed in audit_log.
   → If success → record alert_sent in audit_log.
```

### Config

| Env Var | Default | Description |
|---------|---------|-------------|
| `SAFE_ZONE_AGENT_WEBHOOK_URL` | `""` | Webhook URL (empty = disabled) |
| `SAFE_ZONE_AGENT_ALERT_INTERVAL_SECONDS` | `900` (15m) | Chu kỳ check & gửi alert |
| `SAFE_ZONE_AGENT_ALERT_TIMEOUT_SECONDS` | `30` | Timeout gửi webhook |
| `SAFE_ZONE_AGENT_ALERT_MIN_EVENTS` | `1` | Số events tối thiểu để trigger |

## 5. Tích hợp vào `cmd/core-api/main.go`

```go
// In main():
if config.Bool("SAFE_ZONE_AGENT_ENABLED", false) {
    agentEngine := agent.NewEngine()

    auditTask := agent.NewAuditTask(riskService.Store(), riskService.AI(), riskService.Redis())
    agentEngine.Register(auditTask, auditInterval, auditTimeout, auditEnabled)

    feedTask := agent.NewFeedSyncTask(feedSources, redisAddr, redisPassword, redisDB)
    agentEngine.Register(feedTask, feedInterval, feedTimeout, feedEnabled)

    alertTask := agent.NewAlertTask(riskService.Store(), webhookURL)
    agentEngine.Register(alertTask, alertInterval, alertTimeout, alertEnabled)

    agentEngine.Start()
    defer agentEngine.Stop()

    // Register API handlers
    mux.HandleFunc("GET /v1/agent/status", agentStatusHandler(agentEngine))
    mux.HandleFunc("POST /v1/agent/trigger", agentTriggerHandler(agentEngine))
}
```

## 6. Store Package Changes

### New Methods on `store.DB`

```go
// RecordAgentEvent writes an entry to agent_audit_log.
func (d *DB) RecordAgentEvent(taskName, eventType, domain, details string) error

// QueryAgentEvents returns agent events since a given time.
func (d *DB) QueryAgentEvents(since time.Time, eventTypes []string, limit int) ([]AgentEvent, error)

// QuerySuspiciousDomains returns frequently-seen suspicious domains for audit.
func (d *DB) QuerySuspiciousDomains(since time.Time, minOccurrences, limit int) ([]DomainCount, error)
```

### New Types

```go
type AgentEvent struct {
    ID        int64  `json:"id"`
    TaskName  string `json:"task_name"`
    EventType string `json:"event_type"`
    Domain    string `json:"domain,omitempty"`
    Details   string `json:"details"`
    CreatedAt string `json:"created_at"`
}

type DomainCount struct {
    Domain string `json:"domain"`
    Count  int    `json:"count"`
}
```

## 7. Risk Service Changes

Expose internal dependencies cho Agent:

```go
// New methods on risk.Service:
func (s *Service) StoreDB() *store.DB     { return s.store }
func (s *Service) AIClient() *ai.Client    { return s.ai }
func (s *Service) RedisCache() *cache.Redis { return s.redis }
```

## 8. Dashboard Integration

Tab "System" trong Dashboard sẽ hiển thị thêm:
- Agent Engine status (enabled/disabled).
- Mỗi task: tên, trạng thái, lần chạy cuối, lần chạy kế, số lỗi.
- Nút "Trigger Now" cho mỗi task.

Dữ liệu lấy từ `GET /v1/agent/status`.

## Testing Strategy

- **Engine:** Test register, start/stop, manual trigger, timeout handling, disabled task skip.
- **Audit:** Test với SQLite in-memory + mock data. Test skip override, auto-block threshold, limit per cycle.
- **FeedSync:** Test multi-source parsing, partial failure recovery (1 source fail, others ok).
- **Alert:** Test webhook payload format, Discord format detection, empty event skip, HTTP error handling.
- Tất cả test không yêu cầu network (mock HTTP servers, in-memory SQLite).
