# Requirements: AI Agent Workflow

## Goal

Biến Safe Zone từ một hệ thống phân tích **phản ứng thụ động** (chỉ phân tích khi có request đến) thành một hệ thống **chủ động tự vận hành** (Autonomous), có khả năng tự quét, tự làm giàu dữ liệu, tự ra quyết định chặn, và tự thông báo — tất cả chạy nền mà không cần sự can thiệp thủ công của quản trị viên.

## Nguyên tắc thiết kế

- **Zero-Cost-First:** Mọi Agent task đều hoạt động đầy đủ mà không cần API Key trả phí. Gemini AI là lớp bổ sung tùy chọn (Free Tier 1,500 req/ngày đủ dùng).
- **Fail-Open:** Nếu bất kỳ Agent task nào lỗi (mất mạng, Redis chết, AI timeout), hệ thống lõi vẫn hoạt động bình thường.
- **Tái sử dụng tối đa:** Agent sử dụng lại các module đã có (`internal/feed`, `internal/risk`, `internal/store`, `internal/ai`, `internal/tlsinspect`, `internal/whois`) thay vì viết lại.
- **Giám sát được:** Mọi Agent task phải ghi log rõ ràng, có metrics theo dõi, và có thể kiểm tra trạng thái qua API.

## Milestones

### Milestone 1: Agent Engine — Bộ lập lịch & Quản lý Task

- Agent Engine là một goroutine scheduler chạy trong tiến trình `core-api` (không thêm binary mới).
- Hỗ trợ đăng ký nhiều Agent Task, mỗi task có interval riêng.
- Mỗi task có trạng thái: `idle`, `running`, `failed`, `disabled`.
- Task chạy tuần tự (không cần đồng thời giữa các task) để tránh tranh chấp tài nguyên trên VPS cấu hình thấp.
- Có thể bật/tắt từng task bằng biến môi trường.
- Expose trạng thái qua API `/v1/agent/status` để Dashboard hiển thị.

### Milestone 2: Telemetry Audit Task

- Quét bảng `analysis_log` trong SQLite để tìm domain đáng chú ý:
  - Domain có verdict `SUSPICIOUS` xuất hiện >= N lần trong chu kỳ (configurable, mặc định 3).
  - Domain có verdict `SUSPICIOUS` mà chưa từng được enrich (không có reason chứa "tls:" hoặc "whois:").
- Với mỗi domain tìm được, chạy pipeline enrichment đầy đủ: TLS Inspect + WHOIS Lookup + AI Refine (nếu có key).
- Nếu kết quả sau enrichment là `MALICIOUS` với confidence >= threshold (mặc định 0.7):
  - Tự động ghi Override `block` vào SQLite với reason `agent: auto-block (enriched)`.
  - Xóa cache Redis của domain đó (buộc re-evaluate lần query kế tiếp).
- Ghi kết quả audit vào bảng `agent_audit_log` mới trong SQLite.

### Milestone 3: Multi-Source Threat Feed Sync Task

- Mở rộng feed sync hiện có để hỗ trợ **nhiều nguồn** (multi-source):
  - Danh sách nguồn feed cấu hình qua env var `SAFE_ZONE_AGENT_FEED_SOURCES` (comma-separated URLs).
  - Mặc định bao gồm các nguồn miễn phí: PhishTank (CSV), URLhaus (TXT), OpenPhish (TXT).
- Tái sử dụng `internal/feed.Sync()` cho mỗi nguồn.
- Hợp nhất kết quả vào Redis Set `safe-zone:threat:feed` (additive, không replace giữa các nguồn).
- Ghi báo cáo sync vào `agent_audit_log`.

### Milestone 4: Alert / Notification Task

- Quét `agent_audit_log` để tìm các sự kiện quan trọng:
  - Auto-block mới được tạo.
  - Feed sync thất bại.
  - Số domain malicious phát hiện mới vượt ngưỡng trong chu kỳ.
- Gửi thông báo qua **Webhook** (Discord/Slack/Telegram/Generic HTTP POST):
  - Cấu hình webhook URL qua `SAFE_ZONE_AGENT_WEBHOOK_URL`.
  - Payload JSON chuẩn hoá, dễ parse bởi bot bên ngoài.
- Nếu không có webhook URL, chỉ ghi log (fail-open).

## Functional Requirements

### Engine

- Agent Engine khởi động cùng `core-api` nếu `SAFE_ZONE_AGENT_ENABLED=true`.
- Mỗi task có interval cấu hình riêng (mặc định: Audit=1h, FeedSync=24h, Alert=15m).
- Task không chạy đồng thời: nếu task trước chưa xong, task tiếp theo chờ.
- Mỗi task có timeout riêng (mặc định: Audit=5m, FeedSync=2m, Alert=30s).
- API `/v1/agent/status` trả về JSON danh sách task kèm trạng thái, lần chạy gần nhất, lần chạy tiếp theo, số lỗi.
- API `POST /v1/agent/trigger?task=<name>` cho phép trigger thủ công một task ngoài lịch (Admin tooling).

### Telemetry Audit

- Chỉ audit domain có verdict `SUSPICIOUS` (không audit `SAFE` hoặc `MALICIOUS` đã rõ ràng).
- Ngưỡng auto-block: confidence >= 0.7 VÀ verdict MALICIOUS sau enrichment.
- Override tự động có reason bắt đầu bằng `agent:` để phân biệt với override thủ công.
- Domain đã có override (dù allow hay block) sẽ bị skip (không ghi đè ý định Admin).
- Giới hạn số domain audit mỗi chu kỳ (mặc định: 50) để kiểm soát tài nguyên.

### Multi-Source Feed Sync

- Mỗi nguồn được sync độc lập; nếu 1 nguồn lỗi, các nguồn khác vẫn tiếp tục.
- Không xóa Redis Set trước khi sync (additive mode) — chỉ thêm, không mất dữ liệu cũ.
- Ghi log chi tiết cho mỗi nguồn: valid/invalid/duplicate counts.

### Alerting

- Payload webhook bao gồm: timestamp, event_type, summary, details (array of affected domains).
- Hỗ trợ Discord format tự động nếu URL chứa `discord.com/api/webhooks`.
- Rate limit webhook: tối đa 1 alert/phút để tránh spam.

## Non-Functional Requirements

- Không thêm binary mới (Agent chạy trong `core-api`).
- Không thêm dependency mới ngoài standard library và các dependency đã có.
- Không yêu cầu Redis bắt buộc cho Agent (audit task chỉ cần SQLite).
- Không yêu cầu API Key bắt buộc (Gemini optional, heuristics-only mode hoạt động đầy đủ).
- Tất cả interval/threshold có thể cấu hình qua env var.
- Agent task sử dụng `context.Context` với timeout để tránh goroutine leak.
- Memory footprint thấp: Agent không load toàn bộ audit log vào RAM, sử dụng SQL LIMIT.

## Acceptance Criteria

- `SAFE_ZONE_AGENT_ENABLED=true` → Agent Engine khởi động cùng core-api, tasks chạy theo lịch.
- `SAFE_ZONE_AGENT_ENABLED=false` (hoặc không set) → core-api hoạt động bình thường không có Agent.
- Audit task tìm được domain suspicious, enrich, và auto-block nếu vượt ngưỡng.
- Feed sync task tải được nhiều nguồn, ghi vào Redis, ghi audit log.
- Alert task gửi được webhook khi có sự kiện mới.
- `GET /v1/agent/status` trả về JSON trạng thái tất cả task.
- `POST /v1/agent/trigger?task=audit` trigger thủ công thành công.
- Agent disabled → `GET /v1/agent/status` trả về `{"enabled": false}`.
- `go test ./...` pass.
- `go build ./...` pass.
