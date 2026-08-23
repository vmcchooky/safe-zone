# Policy Manual Trigger cho Agent Engine

> **Tài liệu Living Document** — Cập nhật đồng bộ mỗi khi có thay đổi.
> Tuân thủ quy tắc tại `.agents/AGENTS.md` Section 5.

## Tóm tắt (Abstract)

Agent Engine phân biệt trạng thái task được đăng ký với trạng thái task được phép chạy theo lịch. Trước thay đổi này, manual trigger có thể enqueue một task đang `enabled=false`, khiến API admin vượt qua safety boundary của scheduler. Policy mới áp dụng cùng điều kiện enablement cho scheduled run và manual trigger: task disabled bị từ chối bằng HTTP `409 Conflict`. Engine trả kết quả có kiểu cho bốn trạng thái `accepted`, `task_not_found`, `task_disabled` và `queue_full`; API ánh xạ queue đầy sang HTTP `429 Too Many Requests`. Thay đổi không bổ sung cơ chế `force`, không tự sửa env/config và không thực thi task khi chỉ kiểm tra policy. Kiểm thử package-level xác nhận hai package liên quan pass sau khi triển khai.

## Policy Manual Trigger

### Mục tiêu (Objectives)

Mục tiêu là loại bỏ khả năng admin endpoint chạy task đã bị operator tắt, đồng thời bảo đảm response thành công chỉ được trả khi yêu cầu thực sự vào trigger queue. Contract phải giữ nguyên các nhánh đã có cho engine disabled, thiếu tên task và task không tồn tại. Policy được thực thi tại `internal/agent` để mọi caller hiện tại hoặc tương lai đều nhận cùng safety behavior, thay vì chỉ kiểm tra tại HTTP handler.

### Phương pháp & Lý do (Methodology & Rationale)

| Quyết định | Phương pháp chọn | Các phương pháp thay thế | Lý do |
|---|---|---|---|
| Task disabled | Từ chối tại engine và trả `task_disabled` | Cho admin chạy; thêm `force=true`; chỉ chặn tại handler | Task disabled thường phản ánh thiếu source, channel hoặc phê duyệt vận hành. Chặn tại engine giữ một policy cho mọi caller và tránh endpoint vô tình vượt cấu hình. |
| HTTP status | `409 Conflict` | `403 Forbidden`; `400 Bad Request`; `423 Locked` | Admin đã qua authorization và request hợp lệ, nhưng trạng thái cấu hình của task xung đột với thao tác được yêu cầu. |
| Queue đầy | Trả `queue_full`, ánh xạ HTTP `429` | Im lặng bỏ trigger; block handler; queue không giới hạn | `429` biểu thị backpressure, không giữ request thread và không tăng bộ nhớ không giới hạn. |
| Kiểu kết quả | `TriggerResult` dạng enum chuỗi | `bool`; sentinel error; struct nhiều field | `bool` không phân biệt not-found, disabled và queue-full. Enum giữ contract nhỏ, có thể kiểm thử bằng equality và không đưa lỗi nội bộ vào response. |
| Force override | Không hỗ trợ | `force=true` cho admin | Force path làm yếu kill switch cấu hình và đòi hỏi audit/approval riêng. Việc bật task phải đi qua config lifecycle hiện hành. |

### Cách thức Thực hiện (Implementation Details)

`internal/agent/engine.go` định nghĩa `TriggerResult` và kiểm tra `registeredTask.enabled` trước thao tác enqueue. Queue non-blocking chỉ trả `accepted` khi phép gửi vào channel thành công; nhánh `default` trả `queue_full`. `internal/api/handlers/agent.go` ánh xạ kết quả sang HTTP `200`, `404`, `409` hoặc `429`, trong khi các điều kiện method, engine và query parameter tiếp tục trả mã cũ.

`internal/agent/engine_test.go` kiểm tra trực tiếp policy ở engine, gồm disabled task không chạy và bounded queue báo đầy. `internal/api/handlers/agent_test.go` dùng table-driven test cho method sai, engine disabled, thiếu task, unknown task, disabled task, enabled task và queue đầy. Các test không khởi động service, không truy cập network ngoài process và không tạo external side effect.

AI agent sử dụng Codex GPT-5 với chiến lược đọc contract hiện hữu, thu hẹp thay đổi tại engine/API boundary, viết table-driven tests rồi chạy quality gates. Không sử dụng subagent; số lượng subagent là 0. Người dùng phê duyệt triển khai policy, còn kiểm soát chất lượng dựa trên review diff và test suite tự động.

### Số liệu (Metrics & Results)

| Chỉ số | Kết quả |
|---|---:|
| Trạng thái `TriggerResult` | 4 |
| Nhánh HTTP trong table-driven policy test | 7 |
| Engine policy tests bổ sung | 2 |
| Package Go kiểm thử trực tiếp | 2/2 pass |
| Package Go chạy race detector | 2/2 pass |
| Full Go test/build/vet | Pass |
| `golangci-lint` | 0 issue |
| `gosec` | 0 issue trên 87 file |
| `govulncheck` reachable vulnerability | 0 |
| Playwright UI regression | 4/4 pass |
| External network call trong test mới | 0 |
| Thay đổi env/config runtime | 0 |

Lệnh kiểm thử trực tiếp:

```powershell
go test ./internal/agent ./internal/api/handlers
go test -race ./internal/agent ./internal/api/handlers
go test ./...
go build ./...
go vet ./...
```

Kết quả targeted ban đầu: `safe-zone/internal/agent` pass trong 8,579 giây và `safe-zone/internal/api/handlers` pass trong 4,722 giây trên Windows local. Race detector sau đó pass lần lượt trong 7,536 giây và 7,118 giây. Máy local không có executable `mise` trong `PATH`, nên các dependency của `mise run ci` được chạy trực tiếp theo `mise.toml`: UI bundle/typecheck/build pass, Go test/build pass, Playwright pass 4/4, lint báo 0 issue, `gosec` báo 0 issue trên 87 file và `govulncheck` báo 0 reachable vulnerability. Lượt Go test đầu chạy song song với Playwright gặp lỗi setup do Playwright đang thay đổi `ui/test-results`; chạy lại tuần tự sau khi Playwright kết thúc đã pass.

### Liên kết Artifacts

- `internal/agent/engine.go`
- `internal/agent/engine_test.go`
- `internal/api/handlers/agent.go`
- `internal/api/handlers/agent_test.go`
- `docs/specs/safe-zone-ai-plan.md`
- `docs/production-completion-checklist.md`

---

## Lịch sử Thay đổi (Version History)

| Ngày | Thay đổi | Tác giả |
|---|---|---|
| 2026-08-23 | Chốt policy fail-closed cho manual trigger và bổ sung engine/API tests | Codex GPT-5 |
