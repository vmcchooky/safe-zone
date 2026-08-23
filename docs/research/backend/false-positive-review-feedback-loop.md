# Feedback loop cho false-positive review queue

- Ngày: 2026-08-23
- Trạng thái: Đã triển khai; local quality gates xanh, chờ CI của pull request
- Phạm vi: local development trước staging canary; không deploy, restart hoặc đổi traffic scope

## Tóm tắt (Abstract)

False-positive queue đã tồn tại nhưng chưa tạo được bằng chứng vận hành đủ tin cậy cho staging canary. API cho phép trạng thái tùy ý, không bắt buộc lý do, không lưu reviewer/thời điểm, để guest đọc dữ liệu contact/note và xử lý allow theo nhiều lần ghi độc lập. Thay đổi này bổ sung provenance cho quyết định, giới hạn queue cho admin và gộp allow override, report resolution cùng audit event vào một SQLite transaction.

## Mục tiêu (Objectives)

1. Biến mỗi report thành một decision record có `review_reason`, `reviewed_by`, `reviewed_at` và `resolution_action`.
2. Chỉ cho admin đọc hoặc xử lý queue vì contact/note có thể chứa dữ liệu cá nhân.
3. Ngăn trạng thái nửa vời khi allow override thành công nhưng report hoặc audit event thất bại.
4. Giữ tương thích với payload `/v1/overrides/review-false-positive` hiện hữu.
5. Cung cấp counter và lịch sử quyết định để đo feedback loop trong canary.

## Phương pháp và phương án thay thế (Methodology & Alternatives)

| Phương án | Ưu điểm | Hạn chế | Quyết định |
| --- | --- | --- | --- |
| Giữ nguyên endpoint, chỉ thêm modal nhập reason | Ít code | Vẫn có partial write và thiếu provenance ở DB | Không chọn |
| Tạo service/queue mới và message broker | Tách biệt, phù hợp quy mô lớn | Tăng hạ tầng trước khi có lưu lượng canary | Chưa cần ở giai đoạn này |
| Mở rộng schema SQLite và dùng transaction | Phù hợp kiến trúc local-first, rollback tự động, migration nhỏ | SQLite vẫn là single-writer; chưa có two-person approval | Chọn |
| Đổi contract cũ thành endpoint mới bắt buộc `report_id` | Contract rõ | Làm hỏng Analysis/legacy dashboard đang gọi payload cũ | Không chọn; thêm `report_id` tùy chọn |

Quy trình thực hiện gồm audit contract hiện hữu, thiết kế transaction boundary, migration tương thích DB cũ, cập nhật API/UI, sau đó kiểm tra quyền truy cập và các failure path. Không thay đổi signed evidence, model policy, runtime traffic hoặc staging scope.

## Chi tiết triển khai (Implementation Details)

### Dữ liệu và transaction

[SQLite store](../../../internal/store/sqlite.go) thêm bốn cột provenance với giá trị mặc định rỗng để database cũ có thể migrate tại startup. Intake report và `false_positive_report` event được ghi trong cùng transaction, kèm `report_id` để correlation. `ReviewBlockReport` ghi trạng thái và audit event trong cùng transaction. `ApproveFalsePositive` xác minh `report_id`/domain, upsert allow override, resolve các report pending cùng domain và ghi `operator_false_positive_review` trước khi commit.

### API và kiểm soát truy cập

[Reports handlers](../../../internal/api/handlers/reports.go) chỉ nhận decision `resolved` hoặc `rejected`, yêu cầu reason tối thiểu 8 ký tự, trả 404 khi ID không tồn tại và trả queue counters. [False-positive override handler](../../../internal/api/handlers/overrides.go) giữ nguyên các field cũ, bổ sung `report_id` tùy chọn và trả 409 nếu domain không khớp report. Route đọc report chuyển từ authenticated sang admin-only.

### Operator UI

[User Reports page](../../../ui/src/routes/UserReportsPage.tsx) hiển thị counter pending/resolved/rejected, mở dialog cho Allow/Resolve/Reject, bắt buộc reason và hiển thị provenance của quyết định cũ. [App routes](../../../ui/src/App.tsx) và [navigation shell](../../../ui/src/components/AppShell.tsx) ẩn queue với guest.

### Contract và runbook

[OpenAPI](../../openapi/safe-zone.yaml) mô tả queue APIs, decision schema và lỗi 404/409. [False-positive runbook](../../runbooks/false-positive-workflow.md) chuyển operator flow sang queue, nêu rõ transaction guarantee và bước xác minh audit.

### Vai trò AI agent

Codex (GPT-5) thực hiện audit code, thiết kế transaction, sửa backend/UI/docs và chạy quality gates trong một nhánh riêng. Không sử dụng subagent; số lượng subagent là 0. Human-in-the-loop vẫn chịu trách nhiệm phê duyệt pull request, quyết định staging canary và mọi hành động deploy/restart/enforce.

## Chỉ số và tiêu chí chấp nhận (Metrics)

| Chỉ số | Mục tiêu trước canary | Cách kiểm tra |
| --- | --- | --- |
| Pending report có decision provenance | 100% sau khi được xử lý | Query/API trả đủ reason, reviewer, time, action |
| Partial write khi allow | 0 | Transaction rollback khi report/domain không khớp hoặc audit insert lỗi |
| Guest đọc contact/note | 0 endpoint | Request guest tới `GET /v1/reports` nhận 403 |
| Status ngoài contract | 0 accepted | Chỉ `resolved` và `rejected` qua status endpoint |
| Queue-originated allow không khớp domain | 0 override được tạo | API trả 409 và report giữ `pending` |
| Automated verification | Backend targeted tests, UI typecheck/build và Playwright đều xanh | Test logs của branch/CI |

Các metric false-positive rate thực tế, decision latency và override aging cần thu từ staging canary; local tests chỉ xác minh contract và tính toàn vẹn dữ liệu.

Kết quả local ngày 2026-08-23:

- `go test ./...` và `go build ./...`: pass.
- `golangci-lint v2.12.2`: 0 issue.
- UI typecheck/build: pass; Vite chỉ còn cảnh báo chunk size hiện hữu, không chặn build.
- Playwright Chromium: 5/5 test pass, gồm flow intake → queue → reason → allow.
- gosec v2.28.0: 0 issue; govulncheck v1.4.0: không có vulnerability reachable.
- OpenAPI YAML: parse thành công.

## Giới hạn và bước tiếp theo

- Queue vẫn dùng global allow override; chưa có TTL hoặc scope theo client group.
- Reason là free text; chưa bắt buộc ticket ID có cấu trúc.
- Chưa có two-person approval cho domain nhạy cảm.
- Trước canary cần định nghĩa SLO cho pending age, decision latency, rollback drill và cách xuất feedback đã ẩn PII cho pipeline huấn luyện/evaluation.

## Lịch sử thay đổi (Version History)

| Ngày | Phiên bản | Thay đổi | Tác giả |
| --- | --- | --- | --- |
| 2026-08-23 | 1.0 | Thiết kế và triển khai feedback loop có provenance, admin-only access và atomic allow decision | Codex (GPT-5) |
