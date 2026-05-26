# Checklist: Triển khai Panic Recovery Middleware & Robustness Hardening

Dưới đây là danh sách các nhiệm vụ cụ thể đã được thực hiện để củng cố khả năng xử lý lỗi runtime nghiêm trọng và tăng tính chịu tải ổn định của hệ thống HTTP Server.

---

## 📅 Tiến độ thực hiện (Checklist)

- `[x]` **Bước 1: Thiết lập & Xây dựng Middleware phục hồi lỗi**
  - `[x]` Khai báo interface `MetricsObserver` tại `internal/serve/http.go` để ngắt kết nối phụ thuộc trực tiếp (circular dependency) với package `observability`.
  - `[x]` Phát triển middleware `serve.Recovery(next http.Handler, obs MetricsObserver) http.Handler` với cơ chế `recover()`, ghi log stack trace chi tiết, đồng bộ hóa metrics lỗi 500 và tự động phát hiện định dạng trả về (JSON lỗi hoặc HTML lỗi dựa trên Header `Accept`).

- `[x]` **Bước 2: Tích hợp Panic Recovery Middleware vào Core API**
  - `[x]` Cập nhật `cmd/core-api/main.go` để tích hợp `serve.Recovery` bọc quanh router chính, nằm ngay dưới middleware ghi log request `logRequests`.

- `[x]` **Bước 3: Tích hợp Panic Recovery Middleware vào DNS Resolver**
  - `[x]` Cập nhật `cmd/dns-resolver/main.go` để tích hợp `serve.Recovery` bọc quanh luồng xử lý HTTP (DoH).

- `[x]` **Bước 4: Phát triển bộ kiểm thử tự động (Automated Unit Tests)**
  - `[x]` Tạo tệp `internal/serve/http_test.go` chứa các ca kiểm thử:
    - Ca kiểm thử phục hồi lỗi JSON: Giả lập HTTP handler bị panic ngẫu nhiên và kiểm chứng API trả về JSON `{"error":"internal server error"}` kèm HTTP Status `500`.
    - Ca kiểm thử phục hồi lỗi HTML: Giả lập HTTP handler của Dashboard bị panic và kiểm chứng trả về mã HTML lỗi giao diện đẹp mắt (Glassmorphism).
    - Ca kiểm thử ghi nhận chỉ số (Metrics integration test): Xác minh observer nhận được cuộc gọi observe trạng thái `500` chính xác.

- `[x]` **Bước 5: Kiểm tra và Nghiệm thu toàn hệ thống**
  - `[x]` Chạy toàn bộ test suite với Race Detector: `go test -race ./...`.
  - `[x]` Biên dịch chạy thử nghiệm toàn bộ hệ thống: `go build ./...`.

- `[x]` **Bước 6: Đồng bộ Fix Double Metrics Observation**
  - `[x]` Cập nhật `logRequests` trong `cmd/core-api/main.go` và `cmd/dns-resolver/main.go` để tạo `panicObserved := false` và truyền con trỏ `*bool` qua context bằng `serve.ObservedPanicKey`.
  - `[x]` Cập nhật `serve.Recovery` để set `*panicObserved = true` sau khi observe lỗi 500, đảm bảo request panic chỉ được ghi metrics một lần.
