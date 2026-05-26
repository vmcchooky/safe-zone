# Checklist: Triển khai Hệ thống Cảnh báo nâng cao đa kênh (Telegram / Slack / Email) & Phát hiện giả mạo

Dưới đây là danh sách các nhiệm vụ cụ thể cần thực hiện để hoàn thành mục tiêu xây dựng và tích hợp hệ thống cảnh báo đa kênh nâng cao, làm nổi bật đe dọa giả mạo cơ quan nhà nước và ngân hàng Việt Nam.

---

## 📅 Tiến độ thực hiện (Checklist)

- `[x]` **Bước 1: Cấu hình Môi trường & Bổ sung Tham số**
  - `[x]` Cập nhật `.env.example` và tệp môi trường `.env` với các tham số cấu hình cho Telegram, Slack, và Email.

- `[x]` **Bước 2: Xây dựng module nhận diện giả mạo thương hiệu Việt Nam**
  - `[x]` Triển khai hàm helper `detectVietnamBrandSpoof(domain string)` trong `internal/agent/alert.go` để tự động phân tích và nhận dạng các website giả mạo Ngân hàng hoặc Cơ quan nhà nước Việt Nam, trích xuất tên miền chính thức.

- `[x]` **Bước 3: Phát triển các Kênh thông báo Nâng cao**
  - `[x]` Triển khai phương thức gửi tin nhắn Telegram `sendTelegram` (sử dụng định dạng HTML Glassmorphism/Modern cực đẹp).
  - `[x]` Triển khai phương thức gửi tin nhắn Slack `sendSlack` (sử dụng định dạng Markdown rõ ràng, emoji sinh động).
  - `[x]` Triển khai phương thức gửi email `sendEmail` qua SMTP tiêu chuẩn (`net/smtp` không phụ thuộc thư viện ngoài).

- `[x]` **Bước 4: Cập nhật AlertTask & Tích hợp Core API**
  - `[x]` Cập nhật hàm `Run` của `AlertTask` trong `internal/agent/alert.go` để tích hợp phát hiện đe dọa nghiêm trọng và phân phối tin nhắn đồng thời tới tất cả các kênh được kích hoạt.
  - `[x]` Cập nhật `cmd/core-api/main.go` để nạp đầy đủ các tham số cấu hình cảnh báo mới từ môi trường khi khởi tạo `AlertTask`.

- `[x]` **Bước 5: Phát triển Unit Test & Nghiệm thu**
  - `[x]` Viết unit test trong `internal/agent/alert_test.go` cho tính năng nhận diện giả mạo và mock các kênh cảnh báo.
  - `[x]` Chạy toàn bộ test suite để đảm bảo an toàn đa luồng: `go test -race ./...`.
  - `[x]` Biên dịch chạy thử nghiệm toàn bộ hệ thống: `go build ./...`.
