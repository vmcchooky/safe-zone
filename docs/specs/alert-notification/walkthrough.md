# Tài liệu Nghiệm thu (Walkthrough): Hệ thống Cảnh báo nâng cao đa kênh (Telegram / Slack / Email) & Phát hiện giả mạo

Tài liệu này tổng hợp kết quả thiết kế, phát triển thực tế, kiểm thử tự động của hệ thống Cảnh báo nâng cao đa kênh (Telegram / Slack / Email) nhằm phát hiện và cảnh báo trực quan các hành vi giả mạo ngân hàng hoặc cơ quan nhà nước Việt Nam cho dự án Safe Zone.

---

## 1. Các thay đổi đã thực hiện (Implemented Changes)

### 1.1. Cấu hình Môi trường
*   **[.env.example](file:///D:/Quorix/services/safe-zone/.env.example)** & **.env**:
    *   Bổ sung đầy đủ các tham số cấu hình cảnh báo cho Telegram Bot, Slack Webhook và Email SMTP.
    *   Cung cấp giá trị mặc định trực quan, tài liệu hóa cách lấy token và chat ID.

### 1.2. Logic Cảnh báo & Phát hiện giả mạo Việt Nam
*   **[internal/agent/alert.go](file:///D:/Quorix/services/safe-zone/internal/agent/alert.go)**:
    *   **Cấu hình**: Mở rộng `AlertConfig` để tích hợp toàn bộ các cấu hình Telegram, Slack, Email (SMTP).
    *   **Hàm phát hiện giả mạo (`detectVietnamBrandSpoof`)**:
        *   Tự động so khớp lý do phát hiện giả mạo với danh sách thương hiệu Nhà nước (`chinhphu`, `bocongan`, `baohiemxahoi`, `vtv`) và các ngân hàng lớn của Việt Nam (`vietcombank`, `techcombank`, `bidv`, `vietinbank`, `mbbank`, `agribank`, `vpbank`, `acb`, `sacombank`, `tpbank`, `vib`, `hdbank`, `shb`, `scb`).
        *   Trả về đầy đủ thông tin chi tiết bao gồm thương hiệu bị mạo danh, tên miền chính thức, phân loại, lý do vi phạm.
    *   **Gửi tin nhắn Telegram (`sendTelegram`)**:
        *   Gửi tin nhắn bất đồng bộ qua Goroutines.
        *   Sử dụng định dạng HTML, làm nổi bật thông báo bằng nhãn `⚠️ [CẢNH BÁO ĐE DỌA NGHIÊM TRỌNG] ⚠️`, có emoji, chia dòng và hiển thị link tên miền chính chủ sạch đẹp.
    *   **Gửi tin nhắn Slack (`sendSlack`)**:
        *   Gửi tin nhắn định dạng Markdown phong phú, cung cấp đầy đủ thông tin chi tiết về đe dọa giả mạo trực quan.
    *   **Gửi Email SMTP (`sendEmail`)**:
        *   Sử dụng gói `net/smtp` tiêu chuẩn của Go để không phụ thuộc vào thư viện bên ngoài.
        *   Thiết kế giao diện email HTML Glassmorphism cao cấp, kết hợp gradient đỏ-cam, viền sắc nét, các box màu xám nổi bật để hiển thị chi tiết tên miền giả mạo và liên kết chính thức.
    *   **Hàm chạy định kỳ (`Run`)**:
        *   Đồng thời lọc qua tất cả sự kiện `auto_block` và nhận dạng thương hiệu Việt Nam bị spoof.
        *   Bắn cảnh báo tới các kênh được bật song song.

### 1.3. Khởi tạo & Cấu hình Core API
*   **[cmd/core-api/main.go](file:///D:/Quorix/services/safe-zone/cmd/core-api/main.go)**:
    *   Đọc và chuyển đổi cấu hình từ môi trường (`SAFE_ZONE_ALERT_TELEGRAM_ENABLED`, v.v.).
    *   Đăng ký `AlertTask` vào `agentEngine` với chu kỳ quét mặc định 15 phút.

### 1.4. Bộ kiểm thử tự động
*   **[internal/agent/alert_test.go](file:///D:/Quorix/services/safe-zone/internal/agent/alert_test.go)**:
    *   Bổ sung test case `TestDetectVietnamBrandSpoof` kiểm tra nhận dạng chuẩn xác ngân hàng (`vietcombbank.com.vn` -> `vietcombank`) và cơ quan nhà nước (`chinhphuu.vn` -> `chinhphu`).
    *   Bổ sung test case `TestAlertTaskAdvancedChannels` kiểm tra cơ chế gửi tin nhắn đa luồng tới Telegram và Slack, mock HTTP client an toàn và kiểm chứng nội dung payload gửi đi chính xác.

---

## 2. Kết quả Kiểm nghiệm (Verification Results)

### 2.1. Chạy Kiểm thử Unit Test
Toàn bộ hệ thống kiểm thử chạy với Race Detector (`-race`) đã vượt qua thành công:
```bash
go test -race -v ./internal/agent/...
```

**Log chạy thành công:**
```text
=== RUN   TestAlertTaskName
--- PASS: TestAlertTaskName (0.00s)
...
=== RUN   TestDetectVietnamBrandSpoof
--- PASS: TestDetectVietnamBrandSpoof (0.00s)
=== RUN   TestAlertTaskAdvancedChannels
2026/05/21 13:53:37 agent alert triggered: 1 events (1 critical)
--- PASS: TestAlertTaskAdvancedChannels (0.25s)
...
PASS
ok  	safe-zone/internal/agent	13.265s
```

### 2.2. Biên dịch Dự án
Toàn bộ mã nguồn dự án được biên dịch thành công hoàn hảo:
```bash
go build ./...
```
 Không có bất kỳ lỗi cú pháp, lỗi import chéo hay cảnh báo nào phát sinh từ trình biên dịch.
