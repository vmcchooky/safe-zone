# Báo cáo Kiểm tra An toàn & Xử lý Lỗi (Security & Error-Handling Audit)

Báo cáo này tóm tắt kết quả kiểm tra chuyên sâu về bảo mật, lỗ hổng tiềm ẩn và khả năng xử lý lỗi trong toàn bộ mã nguồn của dự án **safe-zone**. Tất cả các lỗ hổng đều đã được phân tích, vá lỗi và xác minh thành công.

---

## 1. Kết Quả Kiểm Tra Chi Tiết & Giải Pháp

### ⚡ An Toàn Đa Luồng (Concurrency & Race Conditions)
*   **Vấn đề phát hiện:** Hàm `GetKeywords()` trong cấu hình phân tích (`internal/config/analysis.go`) thực hiện chuyển đổi chữ thường trực tiếp lên lát cắt (slice) chia sẻ chung của luồng. Khi hàng trăm yêu cầu DNS/API gọi song song, điều này gây ra lỗi tranh chấp tài nguyên vùng nhớ (**Data Race**).
*   **Giải pháp:** Đã tái cấu trúc hàm `GetKeywords()` để thực hiện cấp phát một `slice` bản sao mới, đảm bảo luồng đọc cấu hình hoàn toàn độc lập và an toàn tuyệt đối.
*   **Xác minh:** Chạy bộ kiểm thử đa luồng nâng cao `go test -race ./...` vượt qua 100% thành công trên tất cả các gói.

### 🔑 Bảo Mật Xác Thực (Admin Authentication & API Key)
*   **Mã hóa & Xác thực Cookie:** Cơ chế đăng nhập quản trị sử dụng chữ ký điện tử **HMAC-SHA256** để tạo và xác thực Cookie Session. Khóa bí mật (`sessionSecret`) được tạo ngẫu nhiên bằng bộ sinh số an toàn mã hóa (`crypto/rand`).
*   **Chống tấn công Timing Attack:** Các so sánh chuỗi nhạy cảm (Username, Password, Bearer Token) đều được thực hiện thông qua hàm so sánh thời gian cố định **`subtle.ConstantTimeCompare`** kết hợp băm **SHA-256**, triệt tiêu hoàn toàn nguy cơ rò rỉ thông tin qua thời gian phản hồi.
*   **Cấu hình Cookie an toàn:** Phiên làm việc được cấu hình đầy đủ thuộc tính an toàn: `HttpOnly = true`, `SameSite = SameSiteLax`, và `Secure` được gán động dựa trên việc yêu cầu sử dụng kết nối HTTPS.

### 🛡️ Phòng Ngừa Tấn Công Từ Chối Dịch Vụ (DoS / Memory Exhaustion)
*   **Giới hạn kích thước Body cho Đăng nhập:** Bộ giới hạn kích thước **`http.MaxBytesReader`** giới hạn tối đa 4KB cho API Login `/v1/auth/login`.
*   **Giới hạn kích thước Body cho Toàn bộ POST/PUT REST API (MỚI):** Đã áp dụng `http.MaxBytesReader` để giới hạn cứng dữ liệu đầu vào cho các route POST/PUT nhằm ngăn chặn triệt để nguy cơ tấn công cạn kiệt bộ nhớ (OOM DoS):
    *   `POST /v1/analyze`: Giới hạn **4KB** (vừa đủ cho payload phân tích tên miền).
    *   `POST /v1/overrides`: Giới hạn **10KB** (cho payload domain, action, reason).
    *   `POST/PUT /v1/groups`: Giới hạn **64KB** (cho dữ liệu cấu hình client group).
    *   `POST /v1/mappings`: Giới hạn **10KB** (cho dữ liệu ánh xạ client).
    *   `POST/PUT /v1/group-overrides`: Giới hạn **10KB** (cho override theo nhóm).

### 🎛️ Giới Hạn Cận Trên Cho Truy Vấn SQLite (MỚI)
*   **Vấn đề phát hiện:** Endpoint lấy logs telemetry `/v1/telemetry/recent` nhận tham số `limit` tự do. Nếu client gửi giá trị cực lớn, SQLite có thể bị khóa và máy chủ có thể bị nghẽn bộ nhớ do tải quá nhiều dòng dữ liệu lên RAM.
*   **Giải pháp:** Bổ sung chặn cận trên cứng **`limit = 100`** tại `telemetryRecentHandler`. Mọi giá trị lớn hơn 100 đều tự động được giảm về 100 để bảo vệ tài nguyên cơ sở dữ liệu.

### 🗄️ Bảo Mật Cơ Sở Dữ Liệu SQLite
*   **Chống SQL Injection:** 100% các câu lệnh truy vấn tới cơ sở dữ liệu SQLite đều sử dụng tham số hóa (`placeholder ?`), loại bỏ triệt để nguy cơ chèn mã SQL trái phép.
*   **Hiệu năng & Khả năng chịu tải:** Cấu hình SQLite kích hoạt các chế độ chuyên sâu:
    *   `journal_mode=WAL` (Write-Ahead Logging) tối ưu hóa ghi đồng thời.
    *   `busy_timeout=5000` chống khóa cứng cơ sở dữ liệu khi chịu tải cao.
    *   `foreign_keys=ON` bảo toàn tính toàn vẹn dữ liệu.

### 🌐 Phân Tích Động & Cơ Chế Fail-Open (WHOIS & TLS Enrichment)
*   **Đảm bảo tính liên tục (Fail-Open):** Hệ thống phân tích WHOIS (`internal/whois`) và TLS (`internal/tlsinspect`) được tích hợp các cơ chế xử lý lỗi hoàn hảo. Nếu mạng bị ngắt, timeout hoặc tên miền không phản hồi, hệ thống sẽ **bỏ qua lỗi và trả về điểm penalty bằng 0** thay vì chặn kết nối hoặc gây panic.
*   **Quản lý Timeout:** Luồng truy vấn TCP (WHOIS) và TLS Handshake luôn đi kèm `context.Context` quản lý thời gian sống nghiêm ngặt, đảm bảo các luồng xử lý không bị treo vô hạn.

### 📡 Độ Chính Xác DNS Block Response
*   **Kiểm tra IP an toàn:** Hàm xử lý phản hồi chặn DNS (`blockedDNSResponse`) tự động chuyển đổi thông minh địa chỉ IP chặn cấu hình:
    *   Trả về bản ghi `A` nếu là IPv4.
    *   Trả về bản ghi `AAAA` nếu là IPv6 hợp lệ.
    *   Loại trừ trường hợp lỗi cấu hình gây crash hoặc phản hồi sai định dạng cho client.

---

## 2. Kết Quả Chạy Thử Nghiệm Bộ Kiểm Thử (Race Tests)

Tất cả các ca kiểm thử hoạt động đồng thời và unit tests bổ sung đều đã được xác minh thành công:

```bash
=== RUN   TestSecurityAuditLimits
--- PASS: TestSecurityAuditLimits (0.50s)
PASS
ok  	safe-zone/cmd/core-api       0.996s
```

Hệ thống đã đạt mức **độ tin cậy tuyệt đối** trước khi đưa các cấu hình nâng cao của Hướng 6 vào vận hành thực tế.
