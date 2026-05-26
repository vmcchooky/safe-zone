# Đặc tả Yêu cầu: Hỗ trợ DNS-over-TLS (DoT) (Hướng 7)

## 1. Giới thiệu & Mục tiêu
DNS-over-HTTPS (DoH) hoạt động rất tốt trên các trình duyệt web hiện đại, tuy nhiên trên các thiết bị di động (đặc biệt là hệ điều hành Android), tính năng bảo mật hệ thống mặc định **"Private DNS" (DNS riêng tư)** bắt buộc sử dụng giao thức **DNS-over-TLS (DoT) trên cổng 853**. 

Mục tiêu của **Hướng 7** là nâng cấp `dns-resolver` để chạy song song cả server **DoH (port 443/8081)** và **DoT (port 853)** trên cùng máy chủ để:
- Bảo vệ toàn bộ thiết bị di động (Android, iOS) ở tầng hệ điều hành mà không cần cài đặt thêm phần mềm của bên thứ ba.
- Giữ nguyên triết lý thiết kế **Zero-Cost**: Không phát sinh thêm chi phí vận hành, chạy cực nhẹ trực tiếp trên RAM máy chủ.
- Tự động sinh chứng chỉ TLS tự ký (Self-Signed) khi không cấu hình chứng chỉ Let's Encrypt, giúp việc chạy thử ở local diễn ra trơn tru ngay lập tức; nếu người vận hành đã cấu hình đường dẫn cert/key nhưng tải thất bại, server phải fail fast để tránh trạng thái production "UP" nhưng client DoT không tin cậy được.

---

## 2. Yêu cầu Chức năng (Functional Requirements)

### DOT-REQ-001: Chạy song song DoH và DoT
Dịch vụ `dns-resolver` phải khởi chạy song song hai server trên hai cổng khác nhau đồng thời:
1.  **DoH Server:** HTTP/HTTPS REST endpoint (nhận các query `/dns-query` thông qua reverse proxy).
2.  **DoT Server:** Raw TCP server bọc TLS lắng nghe trực tiếp trên cổng mặc định `853` (hoặc cổng tùy biến qua biến môi trường để chạy không cần quyền root lúc phát triển).

### DOT-REQ-002: Zero-Configuration TLS Fallback + Production Fail-Fast
- Khi cấu hình đường dẫn chứng chỉ Let's Encrypt qua biến môi trường (`SAFE_ZONE_DNS_DOT_CERT_FILE` và `SAFE_ZONE_DNS_DOT_KEY_FILE`), server DoT sẽ tải chứng chỉ thật từ ổ đĩa.
- Nếu một trong hai biến cert/key được cấu hình nhưng `tls.LoadX509KeyPair` thất bại, server phải ghi log lỗi và thoát ngay (`os.Exit(1)`).
- Nếu không cấu hình cert/key, server tự động phát sinh một cặp khóa và **chứng chỉ SSL tự ký (Self-Signed Certificate)** tạm thời trực tiếp trên bộ nhớ RAM để đảm bảo môi trường dev/local vẫn khởi động không cần cấu hình.

### DOT-REQ-003: Cơ chế Phân tích và Chặn Tên miền Đồng bộ
Mỗi truy vấn DNS gửi tới cổng DoT phải được phân tách để kiểm tra chính sách thông qua dịch vụ `risk.Service` dùng chung:
- **Nếu là tên miền thuộc diện chặn (BLOCK):** Áp dụng `SAFE_ZONE_DNS_BLOCK_STRATEGY`:
  - `sinkhole`: trả về bản ghi `A`/`AAAA` trỏ về IP trang cảnh báo (`blockPageIP`), với TTL cấu hình thấp.
  - `nxdomain`: trả về `NXDOMAIN`.
  - `refused`: trả về `REFUSED`.
  - `nullip`: trả về `0.0.0.0` cho `A` hoặc `::` cho `AAAA`.
- **Nếu là tên miền an toàn (ALLOW):** Chuyển tiếp truy vấn an toàn tới Upstream Resolver sử dụng giao thức DoH (tái sử dụng `forwardDoH`) và trả kết quả sạch về cho client.

### DOT-REQ-004: Tích hợp Rate Limiting & Bảo vệ DDoS
- Áp dụng cơ chế giới hạn tần suất truy cập cho các client DoT dựa trên IP nguồn (Key).
- Sử dụng trực tiếp gói `internal/ratelimit` hiện có.
- Nếu client vượt ngưỡng tần suất truy cập tối đa cho phép (ví dụ `100 req/minute`), server DoT sẽ lập tức ngắt hoặc phản hồi lỗi `RcodeRefused` (hoặc `RcodeServerFailure`) để tránh làm nghẽn luồng xử lý hoặc cạn kiệt tài nguyên máy chủ.

### DOT-REQ-005: Graceful Shutdown
Khi nhận được tín hiệu kết thúc từ hệ điều hành (SIGINT, SIGTERM), `dns-resolver` phải đóng cả hai server DoH và DoT một cách sạch sẽ, giải phóng tất cả các kết nối TCP đang mở trước khi thoát.

---

## 3. Yêu cầu Phi Chức năng (Non-Functional Requirements)

- **Hiệu năng cao & Độ trễ thấp:** Phản hồi DoT đối với các domain đã cache (hit) phải `< 5ms`.
- **An toàn luồng (Thread-Safety):** Handler DoT phải an toàn tuyệt đối trước các truy cập đồng thời của hàng ngàn client.
- **Bảo mật kết nối:** Hỗ trợ chuẩn mã hóa TLS 1.2 và TLS 1.3 với các bộ Cipher Suite an toàn.
