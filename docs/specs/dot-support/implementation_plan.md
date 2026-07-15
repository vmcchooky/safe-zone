# Kế hoạch triển khai: Hỗ trợ DNS-over-TLS (DoT) (Hướng 7)

> **Trạng thái tài liệu:** Đây là kế hoạch lịch sử. Repo hiện tại không còn file test riêng dưới `cmd/dns-resolver`; các mục test bên dưới cần được xem là phạm vi cần tái xác minh, không phải danh sách file hiện có.

Bản kế hoạch này mô tả chi tiết phương án thiết kế và triển khai cổng **DNS-over-TLS (DoT)** trên cổng `853` song song với cổng **DNS-over-HTTPS (DoH)** hiện có. Điều này giúp dự án bảo vệ các thiết bị di động (đặc biệt là Android với tính năng Private DNS mặc định) mà không cần cài đặt phần mềm ngoài, tuân thủ triết lý **Zero-Cost** cho vận hành và **Zero-Configuration** cho local/dev khi không cấu hình chứng chỉ thật.

---

## User Review Required

> [!IMPORTANT]
> **Tự động sinh chứng chỉ tự ký (Self-Signed Certificates):**
> Nhằm đơn giản hóa quá trình phát triển cục bộ, hệ thống sinh chứng chỉ TLS tự ký trực tiếp trên RAM khi không có chứng chỉ thật được cấu hình. Nếu người vận hành đã cấu hình cert/key nhưng file lỗi, thiếu, hoặc không đọc được, `dns-resolver` fail fast thay vì âm thầm fallback sang self-signed.
>
> **Không chiếm quyền Root ở Local (Cổng 8533 làm mặc định khi Dev):**
> Ở các hệ điều hành Unix/Linux, các cổng `< 1024` yêu cầu quyền root. Để phát triển và kiểm thử ở local dễ dàng, mặc định chúng ta sẽ chạy cổng DoT trên cổng tùy biến `:8533` (hoặc cổng cấu hình `.env` `SAFE_ZONE_DNS_DOT_ADDR`), và chỉ chạy trên cổng `:853` thực tế khi triển khai Docker/Production.

---

## Open Questions

Không có câu hỏi mở nào. Các đề xuất trên tuân thủ chuẩn thực hành kỹ thuật phần mềm an toàn, linh hoạt và tối ưu hiệu năng.

---

## Proposed Changes

### 1. DNS Resolver Component (`cmd/dns-resolver`)

Thực hiện cập nhật và cấu hình để chạy song song server DoT và DoH.

#### [MODIFY] [main.go](file:///D:/Quorix/services/safe-zone/cmd/dns-resolver/main.go)
-   **Struct `app`:** Bổ sung trường `dotLimiter *ratelimit.Limiter`.
-   **Khởi chạy `main()`:**
    -   Tải các biến cấu hình từ môi trường (`SAFE_ZONE_DNS_DOT_ENABLED`, `SAFE_ZONE_DNS_DOT_ADDR`, `SAFE_ZONE_DNS_DOT_CERT_FILE`, `SAFE_ZONE_DNS_DOT_KEY_FILE`, `SAFE_ZONE_RATELIMIT_DOT_RPM`, `SAFE_ZONE_RATELIMIT_DOT_BURST`).
    -   Khởi tạo `dotLimiter` nếu rate limiting được bật.
    -   Tạo TLS Config. Load chứng chỉ thật từ đường dẫn; nếu đường dẫn cert/key được cấu hình nhưng load lỗi thì ghi log lỗi và thoát. Chỉ tự sinh Self-Signed Certificate khi cert/key không được cấu hình.
    -   Khởi chạy server HTTP DoH và server DoT song song bằng goroutine.
    -   Bắt tín hiệu `SIGINT/SIGTERM` để shutdown graceful cả hai server.
-   **Hàm `dotHandler(w dns.ResponseWriter, r *dns.Msg)`:** Nhận truy vấn DoT, kiểm tra Rate Limit, kiểm tra chính sách block/allow, forward tới upstream bằng DoH và trả lời client.
-   **Hàm helper `generateSelfSignedCert() (tls.Certificate, error)`:** Sinh chứng chỉ SSL tự ký 2048-bit RSA tạm thời trực tiếp trên RAM.
-   **Hàm `blockedDNSMessage(query *dns.Msg) (*dns.Msg, error)`:** Dịch chuyển logic tạo message DNS block từ byte thô của DoH sang đối tượng `dns.Msg` của DoT, đồng thời áp dụng `sinkhole`, `nxdomain`, `refused`, hoặc `nullip`.
-   **Hàm `sendServfail(w dns.ResponseWriter, r *dns.Msg)`:** Đóng gói gửi phản hồi ServFail.

#### [MODIFY] Test coverage cho `cmd/dns-resolver` (file lịch sử không còn trong repo hiện tại)
-   Bổ sung test suite cho DoT:
    -   `TestGenerateSelfSignedCert`: Kiểm thử thành công tính năng tự sinh SSL.
    -   `TestDoTHandlerBasic`: Gửi truy vấn DoT giả lập (Allow & Block) và kiểm tra kết quả trả về.
    -   `TestDoTHandlerRateLimiter`: Kiểm tra DoT phản hồi `RcodeRefused` khi bị rate limit.
    -   `TestDoTHandlerConcurrent`: Kiểm thử an toàn đa luồng trên DoT handler.

---

### 2. Configuration & Infrastructure

#### [MODIFY] [.env.example](file:///D:/Quorix/services/safe-zone/.env.example)
-   Bổ sung các biến cấu hình:
    ```bash
    # DNS-over-TLS (DoT) Configurations
    SAFE_ZONE_DNS_DOT_ENABLED=true
    SAFE_ZONE_DNS_DOT_ADDR=:8533
    SAFE_ZONE_DNS_DOT_CERT_FILE=
    SAFE_ZONE_DNS_DOT_KEY_FILE=
    SAFE_ZONE_RATELIMIT_DOT_RPM=100
    SAFE_ZONE_RATELIMIT_DOT_BURST=20
    ```

#### [MODIFY] [docker-compose.yml](file:///D:/Quorix/services/safe-zone/docker-compose.yml)
-   Mở cổng `853` trỏ về container `dns-resolver` để sẵn sàng hỗ trợ di động.
-   Thiết lập các biến môi trường tương ứng cho môi trường Docker production (mặc định trỏ về cổng `:853`).

---

## Verification Plan

### Automated Tests
-   Chạy toàn bộ các ca kiểm thử bảo mật đa luồng và đơn luồng để đảm bảo không bị lỗi biên dịch hoặc rò rỉ:
    ```bash
    go test -race -count=1 ./...
    ```
-   Chạy các ca kiểm thử cụ thể của `cmd/dns-resolver` để kiểm chứng logic xử lý:
    ```bash
    go test -v ./cmd/dns-resolver/...
    ```

### Manual Verification
-   Khởi chạy dịch vụ `dns-resolver` trên local (`go run ./cmd/dns-resolver`).
-   Sử dụng công cụ `kdig` hoặc `dog` (nếu có) gửi truy vấn DoT lên cổng `8533`:
    ```bash
    kdig @127.0.0.1 -p 8533 +tls example.com
    kdig @127.0.0.1 -p 8533 +tls -v bocongan-verify.xyz
    ```
-   Kiểm tra xem tên miền cảnh báo có lập tức trả về IP trang block page của hệ thống hay không.
-   Kiểm tra thêm các chiến lược chặn DNS bằng `SAFE_ZONE_DNS_BLOCK_STRATEGY=sinkhole|nxdomain|refused|nullip`.
