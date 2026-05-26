# Kế hoạch Rà soát An toàn & Vá lỗ hổng DoT (DoT Security Hardening & Robustness Plan)

Kế hoạch này tập trung vào việc thực hiện rà soát an toàn chuyên sâu (Security Audit) và triển khai vá các lỗ hổng tiềm ẩn trong cấu phần máy chủ **DNS-over-TLS (DoT)** vừa được phát triển. Mục tiêu là tối ưu hóa độ tin cậy, ngăn chặn các nguy cơ tấn công từ từ chối dịch vụ (DoS), rò rỉ luồng xử lý (goroutine leak), và bảo toàn tính liên tục cao nhất của dịch vụ phục vụ cộng đồng.

---

## 1. Các Lỗ Hổng Bảo Mật Được Nhận Diện & Giải Pháp Vá

1. **Lỗ hổng cạn kiệt kết nối (Slowloris / FD Exhaustion):** Cổng DoT (`dns.Server`) hiện tại chạy trên giao thức TCP TLS nhưng thiếu cấu hình `ReadTimeout` và `WriteTimeout`. Kẻ tấn công có thể mở hàng ngàn kết nối TCP TLS và duy trì vô hạn không gửi dữ liệu, gây cạn kiệt file descriptor (sập cổng DoT).
   * *Giải pháp:* Cấu hình `ReadTimeout: 5 * time.Second` và `WriteTimeout: 5 * time.Second` trực tiếp cho `dotServer`.
2. **Rò rỉ luồng khi Upstream bị treo (Goroutine / Context Leak):** Hàm xử lý truy vấn `dotHandler` gọi upstream DoH thông qua `forwardDoH` bằng `context.Background()`. Nếu upstream DoH bị chậm hoặc treo, goroutine xử lý DoT sẽ bị giữ vô hạn dẫn đến nghẽn tài nguyên.
   * *Giải pháp:* Thiết lập context ngắn hạn `context.WithTimeout(context.Background(), 3 * time.Second)` cho luồng forward.
3. **Sai lệch định dạng IP Client (IPv6 Format Inconsistency):** Địa chỉ IP trích xuất từ connection TLS của DoT có thể chứa dấu ngoặc vuông `[...]` của IPv6 (ví dụ `[::1]`). Nếu không được làm sạch, nó sẽ làm sai lệch key của map trong `ratelimit` và engine chính sách.
   * *Giải pháp:* Chuẩn hóa IP bằng `strings.Trim(clientIP, "[]")` đồng bộ tuyệt đối với cơ chế bên DoH.
4. **Thiếu cơ chế Panic Recovery trên luồng DNS:** Trình xử lý DNS `dotHandler` được gọi bất đồng bộ bởi gói `github.com/miekg/dns`. Nếu xảy ra panic runtime không mong muốn bên trong handler (ví dụ lỗi logic con trỏ hoặc phân tách thông tin), nó có thể làm sập toàn bộ tiến trình `dns-resolver`.
   * *Giải pháp:* Tích hợp cơ chế Panic Recovery chuyên biệt (`defer/recover`) tại đầu hàm `dotHandler` để log chi tiết lỗi và trả lời `ServFail` an toàn cho client.

---

## 2. Kế hoạch triển khai thay đổi

### DNS Resolver Component (`cmd/dns-resolver`)

#### [MODIFY] [main.go](file:///D:/Quorix/services/safe-zone/cmd/dns-resolver/main.go)
-   **Cấu hình DoT Server (`dotServer`):** Bổ sung `ReadTimeout` và `WriteTimeout` vào cấu hình khởi tạo của `dns.Server` để ngăn chặn tấn công Slowloris.
-   **Trình xử lý DoT (`dotHandler`):**
    -   Bổ sung khối `defer func()` ở đầu hàm thực hiện recovery panic, ghi log lỗi an toàn bằng `log.Printf` và phản hồi `ServFail` thông qua hàm helper `sendServfail` để bảo vệ server.
    -   Chuẩn hóa IP client sau khi thực hiện `SplitHostPort` bằng cách sử dụng `strings.Trim(clientIP, "[]")`.
    -   Bổ sung context quản lý thời gian sống nghiêm ngặt `context.WithTimeout` (3 giây) khi gọi `a.forwardDoH` và kiểm tra chính sách block/allow, đảm bảo dọn dẹp goroutine nhanh chóng nếu client TLS hoặc upstream ngắt kết nối.

---

## 3. Kế hoạch Kiểm thử & Xác minh

### Automated Tests
-   Chạy test suite hiện tại với cờ Race Detector hoạt động song song để đảm bảo tính an toàn đa luồng tuyệt đối:
    ```bash
    go test -race -v -count=1 ./cmd/dns-resolver/...
    ```
-   Bổ sung ca kiểm thử bảo mật nâng cao để kiểm chứng các tính năng vá lỗi:
    -   `TestDoTHandlerPanicRecovery`: Giả lập một panic xảy ra trong handler và xác minh rằng máy chủ DoT vẫn sống khỏe mạnh, đồng thời trả về mã lỗi `RcodeServerFailure`.
    -   `TestDoTHandlerIPv6Sanitization`: Xác minh các IP IPv6 có ngoặc vuông `[::1]` được xử lý chuẩn hóa chính xác, không gây lỗi rate limit hoặc định tuyến.

### Manual Verification
-   Biên dịch và chạy thử hệ thống ở môi trường local để đảm bảo tính ổn định tối đa của mã nguồn.
