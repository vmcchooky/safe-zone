# Đánh giá An toàn & Đề xuất Cải thiện Trước khi Triển khai VPS (Safe Zone)

Tài liệu này tổng hợp kết quả đánh giá an toàn, kiểm toán mã nguồn và phân tích khoảng trống vận hành đối với dự án **Safe Zone — Anti-Phishing System**, phục vụ công tác tối ưu hóa hệ thống ở môi trường local trước khi chạy thử nghiệm trên máy chủ VPS thực tế.

---

## 1. Phân tích 3 Điểm yếu Bảo mật & Logic Trong Code (Cần Khắc Phục Ngay)

Dưới đây là 3 lỗi logic và bảo mật cụ thể được phát hiện trong quá trình kiểm toán mã nguồn:

### 1.1. [Resolved] Rò rỉ Thông tin Admin Secret Trong Log Cục bộ
*   **Vị trí mã nguồn:** [cmd/core-api/security.go (dòng 65 & 86)](file:///D:/Quorix/services/safe-zone/cmd/core-api/security.go#L65-L89)
*   **Chi tiết vấn đề:** Khi chạy ở chế độ cục bộ (local mode) và không cấu hình biến môi trường `SAFE_ZONE_ADMIN_PASSWORD` hoặc `SAFE_ZONE_ADMIN_API_KEY`, hệ thống tự sinh ngẫu nhiên chuỗi bảo mật.
*   **Hậu quả:** 
    *   *Trước đây:* In ra cấu trúc log JSON (`logjson.Info`) của container.
    *   *Hiện tại:* Đã chuyển sang `fmt.Printf` (in ra `stdout` chung). Tuy nhiên, `stdout`/`stderr` của tiến trình vẫn bị Docker daemon thu thập (`docker logs`) hoặc systemd ghi nhận (`journalctl`), do đó các secret vẫn bị rò rỉ dưới dạng bản rõ trong luồng log stream chung.
*   **Đề xuất khắc phục:** 
    *   Tuyệt đối không in giá trị secret thô ra bất kỳ luồng đầu ra tiêu chuẩn nào (`stdout`/`stderr`).
    *   Ghi toàn bộ thông tin secret tự sinh cục bộ vào một tệp tạm nằm trong danh mục bị bỏ qua bởi Git (ví dụ: `tmp/local_admin_secrets.txt` hoặc `ops/secrets/local_admin_secrets.txt`, cả hai thư mục này đã được định nghĩa trong `.gitignore`).
    *   Thiết lập quyền truy cập tệp an toàn (chmod `0600` - chỉ chủ sở hữu tiến trình được đọc/ghi).
    *   Chỉ ghi nhận một dòng log cảnh báo dạng Warn thông báo cho nhà phát triển biết tệp chứa secret tạm thời đã được ghi tại đường dẫn đó (ví dụ: *"Admin secrets written to tmp/local_admin_secrets.txt"*).
*   **Trạng thái hiện tại:** Đã triển khai. Local fallback secrets được ghi vào file tạm và production yêu cầu secret rõ ràng/đủ mạnh.

---

### 1.2. [Resolved] Trùng lặp Metrics khi Xảy ra Sự cố Panic (Double Observe)
*   **Vị trí mã nguồn:** 
    *   [internal/serve/http.go (dòng 71 & 95)](file:///D:/Quorix/services/safe-zone/internal/serve/http.go#L71-L95)
    *   [cmd/core-api/main.go (dòng 419)](file:///D:/Quorix/services/safe-zone/cmd/core-api/main.go#L419)
    *   [cmd/dns-resolver/main.go (dòng 505)](file:///D:/Quorix/services/safe-zone/cmd/dns-resolver/main.go#L505)
*   **Chi tiết vấn đề:** Khi HTTP Handler xảy ra lỗi panic, middleware `Recovery` (nằm trong) sẽ bắt lỗi, ghi nhận cờ `ObservedPanicKey = true` vào request context thông qua lệnh `r = r.WithContext(ctx)` rồi tiến hành quan sát chỉ số lỗi (`obs.Observe`). Tuy nhiên, trong Go, context là bất biến (immutable), việc re-assign `r` chỉ thay đổi con trỏ cục bộ bên trong hàm defer của `Recovery`. 
    Middleware ghi log bên ngoài (`logRequests`) đã gọi `next.ServeHTTP` trước đó và giữ con trỏ request ban đầu, nên không hề nhận được cờ hiệu này (`r.Context().Value(serve.ObservedPanicKey)` luôn trả về `nil`). Do đó, `logRequests` tiếp tục gọi `metrics.Observe` lần thứ hai khi yêu cầu kết thúc với mã lỗi 500.
*   **Hậu quả:** Mỗi sự cố panic của hệ thống HTTP/DoH đều bị đếm trùng lặp **2 lần** trong Telemetry Registry, làm sai lệch báo cáo tỷ lệ lỗi và cảnh báo an toàn.
*   **Đề xuất khắc phục:** Sử dụng một con trỏ tham chiếu kiểu `*bool` được tạo và truyền từ middleware ngoài (`logRequests`) vào context. Middleware trong (`Recovery`) sẽ thay đổi giá trị của con trỏ đó để truyền trạng thái ngược lên phía trên một cách an toàn.
*   **Trạng thái hiện tại:** Đã triển khai trong `cmd/core-api/main.go`, `cmd/dns-resolver/main.go`, và `internal/serve/http.go`.

---

### 1.3. [Resolved] dns-resolver Không Khởi động Lại khi Lỗi Cấu hình DoT Certificate
*   **Vị trí mã nguồn:** [cmd/dns-resolver/main.go (dòng 149-165)](file:///D:/Quorix/services/safe-zone/cmd/dns-resolver/main.go#L149-L165)
*   **Chi tiết vấn đề trước đây:** Nếu admin cấu hình tệp chứng chỉ DoT (`certFile` và `keyFile`) nhưng quá trình tải tệp gặp lỗi (ví dụ: sai quyền hạn đọc ghi, sai đường dẫn, chứng chỉ hỏng), chương trình từng chỉ in log `Warn`, tự sinh chứng chỉ tự ký (self-signed cert) thông qua `generateSelfSignedCert()` và tiếp tục khởi chạy máy chủ DoT trên cổng 853.
*   **Hậu quả:** Tất cả các DNS-over-TLS client trên thực tế (như Private DNS của Android) đòi hỏi chứng chỉ TLS được ký bởi các CA công cộng hợp lệ. Việc âm thầm fallback sang self-signed cert sẽ làm toàn bộ client mất kết nối mạng. Dịch vụ hiển thị trên systemd/Docker vẫn báo trạng thái **UP (Running)** nhưng thực tế hệ thống đã bị tê liệt từ bên ngoài.
*   **Đề xuất khắc phục:** Áp dụng cơ chế **Fail-Fast**. Nếu người vận hành đã chỉ định cấu hình cert/key file mà việc tải tệp thất bại, chương trình phải lập tức in log lỗi nghiêm trọng và dừng chạy (`os.Exit(1)`).
*   **Trạng thái hiện tại:** Đã triển khai fail-fast khi cert/key được cấu hình nhưng tải thất bại. Self-signed fallback chỉ còn dành cho trường hợp không cấu hình cert/key trong local/dev.

---

## 2. 5 Phần Quan trọng Đã Triển Khai & Cần Xác Minh Trên VPS

> Cập nhật 2026-05-26: 5 hạng mục dưới đây đã được triển khai trong repo. Các bước còn lại là chạy/ghi nhận kết quả trên môi trường VPS mục tiêu.

Để bảo đảm quá trình chạy thử trên VPS không gặp sự cố về tài nguyên hoặc cấu hình sai, cần tập trung hoàn thiện 5 điểm sau ở local:

1.  **[x] Xây dựng Kịch bản Test Tải Cục bộ (Local Load Testing Tool):**
    *   Đã triển khai `cmd/load-test` cho HTTP/DoH, cache-hit/cache-miss, concurrency, rate-limit, và latency summary.
    *   Còn lại: chạy benchmark trên VPS mục tiêu và lưu kết quả p50/p95/p99, throughput, error rate, CPU/RAM.
2.  **[x] Cài đặt Tự động Offsite Backup qua `rclone`:**
    *   `scripts/safe-zone.sh` và `scripts/safe-zone.ps1` đã backup Redis RDB, SQLite hot backup bằng `.backup`, `.env`, Caddyfile, và upload tùy chọn qua `SAFE_ZONE_RCLONE_REMOTE`/`SAFE_ZONE_RCLONE_DEST`.
    *   Còn lại: ghi nhận restore drill định kỳ trên máy sạch.
3.  **[x] Hoàn thiện Script Rà quét Cổng Công cộng (Public Edge Security Scan):**
    *   `scripts/check-production-ports.sh` và `scripts/public-edge-smoke.sh` đã sẵn sàng để xác thực bề mặt public edge.
    *   Còn lại: chạy từ ngoài VPS và lưu lại bằng chứng môi trường.
4.  **[x] Tối ưu hóa Trải nghiệm Trang Chặn HTTPS (HTTPS Block Page UX):**
    *   `SAFE_ZONE_DNS_BLOCK_STRATEGY` hỗ trợ `sinkhole`, `nxdomain`, `refused`, và `nullip`.
    *   Operator có thể dùng `sinkhole` cho HTTP block page hoặc `nxdomain`/`refused`/`nullip` để tránh cảnh báo mismatch TLS trên HTTPS.
5.  **[x] Reconcile và Dọn dẹp Tài liệu Đặc tả (Docs Synchronization):**
    *   Checklist production và các spec liên quan đã được đồng bộ với trạng thái code hiện tại.
    *   Còn lại: tiếp tục duy trì đồng bộ khi có release task mới.

---

## 3. Các Hạng mục Khoảng trống Cần Bổ sung Để Lên Production MVP

Hệ thống Safe Zone sẽ chính thức đạt trạng thái **Production MVP** khi và chỉ khi hoàn thành đầy đủ các tiêu chí thoát (Exit Criteria) sau:

*   **Network Safety:** Public traffic chỉ được phép đi qua các cổng đã chỉ định (80, 443, 853). Đã chạy thành công port-scan check.
*   **Credential Integrity:** Mật khẩu admin và API key được kiểm tra độ mạnh tự động, nạp từ Docker secrets/file-based secrets (`*_FILE`) và tuyệt đối không rò rỉ trong log.
*   **TLS Production:** DoH và trang quản trị chạy HTTPS thành công với Let's Encrypt qua Caddy. DoT chạy chứng chỉ tin cậy được cập nhật tự động.
*   **Reliable Feeds:** Các nguồn threat intelligence kết nối ổn định thông qua preset `production-free`, có cảnh báo khi dữ liệu feed bị quá hạn (stale feed warning).
*   **Diễn tập Khôi phục (DR Drill):** Đã thực hiện thành công ít nhất một bài kiểm tra khôi phục lại toàn bộ dữ liệu từ bản offsite backup trên máy chủ sạch.
*   **Threat Model:** Đã hoàn thành tài liệu phân tích mô hình hiểm họa theo chuẩn STRIDE để rà soát an ninh hệ thống trước khi vận hành thực tế.
