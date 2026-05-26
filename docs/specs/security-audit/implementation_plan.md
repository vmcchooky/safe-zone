# Kế hoạch Thực hiện Audit Bảo mật & Xử lý Lỗi (Security & Error-Handling Audit)

Bản kế hoạch này mô tả chi tiết các vấn đề bảo mật và xử lý lỗi được phát hiện trong phần máy chủ Core API (`cmd/core-api/`) và bộ phân giải DNS (`cmd/dns-resolver/`), cùng phương án khắc phục nhằm tối ưu hóa tính an toàn, hiệu năng và độ ổn định của hệ thống trước khi tiếp tục phát triển các tính năng nâng cao.

## User Review Required

> [!IMPORTANT]
> **Giới hạn kích thước Request Body (DoS Prevention):**
> Kế hoạch đề xuất áp dụng bộ giới hạn kích thước dữ liệu nhận vào (`http.MaxBytesReader`) đối với tất cả các API REST nhận dữ liệu dạng POST/PUT để ngăn chặn tấn công làm cạn kiệt bộ nhớ (Memory Exhaustion DoS).
> Các giới hạn cụ thể dự kiến:
> *   `POST /v1/analyze`: 4KB (vừa đủ cho payload domain)
> *   `POST /v1/overrides`: 10KB (dư dả cho domain, action, reason)
> *   `POST/PUT /v1/groups`: 64KB (đủ cho danh mục chặn và mô tả)
> *   `POST /v1/mappings`: 10KB (cho thông tin ánh xạ IP/Client)
> *   `POST/PUT /v1/group-overrides`: 10KB
>
> **Giới hạn Cận trên cho Truy vấn (Query Limit Control):**
> Chặn giá trị lớn nhất cho tham số `limit` khi lấy log telemetry gần đây (`GET /v1/telemetry/recent`) để tránh việc SQLite bị khóa lâu hoặc tiêu tốn bộ nhớ quá mức khi truy vấn hàng triệu bản ghi. Đề xuất giới hạn cứng `limit` tối đa là 100 bản ghi trên mỗi yêu cầu.

## Open Questions

Không có câu hỏi mở nào. Các đề xuất trên đều là những biện pháp thực hành bảo mật tiêu chuẩn (security best practices) không gây ảnh hưởng đến các tính năng hiện tại của ứng dụng.

---

## Proposed Changes

### Core API Server (`cmd/core-api`)

Thực hiện bọc `r.Body` trong `http.MaxBytesReader` để giới hạn dữ liệu tải lên và đặt giới hạn chặn trên cho tham số truy vấn `limit`.

#### [MODIFY] [main.go](file:///D:/Quorix/services/safe-zone/cmd/core-api/main.go)

- **`analyzeHandler` (dòng 334-340):** Thêm giới hạn `r.Body` bằng `http.MaxBytesReader(w, r.Body, 4096)` trước khi thực hiện `json.NewDecoder`.
- **`overridesHandler` (dòng 443-448):** Thêm giới hạn `r.Body` bằng `http.MaxBytesReader(w, r.Body, 10240)` trước khi giải mã JSON.
- **`telemetryRecentHandler` (dòng 486-495):** Thêm logic chặn cận trên cho `limit`:
  ```go
  if limit > 100 {
      limit = 100
  }
  ```
- **`groupsHandler` (dòng 657-662 & 687-690):** Thêm giới hạn `r.Body` bằng `http.MaxBytesReader(w, r.Body, 65536)` trước khi giải mã JSON trong cả hai nhánh POST và PUT.
- **`mappingsHandler` (dòng 747-752):** Thêm giới hạn `r.Body` bằng `http.MaxBytesReader(w, r.Body, 10240)` trước khi giải mã JSON.
- **`groupOverridesHandler` (dòng 825-830):** Thêm giới hạn `r.Body` bằng `http.MaxBytesReader(w, r.Body, 10240)` trước khi giải mã JSON.

---

## Verification Plan

### Automated Tests
- Chạy toàn bộ các ca kiểm thử bảo mật đa luồng và đơn luồng để đảm bảo không bị lỗi biên dịch hoặc rò rỉ:
  ```bash
  go test -race -count=1 ./...
  ```
- Chạy các ca kiểm thử cụ thể của `cmd/core-api` để kiểm chứng logic xử lý:
  ```bash
  go test -v ./cmd/core-api/...
  ```

### Manual Verification
- Khởi động dịch vụ Core API và DNS Resolver.
- Sử dụng các lệnh curl hoặc script test để gửi request body lớn vượt ngưỡng giới hạn cho phép (ví dụ gửi body 10MB lên `/v1/analyze`) và kiểm tra xem máy chủ có lập tức ngắt kết nối với HTTP Status `413 Payload Too Large` hay không.
