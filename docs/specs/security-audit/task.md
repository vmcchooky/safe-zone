# Danh sách đầu việc (Task Checklist) - Security & Error-Handling Audit

Tiến độ triển khai tối ưu hóa bảo mật và xử lý lỗi cho máy chủ Core API và DNS Resolver:

- `[x]` 1. Áp dụng giới hạn kích thước request body (DoS Prevention) cho các API REST POST/PUT trong `cmd/core-api/main.go`
  - `[x]` 1.1 `/v1/analyze` (POST) - Giới hạn 4KB
  - `[x]` 1.2 `/v1/overrides` (POST) - Giới hạn 10KB
  - `[x]` 1.3 `/v1/groups` (POST/PUT) - Giới hạn 64KB
  - `[x]` 1.4 `/v1/mappings` (POST) - Giới hạn 10KB
  - `[x]` 1.5 `/v1/group-overrides` (POST/PUT) - Giới hạn 10KB
- `[x]` 2. Giới hạn cận trên cho tham số truy vấn `limit` (tối đa 100) trong `telemetryRecentHandler`
- `[x]` 3. Chạy kiểm thử toàn bộ hệ thống (`go test -race ./...`) để đảm bảo không bị lỗi hồi quy (regression)
- `[x]` 4. Thực hiện kiểm chứng thủ công gửi payload quá cỡ để kiểm tra tính hiệu quả của `MaxBytesReader` (thông qua Unit Test `TestSecurityAuditLimits`)
- `[x]` 5. Cập nhật báo cáo bảo mật (`codebase_security_audit.md`) và hướng dẫn kỹ thuật (`walkthrough.md`)
- `[x]` 6. Đồng bộ hóa toàn bộ tài liệu (Implementation Plan, Security Audit, Task, Walkthrough) vào thư mục `docs/specs/security-audit/`
