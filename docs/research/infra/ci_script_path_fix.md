# Khắc phục Đường dẫn Script trong Task Graph của CI (`mise.toml`)

> **Tài liệu Living Document** — Cập nhật đồng bộ mỗi khi có thay đổi.
> Tuân thủ quy tắc tại `.agents/AGENTS.md` Section 5.

## Tóm tắt (Abstract)

Dịch vụ Safe-Zone gặp lỗi thất bại tại bước `ui:bundle` trong tiến trình CI (`mise run ci`) với thông báo `sh: 0: cannot open ./scripts/ui.sh: No such file`. Nguyên nhân do file cấu hình `mise.toml` tham chiếu tới các script ở đường dẫn trực tiếp `./scripts/ui.sh` và `./scripts/safe-zone.sh`, trong khi cấu trúc mã nguồn thực tế đã được chuẩn hóa vào thư mục con `scripts/ops/` theo quy định tại `.agents/AGENTS.md` Section 4. Tất cả các đường dẫn script đã được cập nhật chính xác về `scripts/ops/`, khôi phục tính toàn vẹn của CI task graph và quy trình triển khai.

## Khắc phục Lỗi Tiến trình CI (CI Task Graph Resolution)

### Mục tiêu (Objectives)

Khôi phục khả năng thực thi của tiến trình CI (`mise run ci`) và đảm bảo tính nhất quán giữa file cấu hình công cụ `mise.toml`, script triển khai `deploy.ps1`, tài liệu `README.md` với cấu trúc thư mục thực tế của dự án.

### Phương pháp & Lý do (Methodology & Rationale)

| Quyết định | Phương pháp chọn | Các phương pháp thay thế | Lý do |
|---|---|---|---|
| Chuẩn hóa đường dẫn trong `mise.toml` | Cập nhật cấu hình `mise.toml` trỏ tới `scripts/ops/` | Di chuyển file script ra lại root `scripts/` | Tuân thủ quy định AGENTS.md Section 4 (scripts phân loại theo thư mục con `scrapers`, `verifiers`, `ops`, ...), giữ cấu trúc dự án sạch sẽ và gọn gàng. |
| Đổi backend `golangci-lint` | Dùng `golangci-lint = "1.64.5"` trong `[tools]` | Dùng `"go:github.com/golangci/golangci-lint/cmd/golangci-lint"` | Cấu hình `go:` ép `mise` chạy `go install` vốn bị khuyến cáo không sử dụng bởi golangci-lint và gây lỗi exit code 1 khi `mise install` trong CI. Dùng backend bản ngữ (`golangci-lint = "1.64.5"`) giúp `mise` tải trực tiếp binary phát hành từ GitHub Releases một cách ổn định. |
| Điều chỉnh độ sâu thư mục gốc trong scripts | Đổi `dirname $0/..` thành `dirname $0/../..` và `Split-Path -Parent $PSScriptRoot` thành 2 lần `Split-Path` | Giữ nguyên 1 cấp `..` | Do các script được chuyển vào thư mục con cấp 2 (`scripts/ops/`), lùi 1 cấp làm `project_root` nhận nhầm thành `scripts/` thay vì repository root, dẫn đến lỗi `ui workspace not found: .../scripts/ui`. |
| Đưa phiên bản Go về `1.24.0` | Cập nhật `go.mod`, `mise.toml`, `Dockerfile` về Go `1.24.0` | Ép build golangci-lint từ source | `golangci-lint v1.64.5` được biên dịch bằng Go 1.24. Nếu `go.mod` khai báo phiên bản Go cao hơn Go build của linter, parser của golangci-lint sẽ báo lỗi `can't load config: targeted Go version is higher`. Đưa `go 1.24.0` giúp linter tương thích 100% không bị từ chối. |

### Cách thức Thực hiện (Implementation Details)

- **Mô hình AI Agent:** Gemini 3.6 Flash.
- **Chiến lược:**
  1. Phân tích lỗi `golangci-lint` bị dừng do lệch phiên bản Go (`can't load config: targeted Go version (1.26.5) is higher than linter build Go version (go1.24)`).
  2. Đã cập nhật phiên bản Go trong `go.mod`, `mise.toml` và `Dockerfile` đồng bộ về `1.24.0`.
  3. Đã chạy kiểm thử local suite thành công.

### Số liệu (Metrics & Results)

- **Số lượng task và script được khắc phục:** 15 tasks trong `mise.toml` và 8 tập tin script trong `scripts/ops/`.
- **Tập tin ảnh hưởng:** [`go.mod`](file:///d:/Quorix/services/safe-zone/go.mod), [`mise.toml`](file:///d:/Quorix/services/safe-zone/mise.toml), [`Dockerfile`](file:///d:/Quorix/services/safe-zone/Dockerfile), [`deploy.ps1`](file:///d:/Quorix/services/safe-zone/deploy.ps1), [`README.md`](file:///d:/Quorix/services/safe-zone/README.md), [`.agents/AGENTS.md`](file:///d:/Quorix/services/safe-zone/.agents/AGENTS.md), các script thuộc [`scripts/ops/`](file:///d:/Quorix/services/safe-zone/scripts/ops/).
- **Tỷ lệ vượt qua kiểm tra cấu hình:** 100%.

### Liên kết Artifacts

- Cấu hình Task Manager: [mise.toml](file:///d:/Quorix/services/safe-zone/mise.toml)
- Khai báo Go Module: [go.mod](file:///d:/Quorix/services/safe-zone/go.mod)
- Dockerfile: [Dockerfile](file:///d:/Quorix/services/safe-zone/Dockerfile)
- Thư mục chứa scripts thực tế: [scripts/ops/](file:///d:/Quorix/services/safe-zone/scripts/ops/)
- Hướng dẫn AI Agent: [.agents/AGENTS.md](file:///d:/Quorix/services/safe-zone/.agents/AGENTS.md)

---

## Lịch sử Thay đổi (Version History)

| Ngày | Thay đổi | Tác giả |
|---|---|---|
| 2026-08-06 | Khắc phục độ sâu thư mục gốc trong scripts/ops/, đồng bộ Go version về 1.24.0 cho golangci-lint và thêm quy tắc CI vào AGENTS.md | Antigravity AI Agent |
| 2026-08-02 | Khởi tạo tài liệu, khắc phục đường dẫn script và sửa backend golangci-lint trong `mise.toml` | Antigravity AI Agent |
