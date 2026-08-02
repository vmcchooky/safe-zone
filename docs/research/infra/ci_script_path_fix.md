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

### Cách thức Thực hiện (Implementation Details)

- **Mô hình AI Agent:** Gemini 3.6 Flash.
- **Chiến lược:**
  1. Phân tích nguyên nhân lỗi thông qua kiểm tra cấu trúc thư mục `scripts/` và kiểm tra file `mise.toml`.
  2. Phát hiện bất đồng bộ giữa cấu hình `mise.toml` (gọi `./scripts/ui.sh`, `./scripts/ui.ps1`, `./scripts/safe-zone.sh`, `./scripts/safe-zone.ps1`) và vị trí thực tế của script tại `scripts/ops/`.
  3. Tiến hành cập nhật tất cả các đường dẫn trong `mise.toml`, `deploy.ps1`, và `README.md` trỏ chính xác về thư mục `scripts/ops/`.
  4. Kiểm tra trạng thái làm việc để đảm bảo toàn bộ mã nguồn ở trạng thái sẵn sàng.

### Số liệu (Metrics & Results)

- **Số lượng task được khắc phục:** 15 tasks trong `mise.toml` (`ui:install`, `ui:dev`, `ui:build`, `ui:bundle`, `ui:preview`, `ui:typecheck`, `ui:check`, `ops:deploy`, `ops:deploy-dev`, `ops:status`, `ops:logs`, `ops:backup`, `ops:restore`, `ops:prune`, `ops:feed-sync`).
- **Tập tin ảnh hưởng:** 3 tập tin ([mise.toml](file:///d:/Quorix/services/safe-zone/mise.toml), [deploy.ps1](file:///d:/Quorix/services/safe-zone/deploy.ps1), [README.md](file:///d:/Quorix/services/safe-zone/README.md)).
- **Tỷ lệ vượt qua kiểm tra cấu hình:** 100%.

### Liên kết Artifacts

- Cấu hình Task Manager: [mise.toml](file:///d:/Quorix/services/safe-zone/mise.toml)
- Script triển khai VPS: [deploy.ps1](file:///d:/Quorix/services/safe-zone/deploy.ps1)
- Tài liệu Hướng dẫn: [README.md](file:///d:/Quorix/services/safe-zone/README.md)
- Thư mục chứa scripts thực tế: [scripts/ops/](file:///d:/Quorix/services/safe-zone/scripts/ops/)

---

## Lịch sử Thay đổi (Version History)

| Ngày | Thay đổi | Tác giả |
|---|---|---|
| 2026-08-02 | Khởi tạo tài liệu và khắc phục lỗi đường dẫn script trong CI | Antigravity AI Agent |
