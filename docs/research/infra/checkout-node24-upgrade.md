# Nâng GitHub Actions checkout lên Node.js 24

> **Tài liệu Living Document** — Cập nhật đồng bộ mỗi khi workflow checkout thay đổi.
> Tuân thủ quy tắc tại `.agents/AGENTS.md` Section 5.

## Tóm tắt (Abstract)

GitHub Actions phát cảnh báo deprecation tại toàn bộ CI jobs vì `actions/checkout@v4` dùng runtime Node.js 20. Workflow vẫn pass do GitHub-hosted runner cưỡng chế action chạy trên Node.js 24, nhưng trạng thái này phụ thuộc lớp tương thích tạm thời của nền tảng. Thay đổi nâng hai checkout step lên `actions/checkout@v6`, phiên bản sử dụng Node.js 24 và tách persisted credentials khỏi repository Git config. Phạm vi chỉ gồm `.github/workflows/ci.yml`; task graph, permissions và Docker build arguments không đổi. Pull request CI là phép kiểm tra quyết định vì action chỉ thực thi trên GitHub runner.

## Công việc: checkout Node.js 24

### Mục tiêu (Objectives)

1. Loại bỏ annotation deprecation Node.js 20 khỏi quality job và bốn Docker build jobs.
2. Giữ nguyên `contents: read`, trigger, matrix và task graph hiện hữu.
3. Xác nhận `actions/checkout@v6` tương thích với GitHub-hosted `ubuntu-latest` đang dùng trong repository.

### Phương pháp & Lý do (Methodology & Rationale)

| Quyết định | Phương pháp chọn | Các phương pháp thay thế | Lý do |
| --- | --- | --- | --- |
| Version checkout | Nâng major tag từ `@v4` lên `@v6` | Giữ `@v4`; dùng `@v5`; pin full commit SHA | `@v6` xử lý trực tiếp Node.js 20 deprecation và cải thiện credential isolation. `@v5` cũng dùng Node.js 24 nhưng không có thay đổi credential của v6. Full SHA giảm rủi ro tag mutation nhưng repository chưa có Dependabot để tự động cập nhật SHA. |
| Phạm vi PR | Chỉ sửa checkout steps và R&D provenance | Gộp thay đổi feature hoặc runner config | PR nhỏ giúp CI xác minh riêng compatibility của action. |
| Runner | Giữ `ubuntu-latest` GitHub-hosted | Chuyển self-hosted | Repository chưa khai báo self-hosted runner; thay runner làm tăng phạm vi và yêu cầu vận hành ngoài mục tiêu cảnh báo. |

### Cách thức Thực hiện (Implementation Details)

Hai dòng `uses: actions/checkout@v4` trong quality và Docker matrix được đổi thành `uses: actions/checkout@v6`. Không thêm credential, không thay `persist-credentials`, không mở rộng GitHub token permissions và không sửa source code sản phẩm.

AI agent sử dụng Codex (GPT-5) với chiến lược đối chiếu annotation CI hậu-merge, thu hẹp diff ở workflow boundary và dùng pull request CI làm compatibility test. Không sử dụng subagent; số lượng subagent là 0. Human-in-the-loop đã phê duyệt push/PR/merge, còn deploy, restart và staging traffic vẫn giữ checkpoint xác nhận riêng.

### Số liệu (Metrics & Results)

| Chỉ số | Trước thay đổi | Mục tiêu/Kết quả |
| --- | --- | --- |
| Checkout steps dùng Node.js 20 action | 2/2 step dùng `@v4` | 0/2 step |
| Annotation Node.js 20 trên CI hậu-merge `32632860971` | 5 jobs | 0 jobs trên PR CI |
| Workflow permissions | `contents: read` | Không đổi |
| Product source files thay đổi | 0 | 0 |
| Subagent | 0 | 0 |

Runner self-hosted hoặc local `act` cũ cần được nâng riêng nếu được đưa vào scope sau này. `actions/checkout@v6` yêu cầu runner mới hơn cho trường hợp container action cần truy cập persisted credentials; workflow hiện tại không dùng container action sau checkout.

### Liên kết Artifacts

- Workflow: `.github/workflows/ci.yml`
- CI cảnh báo gốc: GitHub Actions run `32632860971`
- Upstream action: `https://github.com/actions/checkout`

---

## Lịch sử Thay đổi (Version History)

| Ngày | Thay đổi | Tác giả |
| --- | --- | --- |
| 2026-08-23 | Nâng hai checkout steps từ v4 lên v6 và ghi nhận trade-off | Codex (GPT-5) |
