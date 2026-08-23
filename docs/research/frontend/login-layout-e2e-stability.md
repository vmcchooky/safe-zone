# Ổn định E2E cho Login Card Animation

> **Tài liệu Living Document** — Cập nhật đồng bộ mỗi khi có thay đổi.
> Tuân thủ quy tắc tại `.agents/AGENTS.md` Section 5.

## Tóm tắt (Abstract)

Playwright test của login screen từng đo vị trí card ngay sau khi element xuất hiện, trong khi Framer Motion vẫn cập nhật `transform` theo từng animation frame. CI hậu-merge ngày 2026-08-23 thất bại cả ba lần thử với offset lần lượt là 13,61 px, 29,54 px và 12,90 px so với ngưỡng một chiều 12 px. Cùng commit trước đó pass trên PR CI và local, cho thấy lỗi phụ thuộc thời điểm lấy mẫu thay vì layout tĩnh. Bản sửa chờ computed `transform` trở về `none` trước khi đo bounding box. Assertion mới sử dụng độ lệch tuyệt đối và ngưỡng 1 px để kiểm tra trạng thái cuối thay vì một frame trung gian. Test mục tiêu pass 10/10 lần liên tiếp với `CI=true` sau thay đổi.

## Ổn định Login Layout Test

### Mục tiêu (Objectives)

Mục tiêu là biến test login layout thành phép đo trạng thái ổn định, không phụ thuộc tốc độ runner hoặc thời điểm spring animation được lấy mẫu. Test vẫn phải phát hiện card quá cao, card lệch tâm và việc Moody Dog hoặc background image xuất hiện ngoài ý muốn. Bản sửa chỉ thay đổi test synchronization; UI component, motion configuration và product behavior được giữ nguyên.

### Phương pháp & Lý do (Methodology & Rationale)

| Quyết định | Phương pháp chọn | Các phương pháp thay thế | Lý do |
|---|---|---|---|
| Điểm đồng bộ | Chờ computed `transform: none` trên login card | `waitForTimeout`; chỉ chờ visible; tắt animation toàn test | `visible` xảy ra trước khi spring kết thúc. Computed style phản ánh đúng điều kiện cần đo và không phụ thuộc thời lượng cố định. |
| Ngưỡng vị trí | `Math.abs(offsetFromCentered) <= 1` px | Giữ phép so sánh một chiều; tăng ngưỡng lên 30 px | Độ lệch có thể âm hoặc dương. Ngưỡng 1 px kiểm tra layout tĩnh, còn tăng tolerance sẽ che sai lệch thật. |
| Phạm vi sửa | Test synchronization | Bỏ animation trong component; đổi CSS layout | Product UI không gây lỗi; thay đổi component sẽ mở rộng phạm vi và làm mất entrance animation hiện hữu. |
| Xác minh flake | Lặp test mục tiêu 10 lần với một CI worker | Một lần local; chỉ rerun GitHub job | Lặp lại tăng khả năng phát hiện timing race trước khi push mà không tạo thay đổi external. |

### Cách thức Thực hiện (Implementation Details)

`ui/tests/analysis.spec.ts` lấy locator `login-card`, xác nhận element visible rồi dùng Playwright web-first assertion `toHaveCSS('transform', 'none')`. Playwright tự poll cho tới khi Framer Motion hoàn tất hoặc timeout. Sau điểm đồng bộ, test đo `getBoundingClientRect()` và kiểm tra chiều cao dưới 500 px cùng độ lệch tuyệt đối không quá 1 px.

AI agent sử dụng Codex GPT-5 với chiến lược đọc failed CI log, đối chiếu component animation và thay assertion timing bằng state-based synchronization. Không sử dụng subagent; số lượng subagent là 0. Người dùng đã cho phép xử lý CI failure trong quy trình merge, còn quality control gồm repeat test, full UI suite, GitHub PR CI và CI hậu-merge.

### Số liệu (Metrics & Results)

| Chỉ số | Kết quả |
|---|---:|
| CI retries thất bại trước sửa | 3/3 |
| Offset quan sát trước sửa | 13,61 px; 29,54 px; 12,90 px |
| Ngưỡng cũ | `offset <= 12` px |
| Ngưỡng mới | `abs(offset) <= 1` px sau animation |
| Repeat test với `CI=true` | 10/10 pass |
| Full Playwright suite với `CI=true` | 4/4 pass trong 20,8 giây |
| TypeScript typecheck | Pass |
| UI production behavior thay đổi | 0 |

Lệnh tái lập repeat test:

```powershell
$env:CI='true'
npm --prefix ui exec -- playwright test --grep 'keeps the plain login card' --repeat-each=10
```

### Liên kết Artifacts

- `ui/tests/analysis.spec.ts`
- `ui/src/components/LoginScreen.tsx`
- `ui/playwright.config.ts`
- GitHub Actions run `32630306226`

---

## Lịch sử Thay đổi (Version History)

| Ngày | Thay đổi | Tác giả |
|---|---|---|
| 2026-08-23 | Thay timing-based login layout assertion bằng animation-state synchronization | Codex GPT-5 |
