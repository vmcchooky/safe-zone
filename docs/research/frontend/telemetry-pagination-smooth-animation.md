# Loại bỏ Hiện tượng Giật rung khi Phân trang Bảng Telemetry

> **Tài liệu Living Document** — Cập nhật đồng bộ mỗi khi có thay đổi.
> Tuân thủ quy tắc tại `.agents/AGENTS.md` Section 5.

## Tóm tắt (Abstract)

Bảng Network Telemetry từng xảy ra hiện tượng giật rung mạnh ("kéo xuống rồi giật ngược lên") mỗi khi người dùng nhấn Next hoặc Previous. Nguyên nhân bắt nguồn từ việc thẻ `<tbody>` sử dụng `<AnimatePresence mode="sync">` với hiệu ứng `exit={{ opacity: 0 }}` trên từng hàng `motion.tr`, khiến 12 hàng của trang cũ và 12 hàng của trang mới tồn tại đồng thời trên DOM trong thời gian chạy animation, làm chiều cao bảng phình to đột biến thêm ~924 px rồi đột ngột co lại. Bản sửa loại bỏ `AnimatePresence` bọc đa hàng, cố định số hàng hiển thị, bổ sung hiệu ứng chuyển tiếp độ mờ (`opacity: 0.60`) trong quá trình SWR xác thực dữ liệu và đơn giản hóa việc khôi phục vị trí cuộn sang một animation frame duy nhất. Kiểm thử tự động trên Playwright ghi nhận bảng giữ nguyên 12 hàng, chiều cao không bị phình to và độ lệch thanh phân trang đạt $\le 8\text{ px}$.

---

## Tối ưu Trải nghiệm Phân trang Telemetry

### Mục tiêu (Objectives)

Mục tiêu là triệt tiêu hoàn toàn hiện tượng co giật layout (layout jitter) khi lật trang dữ liệu telemetry, đồng thời giữ nguyên tính thẩm mỹ với hiệu ứng tải mượt mà cho các hàng dữ liệu mới. Bảng phải duy trì kích thước khung tĩnh ổn định, thanh phân trang luôn nằm trong tầm nhìn của người dùng và không kích hoạt cảnh báo DOM console từ Framer Motion.

### Phương pháp & Lý do (Methodology & Rationale)

| Quyết định | Phương pháp chọn | Các phương pháp thay thế | Lý do |
|---|---|---|---|
| Cấu trúc hàng DOM | Thay thế trực tiếp 12 hàng tĩnh, loại bỏ `AnimatePresence` đa hàng trên `<tbody>` | Giữ `AnimatePresence` với `mode="popLayout"` hoặc tăng thời gian ghìm cuộn rAF | Trong bảng HTML (`<table>`), `popLayout` không thể tính toán tuyệt đối các ô `<td>` chuẩn xác. `mode="sync"` nhân đôi số hàng lên 24, gây giãn layout 924 px. Thay thế trực tiếp giữ số hàng cố định 12, triệt tiêu nguồn gốc gây co giãn. |
| Hiệu ứng tải (Loading state) | Hiệu ứng chuyển tiếp độ mờ `opacity: 0.60` khi `refreshingRecent = true` trên `<tbody>` kết hợp stagger fade-in cho hàng mới | Skeleton placeholder thay thế toàn bộ bảng; spinner che toàn màn hình | Skeleton thay thế toàn bộ bảng sẽ làm mất nội dung trước đó và gây gián đoạn thị giác. Chuyển tiếp mờ nhẹ báo hiệu trạng thái nạp dữ liệu một cách tinh tế mà không dịch chuyển vị trí các cột. |
| Khôi phục vị trí cuộn | Gán lại scroll position và nhả tham chiếu trong một animation frame duy nhất | Vòng lặp `requestAnimationFrame` cưỡng bức kéo dài 900 ms | Khi chiều cao DOM không còn bị biến thiên 924 px giữa chừng, vị trí cuộn không còn bị trình duyệt kéo trôi. Vòng lặp rAF 900 ms trước đây trở nên dư thừa và là nguyên nhân trực tiếp gây co giật màn hình khi liên tục ghi đè `scrollTop`. |

### Cách thức Thực hiện (Implementation Details)

Trong [`ui/src/routes/telemetry/TelemetryPage.tsx`](ui/src/routes/telemetry/TelemetryPage.tsx):
1. Loại bỏ hằng số `PAGINATION_SCROLL_SETTLE_MS = 900`.
2. Đơn giản hóa hook `useLayoutEffect`: khôi phục vị trí cuộn đã lưu trong `paginationScrollTopRef` và xóa tham chiếu ngay sau 1 frame với `requestAnimationFrame`.
3. Bỏ bọc `<AnimatePresence mode="sync">` quanh `<tbody>`.
4. Bổ sung lớp hiệu ứng `transition-opacity duration-200` trên `<tbody>`, kích hoạt `opacity-60 pointer-events-none` khi `refreshingRecent` mang giá trị `true`.
5. Đặt khóa định danh duy nhất cho từng hàng `motion.tr`: `key={`${page}-${entry.id}-${entry.domain}`}` với hiệu ứng `initial={{ opacity: 0 }}`, `animate={{ opacity: 1 }}` và độ trễ xuất hiện `delay: index * 0.012`.

Công việc được thực hiện bởi AI agent Antigravity điều phối kiểm thử qua Playwright E2E test suite và trình biên dịch TypeScript.

### Số liệu (Metrics & Results)

| Chỉ số | Trước khi sửa | Sau khi sửa |
|---|---:|---:|
| Số lượng hàng `<tr>` đồng thời khi lật trang | 24 hàng | 12 hàng |
| Biến thiên chiều cao bảng khi lật trang | +924 px | 0 px |
| Thời gian ghìm cuộn cưỡng bức (settle loop) | 900 ms | 1 frame (~16 ms) |
| Độ lệch vị trí thanh phân trang (`scrollTop` vs `maxScroll`) | 0 - 8 px (nhưng bị rung giật 900 ms) | $\le 8\text{ px}$ (mượt mà, không rung giật) |
| Kết quả Playwright `tests/telemetry.spec.ts` | Pass (16,4 giây) | Pass (10,4 giây) |
| Kết quả Playwright `tests/extreme-data.spec.ts` | Pass (9/9 tests) | Pass (9/9 tests) |
| TypeScript check & Vite build | Pass | Pass |

Lệnh kiểm chứng hồi quy:

```bash
npx playwright test tests/telemetry.spec.ts
npx playwright test tests/extreme-data.spec.ts
npm run check
```

### Liên kết Artifacts

- [`ui/src/routes/telemetry/TelemetryPage.tsx`](ui/src/routes/telemetry/TelemetryPage.tsx)
- [`ui/tests/telemetry.spec.ts`](ui/tests/telemetry.spec.ts)
- [`ui/tests/extreme-data.spec.ts`](ui/tests/extreme-data.spec.ts)

---

## Lịch sử Thay đổi (Version History)

| Ngày | Thay đổi | Tác giả |
|---|---|---|
| 2026-08-31 | Loại bỏ `AnimatePresence` gây nhân đôi hàng bảng Telemetry, bổ sung hiệu ứng loading mờ nhẹ và triệt tiêu vòng lặp ghìm scroll 900 ms | Antigravity AI |
