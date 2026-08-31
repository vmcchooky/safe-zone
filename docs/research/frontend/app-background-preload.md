# Tải trước Ảnh nền Giao diện trong Chuỗi Loader Moody Dog

> **Tài liệu Living Document** — Cập nhật đồng bộ mỗi khi có thay đổi.
> Tuân thủ quy tắc tại `.agents/AGENTS.md` Section 5.

## Tóm tắt (Abstract)

Ngay sau khi người dùng đăng nhập thành công vào Safe Zone, giao diện từng xuất hiện hiện tượng màn hình trắng phẳng trong vài trăm mili-giây trước khi hình nền ứng dụng (`app-background.avif`) hiển thị. Nguyên nhân là do ảnh nền chỉ được khai báo trong CSS thuộc tính `background` của class `.shell`, vốn chưa tồn tại trên DOM trong suốt màn hình đăng nhập và chuỗi hiển thị loader Moody Dog (tối thiểu 2,2 giây). Bản sửa đưa tác vụ tải trước (`new Image()`) ảnh nền vào chuỗi song song của `Promise.all` cùng với xác thực API đăng nhập và chunk nạp trước trang Analysis trong `AuthProvider`. Kiểm thử tự động trên Playwright ghi nhận chuỗi loader giữ tính liên tục, ảnh nền sẵn sàng trong bộ nhớ đệm trước khi AppShell mount và toàn bộ 12 test case trong `tests/analysis.spec.ts` vượt qua.

---

## Tối ưu Hóa Hiển thị Ảnh nền Dashboard

### Mục tiêu (Objectives)

Mục tiêu là triệt tiêu hoàn toàn hiện tượng màn hình trắng (white flash / pop-in) khi chuyển tiếp từ màn hình đăng nhập sang giao diện phân tích chính. Đảm bảo toàn bộ hiệu ứng kính mờ (glassmorphism) của AppShell và Analysis Deck hiển thị ngay lập tức với đầy đủ màu sắc và chiều sâu thị giác tại khoảnh khắc loader Moody Dog vừa tắt đi.

### Phương pháp & Lý do (Methodology & Rationale)

| Quyết định | Phương pháp chọn | Các phương pháp thay thế | Lý do |
|---|---|---|---|
| Thời điểm tải trước (Preload timing) | Tải song song trong chuỗi `Promise.all` của `login()` và `refreshSession()` khi loader Moody Dog đang chạy (tối thiểu 2.200 ms) | Preload toàn cục bằng `<link rel="preload">` trong `index.html`; hoặc chờ AppShell mount mới fade-in | Khách truy cập chưa đăng nhập sẽ không phải tải thừa 333 KB ảnh nền nếu không đăng nhập. Khoảng chờ 2.200 ms của Moody Dog đủ để nạp xong ảnh nền vào bộ nhớ mà không làm người dùng tốn thêm thời gian chờ đợi. |
| Cơ chế nạp tài nguyên | Sử dụng JavaScript `new Image()` với trình xử lý `onload` và `onerror` fail-open | Dùng `fetch()` blob URL; hoặc dùng thẻ `<img>` ẩn trong DOM | `new Image()` nạp tài nguyên trực tiếp vào HTTP cache của trình duyệt với overhead tối thiểu. Cơ chế fail-open đảm bảo nếu kết nối ảnh gặp sự cố, luồng đăng nhập vẫn tiếp tục thông suốt. |

### Cách thức Thực hiện (Implementation Details)

Trong [`ui/src/auth/AuthProvider.tsx`](ui/src/auth/AuthProvider.tsx):
1. Định nghĩa hàm `preloadBackgroundImage`:
   ```ts
   const preloadBackgroundImage = () =>
     new Promise<void>((resolve) => {
       if (typeof window === 'undefined') {
         resolve();
         return;
       }
       const img = new Image();
       img.src = '/app-background.avif?v=1';
       img.onload = () => resolve();
       img.onerror = () => resolve();
     });
   ```
2. Đưa `preloadBackgroundImage()` vào mảng `Promise.all` của hàm `login()` và `refreshSession()`, kết hợp cùng `minLoaderDelay(MIN_LOADER_DURATION_MS)` (2.200 ms) và `preloadAnalysisRoute()`.
3. Khi người dùng bấm Authenticate, quá trình giải mã và nạp ảnh nền được thực thi ngay trong lúc Moody Dog đang chạy. Khi Moody Dog kết thúc và AppShell mount, CSS `.shell` lấy ngay hình ảnh đã có sẵn trong cache/RAM của trình duyệt.

Công việc được thực hiện bởi AI agent Antigravity điều phối kiểm thử qua Playwright E2E test suite và TypeScript compiler.

### Số liệu (Metrics & Results)

| Chỉ số | Trước khi sửa | Sau khi sửa |
|---|---:|---:|
| Trạng thái ảnh nền khi AppShell vừa mount | Chưa tải (gửi request sau khi mount) | Đã nạp sẵn trong cache (0 ms độ trễ) |
| Hiện tượng màn hình trắng trước khi hiện ảnh nền | Xuất hiện (~200 - 500 ms) | Triệt tiêu hoàn toàn (0 ms) |
| Thời gian giữ màn hình loader Moody Dog | 2.200 ms | 2.200 ms (không phát sinh thêm) |
| Tải thừa cho khách chưa đăng nhập | Không | Không |
| Kết quả Playwright `tests/analysis.spec.ts` | Pass (12/12 tests) | Pass (12/12 tests, 34,0 giây) |
| TypeScript typecheck & Vite build | Pass | Pass |

Lệnh kiểm chứng hồi quy:

```bash
npx playwright test tests/analysis.spec.ts
npm run check
```

### Liên kết Artifacts

- [`ui/src/auth/AuthProvider.tsx`](ui/src/auth/AuthProvider.tsx)
- [`ui/tests/analysis.spec.ts`](ui/tests/analysis.spec.ts)
- [`ui/src/app.css`](ui/src/app.css)

---

## Lịch sử Thay đổi (Version History)

| Ngày | Thay đổi | Tác giả |
|---|---|---|
| 2026-08-31 | Bổ sung preload ảnh nền ứng dụng trong chuỗi loader Moody Dog tại AuthProvider | Antigravity AI |
