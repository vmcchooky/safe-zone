# Specification: Additive Sync Limitation & Source-Aware Sync

## 1. Hiện trạng (Current State)
Hiện tại, luồng `feed-sync` tải danh sách các domain độc hại từ một nguồn và lưu trực tiếp vào Redis thông qua kiểu dữ liệu Set (`safe-zone:threat:feed`).
- Nếu sử dụng cờ `-replace=true` (mặc định), toàn bộ Set sẽ bị xóa trước khi ghi. Điều này gây mất dữ liệu nếu hệ thống sử dụng nhiều nguồn (multi-source).
- Nếu sử dụng cờ `-replace=false` (cơ chế đồng bộ lũy kế - additive sync), các domain được thêm vào liên tục. Khi một domain bị gỡ bỏ khỏi nguồn upstream (do là false positive hoặc threat đã hết hạn), hệ thống không tự động xóa nó khỏi Redis.
- **Hệ quả**: Dẫn đến sự tích tụ dữ liệu rác (garbage accumulation) và duy trì false-positives dài hạn.

## 2. Mục tiêu (Goal)
Khắc phục cơ chế đồng bộ lũy kế bằng cách chuyển đổi cơ chế lưu trữ sang mô hình **Indicator Expiry (TTL)** kết hợp **Source-Aware Sync**:
1. Hỗ trợ đồng bộ nhiều nguồn dữ liệu cùng lúc mà không ghi đè lên nhau.
2. Tự động loại bỏ các tên miền không còn được báo cáo bởi các nguồn sau một khoảng thời gian nhất định (ví dụ: 14 ngày).

## 3. Giải pháp Đề xuất (Proposed Design)

Sử dụng cấu trúc **Redis Sorted Set (ZSET)** thay thế cho Set thông thường.
- **Key**: `safe-zone:threat:feed`
- **Member**: Tên miền đã chuẩn hóa (normalized domain).
- **Score**: Unix timestamp của thời điểm hết hạn (Expiration Timestamp).

### Cơ chế hoạt động:
1. **Quá trình Sync (`cmd/feed-sync`)**:
   - Thêm tham số/cấu hình xác định TTL cho mỗi nguồn (ví dụ: `SAFE_ZONE_FEED_TTL_DAYS=14`).
   - Thay vì dùng `SADD`, sử dụng `ZADD` với `score = CurrentTimestamp + TTL`.
   - Khi chạy lệnh `ZADD`, nếu domain đã tồn tại (do nguồn khác cung cấp hoặc từ lần sync trước), điểm số (thời gian hết hạn) của nó sẽ được gia hạn.
   - Bỏ qua thao tác xóa toàn bộ key `-replace` khi sync.

2. **Cơ chế Dọn dẹp (Cleanup)**:
   - Vào cuối mỗi lần thực thi `feed-sync` (hoặc cấu hình thành một cron job riêng biệt), thực thi lệnh:
     `ZREMRANGEBYSCORE safe-zone:threat:feed -inf <CurrentTimestamp>`
   - Thao tác này sẽ tự động dọn sạch tất cả các domain không được bất kỳ nguồn nào update trong suốt khoảng thời gian TTL vừa qua.

3. **Quá trình Đánh giá (Risk Service)**:
   - Trong `internal/risk.Service`, thay vì sử dụng `SISMEMBER` để kiểm tra domain, chuyển sang sử dụng `ZSCORE safe-zone:threat:feed <domain>`.
   - Nếu Redis trả về kết quả (domain tồn tại) và có thể kiểm tra thêm `score >= CurrentTimestamp` (để đảm bảo tính chính xác phòng khi chưa dọn dẹp kịp).
   - Kiểm tra suffix (tìm domain gốc) tiếp tục áp dụng Pipeline với `ZSCORE` thay vì `SISMEMBER`.

## 4. Ưu điểm
- **Hiệu năng cao**: `ZSCORE` tra cứu với độ phức tạp $O(1)$, hoàn toàn không gây chậm trễ cho luồng xử lý DNS / API.
- **Mở rộng dễ dàng**: Tương thích tốt với mọi số lượng nguồn dữ liệu. Các nguồn bổ sung cùng một domain chỉ đơn giản là gia hạn thời gian sống (TTL) của domain đó.
- **Tự động làm sạch**: Dễ dàng dọn dẹp các mục cũ không còn giá trị bằng các tính năng native của Redis (`ZREMRANGEBYSCORE`), tránh false-positives tồn tại mãi mãi.

## 5. Kế hoạch Triển khai (Implementation Steps)

1. **Sửa đổi lệnh Sync (`cmd/feed-sync` và `internal/feed/sync.go`)**:
   - Thêm cờ `--ttl-days` (mặc định 14).
   - Cập nhật pipeline Redis từ `SADD` sang `ZADD`. Tính toán score tương ứng.
   - Thêm pipeline thực thi `ZREMRANGEBYSCORE` để xóa domain rác.

2. **Cập nhật Risk Service (`internal/risk/service.go`)**:
   - Đổi `SISMEMBER` sang `ZSCORE` trong logic `analyze()`.
   - Cập nhật quá trình check fallback cho các Subdomains.

3. **Cập nhật Unit / Integration Tests**:
   - Chỉnh sửa Redis mock / test setup để chèn dữ liệu dưới dạng ZSET.
   - Bổ sung test cases: Domain vừa mới hết hạn (score < current time) không được phép `Match`.
