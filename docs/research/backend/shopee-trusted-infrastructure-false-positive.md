# Khắc phục false positive trên hạ tầng Shopee Mobile

> **Tài liệu Living Document** — Cập nhật đồng bộ mỗi khi có thay đổi.
> Tuân thủ quy tắc tại `.agents/AGENTS.md` Section 5.

## Tóm tắt (Abstract)

Safe-Zone từng phân loại một số hostname dưới `shopeemobile.com` là `MALICIOUS/100` dù chúng thuộc hạ tầng Shopee. Kết quả live trước bản vá cho thấy điểm số đến từ lexical scoring: domain dài, từ khóa thương hiệu Shopee bị xem là giả mạo và entropy bị xem là dấu hiệu DGA; adblock không phải nguồn của quyết định này. Bản vá bổ sung `shopeemobile.com` vào các domain thay thế của trusted brand Shopee để loại bỏ hai tín hiệu sai liên quan tới brand spoofing và DGA. Revision của thuật toán phân tích được tăng để các entry Redis được tạo bởi revision cũ không tiếp tục phục vụ kết quả sai. Ba hostname quan sát từ production được đưa vào regression test. Domain CDN dùng chung `baishan-cloud.net` không được thêm vào trusted brand vì ownership của zone không thuộc Shopee và việc tin cậy toàn suffix sẽ mở rộng phạm vi bỏ qua kiểm tra quá mức cần thiết.

## Khắc phục false positive Shopee Mobile

### Mục tiêu (Objectives)

- Phân loại các hostname đã xác minh dưới `shopeemobile.com` là `SAFE` ở lexical pipeline.
- Không làm suy yếu phát hiện phishing trên các domain không thuộc Shopee nhưng chứa từ khóa `shopee`.
- Vô hiệu hóa kết quả cache được tạo theo tập trusted brand cũ sau khi triển khai revision mới.
- Giữ `baishan-cloud.net` ngoài trusted suffix vì đây là hạ tầng CDN dùng chung.

### Phương pháp & Lý do (Methodology & Rationale)

| Quyết định | Phương pháp chọn | Các phương pháp thay thế | Lý do |
|---|---|---|---|
| Nhận diện ownership | Thêm `shopeemobile.com` vào `AltDomains` của brand Shopee | Adblock exception; exact allow override; tắt brand spoofing | Kết quả sai xuất phát từ lexical brand scoring, không phải adblock. Trusted brand suffix giải quyết đúng nguồn tín hiệu và vẫn giới hạn trong zone do Shopee vận hành. |
| Xử lý cache | Tăng `analysisAlgorithmRevision` | Flush toàn Redis; chờ TTL 6 giờ; xóa từng key | Revision mới khiến reader từ chối entry cũ mà không xóa dữ liệu Redis không liên quan. |
| CDN Baishan | Không trust toàn `baishan-cloud.net` | Thêm suffix CDN vào brand Shopee; tắt TLS inspection | CDN dùng chung không chứng minh mọi subdomain là tài sản Shopee. Exact operator override có phạm vi nhỏ hơn nếu hostname cụ thể được xác minh từ traffic của thiết bị. |
| Kiểm thử | Regression test trên ba hostname production | Chỉ kiểm tra root domain; kiểm thử thủ công | Hostname thực tế bao phủ subdomain sâu, chữ số, dấu gạch ngang và độ dài đã gây cộng điểm sai. |

### Cách thức Thực hiện (Implementation Details)

`internal/analysis/brand.go` bổ sung `shopeemobile.com` vào `AltDomains` của record `shopee`. Hàm `IsTrustedBrandSuffix` vì thế nhận diện cả root và subdomain của zone này; `CheckBrandSpoofingWithBrands` không gắn nhãn brand spoofing, đồng thời entropy gate không áp dụng tín hiệu DGA cho hostname trusted.

`internal/risk/service.go` đổi `analysisAlgorithmRevision` từ `2026-06-smart-osint-v2` sang `2026-09-trusted-brand-v3`. Cache key không đổi, nhưng validation của `analysisCacheEntry` từ chối revision cũ và ghi đè bằng kết quả mới khi domain được phân tích lại.

Quá trình khảo sát dùng Codex dựa trên GPT-5 với prompt truy nguyên source-to-result, không sử dụng subagent và không dùng voting. Kiểm soát chất lượng gồm đối chiếu live API, DNS/CNAME, phản hồi HTTP, nguồn công khai liên kết Shopee với `shopeemobile.com`, code review tại pipeline lexical và test package Go. Người vận hành xác nhận sự cố từ traffic của thiết bị; AI agent chỉ chọn phạm vi trust tối thiểu phù hợp với bằng chứng.

### Số liệu (Metrics & Results)

| Chỉ số | Trước bản vá | Sau bản vá cục bộ |
|---|---:|---:|
| `ccms.dr-wan.shopeemobile.com` | `MALICIOUS`, score 100 | `SAFE`, regression test pass |
| `gs1b.sgw.shopeemobile.com` | `MALICIOUS`, score 100 | `SAFE`, regression test pass |
| `mp-others-sg-sg7-19.dr-wan.shopeemobile.com` | `MALICIOUS`, score 100 trong telemetry | `SAFE`, regression test pass |
| Hostname regression | 0 | 3 |
| Package test | Chưa áp dụng | 3/3 package pass |

Lệnh tái kiểm chứng:

```bash
go test ./internal/analysis ./internal/risk ./internal/dns/resolver -count=1
```

Kết quả tại ngày 2026-09-06: `internal/analysis` pass trong 3,983 giây; `internal/risk` pass trong 21,974 giây; `internal/dns/resolver` pass trong 4,306 giây.

### Liên kết Artifacts

- `internal/analysis/brand.go`
- `internal/analysis/analysis_test.go`
- `internal/analysis/brand_test.go`
- `internal/risk/service.go`
- Nguồn ShopeePay sử dụng asset từ `deo.shopeemobile.com`: <https://product.shopeepay.co.id/products/spl-promotional-widget/web>
- Dữ liệu hạ tầng ghi nhận `ccms.dr-wan.shopeemobile.com` thuộc ứng dụng Shopee: <https://www.netify.ai/resources/domains/shopeemobile.com>

---

## Lịch sử Thay đổi (Version History)

| Ngày | Thay đổi | Tác giả |
|---|---|---|
| 2026-09-06 | Bổ sung phân tích nguyên nhân, bản vá trusted brand, cache revision và regression metrics | Codex (GPT-5), human-in-the-loop |
