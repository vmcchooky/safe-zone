# Thiết kế: Module DoH (DNS-over-HTTPS) chuyên biệt theo RFC 8484

## 1. Bối cảnh & Mục tiêu

Trước khi tách, toàn bộ xử lý DoH nằm rải rác trong package `internal/dns/resolver`:
handler HTTP trộn lẫn với handler DoT, client upstream DoH (`DoDoH`) và pool
endpoint nằm chung với tầng policy. Soi chiếu RFC 8484 cho thấy nhiều khoảng cách
tuân thủ. Mục tiêu:

- Tách DoH thành module giao thức độc lập `internal/dns/doh`, tương đương cách
  DoT (RFC 7858) được tách thành một concern riêng trong `dot.go`.
- Tách bạch **giao thức** (transport) khỏi **chính sách** (policy): module DoH
  chỉ làm chuyện mã hóa DNS vào/ra HTTP, không biết gì về block list hay ML.
- Khắc phục các khoảng cách tuân thủ RFC 8484.

## 2. Kiến trúc

```
                ┌──────────────────────────────────────────────────────┐
 Client DoH ───►│ internal/dns/doh            internal/dns/resolver    │
 (GET/POST)     │ ┌────────────────┐   QueryBackend  ┌───────────────┐ │   Upstream DoH
                │ │ server.go      │ ───────────────►│ ResolveQuery  │ │ ───────────────►
 Client DoT ───►│ │ (RFC 8484)     │                 │ (policy,      │ │  (Cloudflare &  │
 (TCP TLS)      │ └────────────────┘                 │  block,       │ │   pool failover │
                │ ┌────────────────┐                 │  uncloak)     │ │                 │
                │ │ client.go      │ ◄───────────────└───────────────┘ │                 │
                │ │ upstream.go    │   ForwardDoH (client + pool)      │                 │
                │ │ cache.go       │                                   │                 │
                │ └────────────────┘                                   │                 │
                └──────────────────────────────────────────────────────┘
```

- `server.go` — endpoint HTTP chuẩn RFC 8484 (GET với tham số `dns`
  base64url không padding; POST với body `application/dns-message`),
  chỉ phụ thuộc `miekg/dns` + stdlib + `internal/ratelimit`.
- `client.go` — `Exchange()`: gửi truy vấn lên upstream DoH, kiểm tra
  status 2xx, `Content-Type` và giới hạn 65535 byte của response.
- `upstream.go` — pool endpoint health-checked, failover theo latency,
  probe định kỳ (di chuyển nguyên trạng từ `resolver/upstream.go` cũ).
- `cache.go` — `CacheFreshnessLifetime()`: tính `max-age` cho `Cache-Control`.

- `resolver.ResolveQuery(ctx, query, client)` — pipeline chính sách dùng chung,
  triển khai `doh.QueryBackend`: policy theo client → chặn theo block strategy
  → forward upstream → uncloaking CNAME. Cả DoH và DoT gọi pipeline này, loại
  bỏ toàn bộ bản sao logic trước đây.
- `resolver/dot.go` — handler DoT giữ các concern đặc thù transport: panic
  recovery, rate limiter riêng, IP từ kết nối TLS, timeout 3s.

## 3. Ma trận tuân thủ RFC 8484

| Điều khoản | Yêu cầu | Trước | Sau |
|---|---|---|---|
| §4.1 | Server `MUST` hỗ trợ cả GET và POST | Đạt | Đạt (có test riêng cho từng method) |
| §4.1/§6 | `dns` param là base64url `MUST NOT` có padding | Đạt (RawURLEncoding) | Đạt + test từ chối padding |
| §4.2.1 | Lỗi DNS (SERVFAIL) đi trong HTTP 200 | Đạt | Đạt + test |
| §4.2.1 | Response không 2xx `MUST NOT` chứa DNS reply | Đạt | Đạt |
| HTTP semantics | Method lạ → `405` + `Allow: GET, POST` | ❌ (400 text) | ✅ 405 + Allow |
| §4.1 | POST sai `Content-Type` → `415` | ❌ (400) | ✅ 415 |
| §6 | Body > 65535 byte → `413` | ❌ (400 do truncation) | ✅ 413 qua `http.MaxBytesError` |
| §5.1 | `SHOULD` gắn freshness lifetime tường minh | ❌ (không có header) | ✅ `Cache-Control: private, max-age=N` |
| §5.1 | `max-age` ≤ TTL nhỏ nhất trong Answer | ❌ | ✅ |
| §5.1 + RFC 2308 | Không Answer + có SOA: `MUST NOT` vượt `SOA MINIMUM` | ❌ | ✅ `min(SOA TTL, SOA Minttl)` |
| §5.1 | Response cá nhân hóa theo client không được shared cache dùng chung | ❌ | ✅ `private` giữ browser cache, chặn shared cache |
| §6 | Client kiểm tra `Content-Type` response upstream | ❌ | ✅ từ chối captive portal HTML |

Ghi chú thiết kế về `private`: resolver chặn theo từng client (IP/client_id),
nên response cho cùng một URL GET có thể khác nhau giữa các client. Nếu không
đánh dấu `private`, một HTTP cache dùng chung (Caddy/CDN) có thể trả câu trả
lời "allowed" của client A cho client B mà policy chặn domain đó — vừa sai
chính sách vừa né lệnh chặn.

## 4. Những gì không đổi

- Không thêm biến môi trường mới; `SAFE_ZONE_UPSTREAM_DOH_URLS`,
  `SAFE_ZONE_DNS_BLOCK_*`, rate limiting theo tier vận hành như cũ.
- Header HSTS vẫn do Caddy edge phát hành (ADR 0004); resolver không nhân bản.
- JSON status/metrics endpoint giữ nguyên shape (`upstream_doh_failures_total`,
  `upstream_doh.endpoints`...).
- Tệp `resolver_test.go` cũ vẫn `//go:build ignore`; phạm vi test sống nằm ở
  `doh/server_test.go`, `doh/client_test.go`, `resolver/pipeline_test.go`.
