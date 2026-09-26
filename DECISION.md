# Safe-Zone Decision Memory

> **Living project memory.** File này lưu các quyết định đã được chấp nhận, bằng chứng và hệ quả vận hành. Mọi AI agent hoặc kỹ sư làm việc trên dự án phải đọc entry liên quan trước khi thay đổi hành vi an toàn, policy, threat feed hoặc cơ chế giảm false positive.
>
> File này không thay thế mã nguồn, test hoặc tài liệu kỹ thuật. Khi có mâu thuẫn, mã nguồn và test là bằng chứng hiện hành; phải cập nhật entry quyết định trong cùng thay đổi khi phát hiện drift.

## Cách dùng

- Tìm entry theo ngày, subsystem, từ khóa hoặc commit trước khi đọc toàn bộ file.
- Một entry có thể có trạng thái `accepted`, `superseded` hoặc `provisional`.
- Khi quyết định ảnh hưởng security behavior, cache, feed, policy hoặc false-positive handling, phải nêu entry tương ứng trong kế hoạch, review hoặc báo cáo triển khai.
- Không ghi secret, token, password, private key, dữ liệu khách hàng hoặc raw runtime data vào file này.
- Khi một quyết định cũ bị thay thế, giữ lại entry cũ ở trạng thái `superseded` và thêm entry mới; không xóa lịch sử.

---

## 2026-09-25 - CDN false-positive hardening: keep the deployed guard, close self-service detection gaps

**Status:** accepted

**Context:**

Safe-Zone đã audit độc lập trên commit `bb8c4d0`, merge/deploy `6f69f5e`, và production build `6f69f5e` (build time `2026-09-23T16:19:04Z`). Audit xác nhận:

- `analysis_log` có 76.659 dòng trong khoảng 30/08–25/09/2026.
- 844 dòng `MALICIOUS` với reason `adblock` nằm trước 06/09; sau mốc này có 0 dòng `MALICIOUS` với reason `adblock`.
- Có 299 dòng `MALICIOUS` sau 06/09; phân bổ lý do có TLS là 219, threat feed là 26, brand là 25, nhóm khác là 29.
- Redis `safe-zone:threat:feed` có 527.576 member. Các shared host cũ như `docs.google.com`, `cdn.jsdelivr.net`, `raw.githubusercontent.com`, `github.com` vẫn còn member với expiry tiếp tục vào tháng 10/2026, nhưng runtime guard đã biến exact hit của shared apex thành `SUSPICIOUS/40`.
- `SAFE_ZONE_POLICY_SEMANTICS=separated`, `SAFE_ZONE_AGENT_ENABLED=false`, `SAFE_ZONE_AI_PROVIDER=none`, `whitelist_domains=0` và `agent_proposals=0` tại thời điểm audit.
- Adblock vẫn chạy `SAFE_ZONE_ADBLOCK_MATCH_MODE=suffix`; vì vậy một số Firebase/Crashlytics/Aria endpoint vẫn có thể bị content-policy block dù security verdict là `SAFE` hoặc `SUSPICIOUS`.

Audit cũng phát hiện một khoảng trống chưa được xử lý: self-service hosting roots như `workers.dev`, `pages.dev`, `vercel.app`, `netlify.app`, `github.io` đang dùng chung `cdnInfraAdvisoryPenalty` và TLS advisory cap với các CDN delegation root. Probe cho thấy `paypal.workers.dev` có thể chỉ nhận penalty 10 và SAFE khi không có exact feed IOC. Đây là residual detection gap; các self-service root phải được tách khỏi cơ chế FP-guard dành cho CDN delegation.

**Decision:**

1. Giữ nguyên production hiện tại; không rollback build `6f69f5e`. Ba lớp guard đã triển khai có tác dụng thực tế: ingestion gate, runtime shared-apex contextualization và delegated-CDN TLS advisory cap.
2. Tách hai khái niệm hạ tầng trong `internal/analysis`:
   - `delegatedCDNRoots`: root do nhà cung cấp CDN/edge kiểm soát tên khách hàng hoặc nội dung dùng chung; dùng penalty advisory 10 và TLS advisory cap.
   - `selfServiceHostingRoots`: root nơi bên thứ ba tự đăng ký tenant; không dùng `cdnInfraAdvisoryPenalty`, không chỉ dựa vào root để cap TLS advisory.
   - `IsCDNRoot` được giữ là API tương thích nhưng chỉ đại diện cho delegated CDN root; `IsSharedHostingRoot` đại diện cho hợp nhất delegated và self-service.
3. Giữ nguyên invariant detection: exact threat-feed IOC trên tenant self-service vẫn phải block; shared apex exact IOC vẫn là contextual `SUSPICIOUS/40`; homoglyph và hyphen-composed brand vẫn giữ trọng số phát hiện đầy đủ.
4. Bump `analysisAlgorithmRevision` khi thay đổi semantics scoring để cache cũ không bị dùng lại. Việc deploy lần này phải được xem là có hiệu lực sau khi revision bump; không dựa vào giả định cache tự hết hạn.
5. Đưa mọi writer của threat feed, gồm OSINT promotion, qua cùng feed-admission predicate. OSINT không được `ZAdd` trực tiếp một shared host hoặc public suffix vào feed chính.
6. Tách telemetry counter cho shared serving host và public suffix; sửa `SummarizeShadowGap` để phản ánh cùng predicate với runtime gate.
7. Không triển khai AI tự động gỡ block. Nếu sau này AI được dùng, chỉ tạo proposal có evidence để operator review; LLM không có ground truth CNAME/ASN/certificate và không được trở thành gatekeeper của allow decision.
8. Xử lý adblock suffix thành slice riêng có shadow metric và canary; không trộn việc đổi content-policy scope vào fix CDN FP này.
9. Purge member feed cũ là thao tác vận hành riêng, cần backup/inventory và kiểm soát multi-source. Không chạy `Replace=true` mù quáng trên production nhiều nguồn.

**Consequences:**

- Giảm FP trên shared apex/CDN edge mà không mất exact tenant IOC blocking.
- Tăng recall phát hiện phishing trên self-service hosting root.
- Cache cũ bị loại khỏi đường đánh giá sau revision bump.
- Threat-feed telemetry có thể phân biệt public suffix và shared serving host.
- Adblock suffix vẫn là nguỗi vận hành riêng cần theo dõi; security verdict và content-policy block phải được báo cáo tách bạch.
- Member cũ trong Redis có thể vẫn tồn tại cho tới khi TTL hết hạn hoặc được purge có kiểm soát; đây là trạng thái vận hành được chấp nhận tạm thời, không phải dữ liệu đã được dọn sạch.

**Validation evidence:**

- `golangci-lint run --timeout 5m`: 0 issues.
- `go test ./internal/analysis ./internal/feed ./internal/agent ./internal/risk ./internal/domaintrie`: PASS.
- `go test ./internal/agent`: PASS.
- Full `go test ./...` và `go build ./...` PASS khi dùng `SAFE_ZONE_ML_MODE=disabled`, `SAFE_ZONE_URL_ML_MODE=disabled`, `SAFE_ZONE_ML_REQUIRED=false`, `SAFE_ZONE_URL_ML_REQUIRED=false`. Khi chạy không có override, workspace local còn thiếu `domain_threat_lgbm.txt`/`url_model.v1.json`; đây là release-environment gap, không phải bằng chứng regression của guard.
- Regression mới pin self-service brand penalty, exact tenant IOC, delegated CDN penalty, OSINT admission refusal, counter telemetry và shadow-gap accounting.
- Independent read-only review ngày 2026-09-25 kết luận `APPROVE WITH CONDITIONS`; hai điều kiện test về lookalike shared host và toàn bộ 17 self-service root đã được bổ sung trước commit.
- Gate tương đương `mise run ci` PASS: 4/4 decision corpus, `go test ./...`, `go build ./...`, `golangci-lint`, `go vet`, UI typecheck/build, Playwright E2E 47/47, gosec 0 issue, govulncheck 0 reachable vulnerability.

**Revisit when:**

- Có bằng chứng traffic rằng một self-service root cụ thể cần cùng chính sách FP với delegated CDN.
- Feed writer mới được thêm ngoài `feed.Sync` và OSINT promotion.
- Đổi `analysis.Result`, policy semantics, cache epoch hoặc threat-feed matching.
- Có thay đổi lớn về nguồn feed, ownership của key hoặc chiến lược purge member.
- Có yêu cầu mở rộng AI/ML từ shadow/observe sang allow hoặc auto-unblock.

---

## 2026-09-23 - CDN false-positive hardening baseline

**Status:** superseded by the 2026-09-25 decision above; retained for history.

**Context:** The first CDN FP hardening pass added the shared-serving-host registry, runtime shared-apex contextualization, feed admission refusal, delegated-CDN TLS advisory cap and focused regression tests.

**Decision:** Keep the three deterministic layers as the baseline. Do not replace them with an LLM that automatically removes blocks. The later self-service-root split and cache revision work refine the baseline rather than reverting it.

**Evidence:** Commit `bb8c4d0`, merged and deployed as `6f69f5e`.

---

## Decision Lookup

- CDN / false positive: `rg -n "CDN|self-service|shared-apex|false-positive|threat feed" DECISION.md`
- Cache / policy / feed semantics: `rg -n "cache|revision|admission|OSINT|policy" DECISION.md`
- Full review: read this file only for repository-wide decision history or when targeted lookup fails and the missing context could change scope, validation or safety.
