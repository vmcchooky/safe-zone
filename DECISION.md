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
- PR #85 merged thành `bdcd495`; CI và Security trên `main` PASS sau merge.
- Production canary 2026-09-26 (deploy `bdcd495`, edge mode `production-edge`, build time `2026-09-26T04:04:45Z`) PASS với A/B probe cùng tập 14 domain:
  - `microsoft.github.io` (exact feed IOC thật trên self-service root) giữ `MALICIOUS/100` và policy `block` trước và sau.
  - `paypal.workers.dev` và `paypal.pages.dev` chuyển `SAFE/10` → `SUSPICIOUS/40`, policy vẫn `allow` (không tạo FP block mới).
  - `paypal.fastly.net` giữ `SAFE/10`; delegated-CDN FP/TLS cap không bị nới.
  - `docs.google.com`, `cdn.jsdelivr.net`, `raw.githubusercontent.com`, `github.com`, `drive.google.com` giữ `SUSPICIOUS/40` contextual, policy `allow`.
  - Lookalike `raw.githubusercontent.com.evil.com` và `evil.pages.dev.attacker.com` giữ `SAFE/15`, không bị nhận thành shared apex.
  - `bank.vercel.app`, `vietcombank.com.vn`, `example.com` không đổi (`SAFE/0`).
  - 12/14 probe không đổi; 2 probe thay đổi đúng mục tiêu thiết kế.
- Canary verification: `/healthz` 200 cho cả core-api và dns-resolver, `/v1/version` báo `bdcd495` ở cả hai service, `public-edge-smoke.sh` PASS, `check-block-page.sh` PASS, `RestartCount=0` cho cả hai container, không có `panic|fatal|ERROR` trong log sau restart, threat feed giữ nguyên `527.517` member và revision `431`.
- Rollback input đã ghi nhận và kiểm chứng trước deploy: backup `backups/20260926-040203` (65 MB, `sha256sum -c SHA256SUMS` toàn bộ OK) và tag bảo toàn `safe-zone-core-api:6f69f5e` / `safe-zone-dns-resolver:6f69f5e` trỏ đúng image ID của build `6f69f5e`.
- **Ngoại lệ release gate:** không có host staging trong cấu hình SSH (chỉ có `safe-zone` production), nên canary chạy thẳng trên production với rollback input đã kiểm chứng và verification window ngắn thay vì triển khai staging tách biệt. Ngoại lệ này cần được đóng bằng một host staging trước release có thay đổi policy/security tiếp theo.
- Chưa thu được phân bổ verdict từ SQL `analysis_log` vì SQLite nằm trong docker volume và container không có `sqlite3`/`python3`; bằng chứng canary dựa trên response `analyze` và `policy` là nguồn chính thức.
- Inventory purge read-only bằng `cmd/feed-shared-host-audit` (predicate `feed.IsAdmissibleDomain`, ZSCAN): production có `527.613` member ở revision `432` và đúng **8** member là shared serving host, đều hết hạn `2026-10-10`. Đối chiếu âm tính `microsoft.github.io`, `evil.github.io`, `raw.githubusercontent.com.evil.com` và `vietcombank.com.vn` đều admissible, nên tenant IOC không nằm trong tập purge candidate.
- **Chưa purge gì trên production.** Member cũ hiện vẫn được runtime shared-apex guard hạ thành `SUSPICIOUS/40` với policy `allow`, nên việc chưa purge không tạo rủi ro chặn nhầm. Purge là slice vận hành riêng, cần backup, kiểm tra multi-source và phê duyệt operator.
- **Multi-source check (2026-09-26) cho thấy purge đơn lẻ sẽ không bền vững:** cả 4 nguồn live vẫn liệt kê shared host dưới dạng exact match — urlhaus (`cdn.jsdelivr.net`, `docs.google.com`, `drive.google.com`, `firebasestorage.googleapis.com`, `github.com`, `raw.githubusercontent.com`), openphish (`sites.google.com`), Phishing-Database (`cdn.ampproject.org`, `firebasestorage.googleapis.com`, `sites.google.com`) và destroylist (`github.com`). Xóa member thủ công chỉ dọn tới lần sync kế tiếp, khi nguồn ghi lại và **ingestion gate** phải từ chối lại. Vì vậy ingestion gate là lớp bảo vệ chính, còn runtime shared-apex guard là lớp phòng vệ thứ hai; purge chỉ là dọn dẹp vận hành và không được ghi nhận là biện pháp sửa lỗi.

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

## 2026-09-26 - Adblock becomes an operator-controlled, reversible layer

**Status:** accepted

**Context:**

Audit telemetry từ 13/09–26/09 trên production (một người dùng) cho thấy
`analysis_log` ghi nhận 12.531 sự kiện chặn trên 129 domain. Trong đó:

- 7.434 sự kiện đến từ quảng cáo/tracking — hoạt động đúng mục đích.
- 4.682 sự kiện thuộc hạ tầng ứng dụng (Firebase, Crashlytics, Xiaomi SDK).
- 717 sự kiện thuộc dịch vụ quan trọng: `log.api.zaloapp.com`,
  `centralized.zaloapp.com`, `ads-platform.zalo.me`, `f-emcc.ngsp.gov.vn`.
- Chỉ 7 sự kiện `MALICIOUS` và tất cả đều là override thủ công của operator
  (`zaloweb.vn`), không phải phát hiện tự động.

Audit bằng `cmd/block-audit` cũng phát hiện `f-emcc.ngsp.gov.vn` — hạ tầng
email cơ quan nhà nước — bị chặn, mối đã nguy hiểm nhưng không nằm trong bất
kỳ danh sách hardcode nào.

**Decision:**

1. Adblock là **chức năng bật/tắt được**, mặc định **bật**, và phải bật/tắt
   được từ dashboard trong một thao tác. Lý do: đây là lớp gây gián đoạn
   dịch vụ lớn nhất, nên đường lùi phải rẻ và tức thì.
2. `enabled` được đánh giá tại thời điểm quyết định nên đổi có hiệu lực ở
   request kế tiếp, không cần resync hay restart.
3. `match_mode` quyết định scope lúc parse nên đổi cần rebuild; setter gửi yêu
   cầu qua kênh coalescing để không block API request.
4. Store là lớp ưu tiên hơn environment cho cả hai công tắc, để lựa chọn của
   operator không bị ghi đè khi refresh hoặc khởi động lại.
5. Tắt adblock **không** làm suy yếu phát hiện malware/phishing: threat feed,
   brand, lexical và OSINT là các lớp độc lập.
6. **Không có AI/ML tự động bật lại.** Chỉ operator quyết định.
7. Việc chuyển production sang `exact` và thêm exception cho nhóm
   `critical_service` là slice tiếp theo, không gộp vào thay đổi expose này.

**Consequences:**

- Có đường lùi vận hành rẻ khi dịch vụ quan trọng bị chặn nhầm.
- `cmd/block-audit` trở thành nguồn inventory định kỳ thay cho việc đo tỷ lệ
  FP thống kê, vì ở quy mô một người dùng tập domain bị chặn là hữu hạn và
  đếm đủ.
- Trade-off của `exact` là một số subdomain quảng cáo có thể lọt; đây là đánh
  đổi có chủ đích lấy việc không gián đoạn dịch vụ.

**Validation evidence:**

- `internal/risk`: test chứng minh toggle có hiệu lực tức thì (tắt thì policy
  không còn block, bật lại thì block trở lại), match mode invalid bị từ chối mà
  không đổi state, refresh không revert lựa chọn của operator, kênh resync
  không block caller.
- `internal/api/handlers`: round-trip toggle qua `/v1/settings`, 400 khi match
  mode sai, và trường bị bỏ qua không làm thay đổi công tắc.
- `go test ./...`, `go build ./...`, `golangci-lint` (0 issue), UI typecheck: PASS.

**Revisit when:**

- Có yêu cầu tách adblock thành nhóm bật/tắt riêng (ads-only, tracker-only).
- Có nhu cầu công tắc theo nhóm client thay vì toàn hệ thống.
- Số lượng nguồn adblock tăng đến mức rebuild thủ công tốn kém.

---

## 2026-09-26 - Adblock false positives are fixed with scoped exceptions, not exact mode

**Status:** accepted

**Context:**

Sau khi triển khai công tắc điều khiển, kế hoạch ban đầu là chuyển production
sang `SAFE_ZONE_ADBLOCK_MATCH_MODE=exact` kèm một số exception. Trước khi đổi,
tác động được đo **offline** từ cache adblock thật (75.945 rule) đối chiếu với
129 domain từng bị chặn.

Kết quả **đảo ngược khuyến nghị**:

| Nhóm | Số domain | Dưới chế độ `exact` |
|---|---:|---|
| Có tên nguyên vẹn trong danh sách | 102 | **vẫn bị chặn** |
| Chỉ khớp qua parent suffix | 26 | được thả |
| Không có trong danh sách | 1 | không liên quan |

26 domain được thả gần như toàn bộ là quảng cáo/tracking (AppsFlyer, Inmobi,
Pangle, Vungle, Admaster). Trong khi đó các host **gây hại** — Zalo, Firebase
Logging, Crashlytics — đều có tên nguyên vẹn trong danh sách nên `exact` **không
giúp gì**. Chuyển sang `exact` sẽ thả quảng cáo mà vẫn giữ hạ tầng hại hại.

**Decision:**

1. Giữ `match_mode=suffix`. `exact` không phải công cụ đúng cho lớp false
   positive này.
2. Dùng **scoped content exception** (`adblock_exceptions.json`) cho từng host
   hại hại, với `matched_rule` và `source_id` chính xác lấy từ cache thật.
3. Exception thêm: `f-emc.ngsp.gov.vn` (hạ tầng email cơ quan nhà nước),
   `crashlytics.com` (suffix, phủ mọi subdomain), `firebaselogging.googleapis.com`,
   `firebaselogging-pa.googleapis.com`, `crashlyticsreports-pa.googleapis.com`.
   Giữ nguyên hai exception Zalo sẵn có.
4. **Cố ý không** except `ads-platform.zalo.me`: đó là nền tảng quảng cáo của
   Zalo, chặn là đúng mục đích. Tương tự, Xiaomi/Microsoft/Google analytics và
   SDK quảng cáo vẫn bị chặn.
5. Bộ phân loại của `cmd/block-audit` là **công cụ sắp xếp**, không phải phán
   quyết. `app_critical` khớp `sdk`/`config`/`telemetry` nên gom nhầm SDK quảng
   cáo. Phán quyết cuối cùng dựa trên hiểu biết về dịch vụ.

**Consequences:**

- 7 exception đang hiệu lực; 8 domain hại hại chuyển sang `allow`.
- Quảng cáo vẫn bị chặn đầy đủ; `microsoft.github.io` vẫn `MALICIOUS/100` +
  `block`.
- Invariant lớp security từ PR #85 không đổi.
- Cần thêm exception mới khi gặp hạ tầng dùng chung mới; công tắc bật/tắt
  vẫn là đường lùi khẩn cấp.

**Validation evidence:**

- `/v1/status.adblock.exceptions`: count `2 → 7`, revision đổi, `last_reload_ok=true`,
  `reload_failures=0`.
- Probe `allow`: `log.api.zaloapp.com`, `centralized.zaloapp.com`,
  `f-emc.ngsp.gov.vn`, `firebase-settings.crashlytics.com`,
  `firebaselogging.googleapis.com`, `firebaselogging-pa.googleapis.com`,
  `crashlyticsreports-pa.googleapis.com`, `settings.crashlytics.com` → 8/8 `allow`.
- Probe `block`: `googleads.g.doubleclick.net`, `ms.applovin.com`,
  `api16-access-wf-sg.pangle.io`, `ads-platform.zalo.me` → 4/4 `block`.
- `microsoft.github.io` → `block` `MALICIOUS/100`.
- Không regression: `docs.google.com`, `cdn.jsdelivr.net`, `github.com` vẫn
  `SUSPICIOUS/40`; `paypal.workers.dev` `SUSPICIOUS/40`; `paypal.fastly.net`
  `SAFE/10`; lookalike `SAFE/15`; `vietcombank.com.vn` `SAFE/0`.
- Rollback: `/tmp/adblock_exceptions.backup.json` (2 entry) trên VPS.

**Revisit when:**

- Danh sách nguồn adblock đổi, khiến `matched_rule` / `source_id` cũ không còn
  khớp và exception im lặng mất hiệu lực.
- Có bằng chứng rằng `exact` hữu ích cho một lớp hạ tầng khác, thì mở lại đề
  xuất dùng `exact` cho **nguồn đó** qua per-source policy thay vì toàn cục.
- Số exception vượt ngưỡng cần quản lý (hiện loader cho phép 1024).

---

## 2026-09-26 - Detection recall verified at 100%; the "zero detections" reading was wrong

**Status:** accepted

**Context:**

Audit telemetry 13/09–26/09 chỉ ghi nhận 7 sự kiện chặn `MALICIOUS`, tất cả là
override thủ công của operator cho `zaloweb.vn`. Điều này từng được đọc là bằng
chứng rằng engine không tự phát hiện được gì, và đó là **kết luận sai**.

**Measurement:**

Lấy mẫu ngẫu nhiên 200 member từ `safe-zone:threat:feed` bằng
`ZRANDMEMBER`, dựng corpus và chạy qua `internal/eval.Runner` (hermetic,
miniredis, không network), rồi xác minh lại trên service thật với Redis
production:

| Tầng đo | Kết quả |
|---|---|
| Hermetic runner, 200 mẫu | `MALICIOUS/100` + `policy=block` **200/200 (100%)** |
| Lý do duy nhất | `matched local threat feed` 200/200 |
| Service thật, 5 mẫu đầu | `MALICIOUS/100` + `block` **5/5** |

**Decision:**

1. Recall của đường threat-feed là **100%** trên mẫu thực tế. Không có khiếm
   khuyết phát hiện cần khắc phục ở lớp này.
2. Con số "0 phát hiện tự động" **không** phải lỗi engine. Nó phản ánh đúng
   sự thật là trong 12 ngày đó **không có known-bad domain nào được truy vấn**.
   Người dùng chỉ truy cập nội dung lành mạnh. Đây là hệ quả của lưu lượng
   một người, không phải khiếm khuyết phát hiện.
3. **Không** nâng ngưỡng, **không** thay đổi trọng số, **không** bật `enforce`
   cho domain ML dựa trên phát hiện sai này.
4. Bài học về phương pháp: không được suy ra kết luận về năng lực hệ thống từ
   một telemetry rỗng. Phải chủ động dựng mẫu known-bad để đo recall.

**Consequences:**

- Ưu tiên 3 trong kế hoạch FP được đánh lại: không cần sửa thuật toán phát
  hiện, vì nó đang hoạt động đúng.
- Nguồn nhiễm còn lại là **chất lượng feed**: mẫu ngẫu nhiên chứa nhiều mục
  rác như `acollectionofviralvideosfromsg.msge7.my.id`, subdomain
  `blogspot`/`weebly`, và CIDR IPFS. Đây là hướng cải thiện chất lượng riêng,
  không phải việc của lát cắt này.

**Validation evidence:**

- `tmp/recall-corpus.json`, `tmp/recall-expected.json`, `tmp/recall_sample.txt`
  (local, gitignored).
- Mẫu được lấy bằng `ZRANDMEMBER` để tránh thiên lệch thứ tự lex của `ZREVRANGE`.

**Revisit when:**

- Có bằng chứng thực địa rằng một IOC trong feed không bị chặn.
- Chính sách feed đổi, hoặc thêm một writer mới ngoài `feed.IsAdmissibleDomain`.
- Muốn đo recall của lớp khác (brand, TLS, lexical) thay vì lớp threat-feed.

---

## 2026-09-26 - Grace degradation is redundant; corroboration already exists in the score model

**Status:** accepted

**Context:**

Sau khi recall threat-feed đo được 100%, bước còn lại của chương trình FP là
giảm **blast radius**: biến một quyết định chặn sai thành gián đoạn nhẹ thay
vì mất dịch vụ. Đề xuất ban đầu là *grace degradation* — nghi bạ chặn trước,
chỉ chặn thật sau khi xác nhận lặp lại.

Trước khi xây, tận dụng bài học của lát cắt trước: **đo trước, đừng xây theo
giả định.**

**Measurement 1 — MALICIOUS đến từ đâu.** Trong 1.306 verdict `MALICIOUS` của
`analysis_log`:

| Nguồn | Số | Ghi chú |
|---|---:|---|
| `adblock` thuần | 844 | kỷ nguyên `PolicySemanticsLegacy`, đã tách lớp |
| feed hit | 32 | dẫn chứng mạnh, đáng tin |
| còn lại | 1.274 | **luôn là ≥ 2 nhóm tín hiệu độc lập** |

Không có mẫu nào là `MALICIOUS` từ một nhóm tín hiệu duy nhất.

**Measurement 2 — ngưỡng toán học.** Với `DefaultAnalysisConfig`:

| Tín hiệu | Điểm |
|---|---:|
| `brand_spoofing` | 50 |
| punycode | 35 |
| entropy | 35 |
| mixed script | 25 |
| keyword base + match + multiple | 35 |
| long domain | 15 |
| hyphen / digit ratio | 10 |

Ngưỡng `MALICIOUS` là **70**. Tín hiệu mạnh nhất đơn lẻ là **50 < 70**, nên
`MALICIOUS` **không thể** đạt bằng một tín hiệu. Cần tối thiểu hai nhóm độc lập
(ví dụ `50 + 35 = 85`), hoặc một feed hit có thẩm quyền (`100`).

**Decision:**

1. **Không** triển khai grace degradation. Nó chồng lặp lên cơ chế corroboration
   đã có sẵn, thêm độ trễ và độ phức tạp mà không giảm FP nào đã quan sát
   được.
2. Blast radius của lớp security đã được giới hạn bằng thiết kế. Đường lùi
   còn lại là công tắc adblock đã triển khai, và `cmd/block-audit` để phát hiện.
3. **Hoãn** verified infrastructure registry có evidence/TTL. Chưa có bằng chứng
   cho thấy registry tĩnh hiện tại thiếu mục: 129 domain bị chặn trong 12 ngày
   và **không** có shared-host nào bị chặn. Xây registry khi có bằng chứng một
   self-service root mới gây FP, không xây trước.
4. Nguồn nhiễm thật sự còn lại là **chất lượng feed** (xem entry 2026-09-26 về
   recall), là hướng công việc riêng.

**Consequences:**

- Chương trình 4 bước kết thúc mà không thêm logic chặn mới, đúng vì bằng
  chứng không ủng hộ.
- Các số liệu trong `analysis_log` pha lẫn lịch sử của các bản vá đã merge, nên
  không dùng làm baseline cho thay đổi scoring trong tương lai.

**Validation evidence:**

- Truy vấn `analysis_log` trên bản sao read-only của DB production.
- Trọng số lấy từ `config.DefaultAnalysisConfig()`; ngưỡng lấy từ pipeline verdict.

**Revisit when:**

- Có bằng chứng thực địa về một lần chặn sai do **chỉ một** nhóm tín hiệu.
- Có tín hiệu mới với trọng số đơn ≥ 70.
- Có self-service root mới gây FP → mở lại đề xuất verified registry.

---

## Decision Lookup

- CDN / false positive: `rg -n "CDN|self-service|shared-apex|false-positive|threat feed" DECISION.md`
- Cache / policy / feed semantics: `rg -n "cache|revision|admission|OSINT|policy" DECISION.md`
- Full review: read this file only for repository-wide decision history or when targeted lookup fails and the missing context could change scope, validation or safety.
