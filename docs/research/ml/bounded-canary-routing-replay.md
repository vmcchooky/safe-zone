# Bounded Canary Routing và Shadow Replay cho Custom Domain ML

> **Tài liệu Living Document** — Cập nhật đồng bộ mỗi khi selector, cache policy hoặc replay contract thay đổi.
> Tuân thủ quy tắc tại `.agents/AGENTS.md` Section 5.

## Tóm tắt (Abstract)

Custom Domain ML cần một cohort có giới hạn trước khi bất kỳ prediction nào được phép promote verdict trong `enforce`. Hệ thống sử dụng selector SHA-256 deterministic trên normalized domain, phần trăm và seed bất biến để Core API và DNS Resolver đưa cùng domain vào cùng cohort. Policy revision mới kết hợp model revision, mode và selector revision nhằm ngăn cache của `shadow` bị tái sử dụng trong `enforce`, hoặc ngược lại. Cấu hình `enforce` thiếu phần trăm hay seed bị từ chối khi khởi động; constructor nội bộ hạ yêu cầu không hợp lệ về `shadow`. Clean replay chạy 137 case trong ba vòng, tương đương 411 request cho mỗi service, với Redis, LLM, enrichment và OSINT không tham gia. Kết quả ghi nhận 0 probability mismatch, 0 response mismatch, 0 ML error và 0 enforce promotion; bằng chứng này chỉ xác nhận implementation trong `shadow`, chưa phê duyệt production canary.

## Bounded Canary Selector và Replay

### Mục tiêu (Objectives)

- Giới hạn ML promotion vào một tỷ lệ xác định của normalized-domain hash space.
- Giữ cohort ổn định giữa `core-api`, `dns-resolver`, các lần restart và cache dùng chung.
- Ngăn kết quả cache từ mode hoặc selector cũ đi qua rollout boundary mới.
- Đo probability parity, response parity, false-positive metrics và latency trên replay lớn hơn smoke test.
- Giữ `SAFE_ZONE_ML_MODE=shadow`; không thay đổi production traffic hoặc signed evidence.

### Phương pháp & Lý do (Methodology & Rationale)

| Quyết định | Phương pháp chọn | Các phương pháp thay thế | Lý do |
|---|---|---|---|
| Khóa cohort | SHA-256 của `seed + NUL + normalized_domain`, ánh xạ vào 10.000 bucket | Random theo request; hash IP/client; allowlist thủ công | Random không tái lập. Hash client làm kết quả cache theo domain có thể rò giữa cohort. Allowlist khó kiểm soát tỷ lệ và dễ lệch giữa hai service. |
| Đơn vị phần trăm | Phần trăm hash space của domain, số nguyên từ 1 đến 100 | Phần trăm request tức thời; weighted routing tại reverse proxy | Domain hash tương thích analysis cache và cho cùng quyết định ở hai service. Tỷ lệ request quan sát có thể lệch khỏi cấu hình khi phân phối domain không đều, nên telemetry phải ghi selected/excluded thực tế. |
| Enforcement guard | `enforce` yêu cầu percent và seed hợp lệ | Giữ full enforcement mặc định; fail-open sang full cohort | Từ chối cấu hình thiếu selector ngăn một thay đổi mode vô tình mở blast radius lên 100%. |
| Cache isolation | Policy revision chứa model revision, mode và selector revision | Chỉ dùng model revision; flush Redis khi đổi mode | Chỉ dùng model revision có thể tái sử dụng verdict của mode cũ. Flush cache tạo mutation rộng và không giải quyết đồng thời nhiều revision. |
| Replay | Hai classifier và hai `risk.Service` độc lập, không Redis/LLM/enrichment/OSINT | Replay trực tiếp qua staging dùng Redis chung; chỉ chạy golden vectors | Instance độc lập buộc cả hai service thực hiện inference cho cùng case, nhờ đó đo probability parity mà shared cache không che mất prediction ở service thứ hai. |

Selector sử dụng 10.000 bucket:

```text
bucket = uint64_be(SHA256(seed || NUL || normalized_domain)[0:8]) mod 10000
selected = bucket < percent * 100
```

Seed không phải credential, nhưng phải được giữ ổn định trong một observation window. Thay percent hoặc seed tạo selector revision mới và policy cache revision mới.

### Cách thức Thực hiện (Implementation Details)

`internal/risk/ml_canary.go` chứa config, selector và status contract. `internal/risk/ml.go` chỉ áp dụng promotion khi mode là `enforce` và domain thuộc cohort; trong `shadow`, classifier vẫn chỉ ghi `would_block`/`would_pass` cùng các counter selected/excluded. Status JSON bổ sung `ml_policy_revision` và object `canary` gồm algorithm, percent, selector revision, selected/excluded predictions, selected would-block/pass và số promotion bị suppress.

`internal/risk/service.go` dùng policy revision trong analysis cache key và cache entry. Revision này tách `shadow`, `enforce` và từng selector, nên kill switch không nhận lại cached ML verdict từ mode trước. Hai biến cấu hình được truyền giống nhau vào Core API và DNS Resolver:

```env
SAFE_ZONE_ML_CANARY_PERCENT=10
SAFE_ZONE_ML_CANARY_SEED=phase5-local-shadow-v1
```

Clean replay có thể tái lập bằng lệnh sau. Output phải nằm trong private working store, không ghi đè archive đã ký:

```powershell
go run ./cmd/ml-replay `
  --labels ml/evidence/representative-replay/run-20260823-owner-approved-addendum/labels.csv `
  --bundle <private-bundle> `
  --canary-percent 10 `
  --canary-seed phase5-local-shadow-v1 `
  --rounds 3 `
  --tolerance 1e-12 `
  --output <private-run>\replay-report.json
```

Codex GPT-5.6 Sol thực hiện thay đổi với một main agent, không dùng subagent và không có cơ chế voting. Prompt strategy khóa các invariant `shadow-only`, domain-level deterministic selection, cache isolation và signed-evidence immutability. Kiểm soát chất lượng gồm unit tests, service-path replay, probability/response parity, full repository validation và runtime status snapshot. Người dùng phê duyệt implementation và local shadow replay; mọi thao tác bật `enforce` vẫn cần xác nhận riêng.

### Số liệu (Metrics & Results)

Run ngày 2026-08-23 sử dụng model `1.0.0`, revision `4632f9ea69124591db89dfb176aacf46323c18043c7b8c8d0972c3b2f92c3bca`, threshold `0.85` và labels SHA-256 `d03e698fdeaa5b4f107b09e3d1b85496c35252e318324f32b48c9e942dcc3844`.

| Chỉ số | Kết quả |
|---|---:|
| Case / round | 137 |
| Số round | 3 |
| Request / service | 411 |
| Offline probability parity | 137/137, 0 mismatch, max delta `0` tại tolerance `1e-12` |
| Runtime candidate probability parity | 19/19 unique candidate, 0 mismatch, max delta `0` |
| Cross-service response parity | 411/411, 0 mismatch |
| Prediction attempts / service | 57 |
| Shadow would-block / would-pass | 21 / 36 |
| Selector observation 10% | 3 selected / 54 excluded prediction; observed selected ratio 5,26% |
| Selected would-block / would-pass | 3 / 0 |
| ML errors / enforce promotions | 0 / 0 |
| Latency p95 | 2.000 µs cho cả hai service |
| Offline benign FPR | 0/25 = 0% |
| Runtime candidate benign FPR | Không tính được; 0 benign case đi vào candidate cohort |

Observed selected ratio không bắt buộc bằng 10% trên mẫu nhỏ. Ba selected prediction là cùng một unique candidate lặp qua ba round; selector hoạt động theo domain hash space, không theo request counter. Tập nhãn còn 78 case `unknown` theo waiver đã duyệt, và runtime candidate subset không chứa benign case. Vì vậy replay xác nhận parity và routing mechanics nhưng chưa đủ để đặt production FP budget hoặc mở `enforce`.

### Liên kết Artifacts

- `internal/risk/ml_canary.go`
- `internal/risk/ml.go`
- `internal/risk/ml_canary_test.go`
- `cmd/ml-replay/main.go`
- `cmd/ml-replay/main_test.go`
- `docs/runbooks/ml-canary-rollout.md`
- `docs/runbooks/ml-shadow-representative-replay.md`
- Private report: `<private-run>/replay-report.json` — không thuộc Git và không phải signed evidence.

---

## Lịch sử Thay đổi (Version History)

| Ngày | Thay đổi | Tác giả |
|---|---|---|
| 2026-08-23 | Thêm bounded selector, cache policy isolation và clean replay 137 case × 3 round | Codex GPT-5.6 Sol |
