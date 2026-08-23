# Quy trình canary cho Custom Domain ML

> **Living document:** Cập nhật cùng mã nguồn và evidence packet. Runbook này
> không tự phê duyệt hoặc tự bật `enforce`.

## Trạng thái hiện tại

Archive `run-20260808` được giữ bất biến và vẫn phản ánh 79 case
`unknown`/`unresolved`. Working preflight ngày 2026-08-23 bổ sung evidence
người dùng cho `replay-0072`, chuyển case này thành malicious true positive và
còn 78 reviewed-unclassifiable cases. Reporter chấp nhận waiver chỉ khi count,
số would-block và SHA-256 của tập case ID khớp; working report hiện ở
`ready_for_review_with_reviewed_unclassifiable_waiver`. Trạng thái rollout vẫn
là **NO-GO**: Product/Security đã ghi owner decisions ngày 2026-08-23, nhưng
release identity, runtime snapshot, canary routing scope và rollback inputs
vẫn chưa khép kín.

## Mục tiêu và phạm vi

- Chuyển `disabled` → `shadow` → `enforce` theo từng phạm vi nhỏ, không
  thay đổi blast radius ngoài phạm vi đã phê duyệt.
- Chỉ cho phép ML promote kết quả lexical `SUSPICIOUS` thành `MALICIOUS` ở
  threshold đã duyệt; ML không được hạ `MALICIOUS` thành safe.
- Giữ kill switch có thể đảo về `shadow` hoặc `disabled` bằng thay đổi
  `SAFE_ZONE_ML_MODE` và restart service.

## Điều kiện trước khi canary

1. Evidence phải khớp với archive đã ký tại
   `ml/evidence/representative-replay/run-20260808/`, gồm manifest,
   requests/results, labels, review summary, approval packet và
   `checksums.sha256`. Nếu triển khai từ private release store, phải đối soát
   hash với archive này trước khi chạy.
2. `manifest.json`, bundle revision, threshold và cấu hình phải khớp giữa
   `core-api` và `dns-resolver`; bundle được validate và mount read-only.
3. External AI, enrichment và OSINT phải tắt trong clean replay. Source
   membership, prior report và model output không phải human ground truth.
4. Hai owner phải ghi quyết định và ngày trong approval packet:
   Product cho threshold/FP budget/canary scope; Security cho source terms,
   access, retention, model integrity và rollout boundary.

## Human-label và FP gates

Template chuẩn là `docs/templates/ml-human-label-review.csv`. Queue phải có
đúng số case trong manifest (run hiện tại có 137), ưu tiên 21
`review_required` case và double-label 21 case cùng khoảng 10% mẫu ngẫu
nhiên (target hiện được ghi trong summary là 35). Các trường
`critical_benign_stratum`, `deterministic_would_block`, `second_human_label`
và `second_reviewer_id` dùng để đo các gate tương ứng. Queue `run-20260808`
có đủ các cột hiện hành. Giá trị `unknown` hoặc `unresolved` có thể là kết quả
review hợp lệ khi evidence không đủ, nhưng không tự động pass approval gate:
case phải được phân giải thêm hoặc nằm trong waiver reviewed-unclassifiable
được ràng buộc và phê duyệt rõ ràng.

Chạy từ repository root:

```powershell
python ml/src/validate_labels.py <private-run>\labels.csv --expected-total 137
python ml/src/report_fp.py --labels <private-run>\labels.csv `
  --summary <private-run>\review-summary.json `
  --packet <private-run>\approval-packet.md
```

- Validator exit `0`: queue đầy đủ và hợp lệ; exit `1`: dữ liệu/schema sai;
  exit `2`: còn pending. Chỉ dùng `--allow-pending` để tạo trạng thái quan
  sát trước adjudication, không dùng nó để đóng gate.
- Reporter exit `0`: report không còn approval blocker, gồm trường hợp waiver
  reviewed-unclassifiable hợp lệ; exit `1`: lỗi dữ liệu/report; exit `2`: còn
  pending; exit `3`: report đã tạo nhưng review gate vẫn block canary.
- Reporter chỉ tính FPR/recall trên `benign` và `malicious`. `compromised`,
  `shared_hosting` và `unknown` bị loại khỏi binary denominator. Việc loại
  khỏi denominator không tự loại `unknown` khỏi approval gate. Reporter ghi
  `unresolved_count`, `unresolved_case_ids`, số would-block và SHA-256 của tập
  case ID. Waiver sai count/hash hoặc thiếu lý do vẫn tạo blocker.
- Critical-benign FPR, reviewer agreement, unresolved/disagreement và các
  case deterministic đã block phải có dữ liệu riêng; thiếu một gate vẫn
  giữ `canary=blocked`.
- Không có confirmed critical-benign FP hoặc disagreement chưa giải quyết nào
  được phép đi qua approval. Case thiếu evidence chỉ được loại khỏi binary
  metrics bằng waiver khớp chính xác và quyết định rõ của Product/Security;
  waiver không biến case đó thành benign hoặc malicious.

## Runtime observation

Đọc JSON `ml` từ `core-api` tại `/v1/status` hoặc `/metrics`, và từ
`dns-resolver` tại `/` hoặc `/metrics`. Các field cần lưu trước/sau mỗi
window gồm:

- `ml_mode`, `ml_state`, `ml_model_version`, `ml_revision`,
  `ml_block_threshold`;
- `prediction_attempts`, `shadow_would_block`, `shadow_would_pass`,
  `enforce_promotions`, `abstains`, `errors`, `skips`;
- `latency_p95_us`, `latency_count`, `latency_histogram_us` và
  `probability_histogram`.

> Đây là JSON status telemetry, không phải các Prometheus series có tên
> `ml_latency`. Runtime hiện bucket latency đến `50,000us` và trả `-1` cho
> p95 vượt bucket cuối. Vì vậy chưa được tuyên bố SLO p95 `200ms` từ field
> này; nếu Product yêu cầu ngưỡng 200ms, phải bổ sung telemetry bucket/metric
> và test trước khi dùng làm approval gate.

Rollback ngay nếu một trong các điều kiện xảy ra:

- `ml_state` không còn `ready`, revision/threshold giữa hai service lệch,
  ML `errors` tăng, hoặc parity mismatch xuất hiện;
- có confirmed critical-benign false positive, report người dùng đáng tin
  cậy, hoặc `enforce_promotions` tăng ngoài traffic/canary scope;
- `latency_p95_us == -1` (p95 đã vượt bucket đo được hiện tại), cho tới khi
  telemetry chính xác hơn;
- Security yêu cầu rollback hoặc bất kỳ owner nào xác định evidence không
  còn đúng với bundle/config đang chạy.

## Canary scope và release identity

Trước khi bật `enforce`, packet mới phải ghi rõ và được phê duyệt:

- instance hoặc compose project cụ thể cho cả `core-api` và `dns-resolver`;
- routing mechanism, request eligibility và traffic cap theo phần trăm;
- thời lượng lẫn số `prediction_attempts` tối thiểu của observation window;
- Product owner, Security owner và operator/on-call chịu trách nhiệm;
- exact Git commit, CI run, immutable image digest của hai service, bundle
  revision, threshold và config snapshot;
- last-known-good image digests/config/bundle và lệnh kill-switch cho đúng
  scope.

Runtime có bounded selector `sha256_normalized_domain_v1`. Cấu hình dùng
`SAFE_ZONE_ML_CANARY_PERCENT` (số nguyên `1..100`) và
`SAFE_ZONE_ML_CANARY_SEED` bất biến trong observation window. Selector ánh xạ
normalized domain vào 10.000 bucket, nên cùng domain có cùng eligibility ở
`core-api`, `dns-resolver` và mọi client. Đây là cap theo domain hash space;
phân phối request thực tế phải được đối chiếu qua `canary.selected_predictions`
và `canary.excluded_predictions`, không suy ra trực tiếp từ percent cấu hình.

`SAFE_ZONE_ML_MODE=enforce` bị từ chối khi khởi động nếu percent bằng `0` hoặc
seed rỗng. Trong `shadow`, selector chỉ ghi observation và không thay đổi
verdict. `ml_policy_revision` kết hợp model revision, mode và selector revision
để cache của `shadow`/selector cũ không đi qua boundary của `enforce`. Các field
`canary.selected_would_block`, `selected_would_pass` và `enforce_suppressed`
phải được lưu trong runtime snapshot.

Selector cấp ứng dụng đã có, nhưng instance/compose project, cap production,
duration, minimum attempts, owner/on-call và LKG snapshot vẫn phải ghi trong
packet mới. Không dùng việc selector tồn tại để tự phê duyệt hoặc tự bật
`enforce`.

## Kích hoạt và rollback

Chỉ sau khi mọi gate trên pass và approval packet có đủ quyết định:

1. Xác nhận instance/routing/traffic cap trong packet khớp với runtime và lưu
   snapshot last-known-good; giữ bundle, threshold và config manifest bất
   biến.
2. Đặt `SAFE_ZONE_ML_MODE=enforce` cho đúng scope và restart service theo
   deployment procedure.
3. Ghi snapshot status trước/sau, theo dõi các field ML và false-positive
   reports trong window đã Product phê duyệt.
4. Khi rollback, đặt `SAFE_ZONE_ML_MODE=shadow` (hoặc `disabled`), restart,
   xác nhận cả hai service trở lại `ml_state`/revision mong muốn và ghi
   incident. Khôi phục bằng immutable image digest/config snapshot đã lưu,
   không dùng tag trôi nổi. Model revision mới phải tạo cache miss.

## Artifacts và source of truth

- Replay procedure: `docs/runbooks/ml-shadow-representative-replay.md`.
- Historical approval packet (không phải approval hợp lệ cho canary hiện tại):
  `ml/evidence/representative-replay/run-20260808/approval-packet.md`.
- Archive provenance/checksums:
  `ml/evidence/representative-replay/run-20260808/ARCHIVE.md`.
- ML methodology và release gates:
  `docs/research/ml/method.md`, `docs/specs/safe-zone-ai-plan.md` và
  `docs/production-completion-checklist.md`.

## Lịch sử thay đổi

| Ngày | Thay đổi | Tác giả |
|---|---|---|
| 2026-08-08 | Tạo runbook canary ban đầu | Junie |
| 2026-08-09 | Đối chiếu runtime telemetry, label tooling và approval gates; loại bỏ tuyên bố chưa có evidence | Junie |
| 2026-08-22 | Cập nhật trạng thái run-20260808: human review hoàn tất, owner approvals đã ghi nhận, canary preflight còn lại | Codex |
| 2026-08-22 | Sửa gate `unknown`/`unresolved`, đặt run-20260808 về NO-GO và bổ sung yêu cầu canary scope/release identity/LKG rollback | Codex (GPT-5) |
| 2026-08-23 | Thêm reviewed-unclassifiable waiver ràng buộc count/would-block/case-ID hash; ghi nhận evidence người dùng chuyển replay-0072 thành malicious trong working copy | Codex (GPT-5.6 Sol) |
| 2026-08-23 | Ghi nhận Product/Security owner decisions cho working packet; rollout tiếp tục NO-GO do runtime/release/canary/rollback gates | Codex (GPT-5.6 Sol) |
| 2026-08-23 | Thêm bounded normalized-domain selector, cache policy revision và shadow-only canary telemetry; production enforce chưa được phê duyệt | Codex (GPT-5.6 Sol) |
