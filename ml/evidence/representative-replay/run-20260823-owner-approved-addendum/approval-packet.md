# Safe Zone ML v1 shadow replay approval packet

- Model version/revision: `1.0.0` / `4632f9ea69124591db89dfb176aacf46323c18043c7b8c8d0972c3b2f92c3bca`
- Local candidate commit: `2f0a9e79cf468e2b8603f709479850b629453b4a`; ML logic commit: `847c6d582f305c99439e1293d2e28ba65606205d`; GitHub CI pending
- Threshold: `0.85`
- Cases: `137`; human labels complete: `137/137`
- Core HTTP non-200: `0`
- DNS HTTP non-200: `0`
- Cross-service verdict parity mismatches: `0`

### ML Replay Methodology
- **137 Offline Predictions:** Tập mẫu phân tầng (stratified sample) được trích xuất từ các nguồn dữ liệu tin cậy và báo cáo người dùng. Mục tiêu là đánh giá khả năng tổng quát và độ an toàn của mô hình trên các kịch bản đa dạng (bao gồm cả hard cases).
- **19 Live Staging Attempts:** Lưu lượng truy vấn thực tế được ghi nhận trên môi trường Staging (shadow mode). Kết quả cho thấy sự ổn định về mặt kỹ thuật (0 lỗi, 0 sai lệch giữa các service).

<!-- BEGIN HUMAN-LABEL-METRICS -->
### Human-label review metrics
- **Status:** `complete`
- **Coverage:** 137/137 (100.0%)
- **Threshold:** `0.85`
- **Double-label target:** 35 cases
- **False Positive Rate:** 0.0000 (0/25)
- **Recall:** 0.7647 (26/34)
- **Non-binary labels excluded:** {'compromised': 0, 'shared_hosting': 0, 'unknown': 78}
- **Unresolved reviewed cases:** 78
- **Reviewed-unclassifiable gate:** `waived`
- **Reviewed-unclassifiable would-block:** 33
- **Reviewed-unclassifiable case-ID SHA-256:** `efdaa81a8fc9cb6350aff67a1e1513f4b696a71f7d11b3e8c728fcf86e6acb27`
- **Critical-benign review:** `available_with_waiver`
- **Reviewer agreement:** `waived`
- **Deterministic policy evidence:** `available`
- **Approval blockers:** none recorded
<!-- END HUMAN-LABEL-METRICS -->

## Current decision

The technical review gate is ready with an exact-set reviewed-unclassifiable waiver. Product and Security approvals for this working packet are recorded below. Runtime, release-identity, canary-scope and rollback preflight gates remain; do not enable `enforce` until they pass and an explicit activation confirmation is given.

### Statistical and governance disclosure

- `FPR 0.0000` means no false positive was observed among the 25 reviewed
  benign cases. It is a sample estimate, not a 0% production guarantee; the
  rule-of-three upper bound is approximately 12% at 95% confidence for this
  zero-event sample. Canary monitoring must retain the documented FP budget and
  kill switch.
- The review evidence was collected with AI-assisted tooling, while the label
  decisions were entered and attested by `reviewer.vmc`. AI agents are not
  reviewers, and the quarantined AI-filled labels are excluded.
- The `idn_punycode` critical-benign stratum and 35-case double-label target
  are explicit governance waivers for this single-owner scope; they reduce
  assurance and must be accepted by the signing owners.
- The reviewed-unclassifiable waiver excludes 78 reviewed cases from binary
  metrics: 33 model would-block and 45 would-pass. It does not classify these
  cases and does not establish model correctness for them.

### Proposed Waivers
1. **Critical Benign Stratum (`idn_punycode`):** Tất cả 12 tên miền IDN/Punycode trong mẫu đại diện đều ở trạng thái không hoạt động/hết hạn (NXDOMAIN/timeout/parked) với `insufficient evidence`, không có case sống. Chấp nhận waiver không yêu cầu bổ sung case giả định.
2. **Double-label Requirement (Target: 35):** Dự án quy mô đơn người thực hiện (single-reviewer scope). Toàn bộ 137 case đã được rà soát độc lập với bằng chứng chi tiết (`reviewer.vmc`). Chấp nhận waiver yêu cầu người review thứ hai.
3. **Reviewed-unclassifiable (78 cases):** Loại đúng tập case có SHA-256 `efdaa81a8fc9cb6350aff67a1e1513f4b696a71f7d11b3e8c728fcf86e6acb27` khỏi FPR/recall; 33 case would-block phải được coi là uncertainty trong canary, không phải confirmed true positives.

## Product owner decision

- [X] Approve threshold and false-positive budget for the updated metrics
- [X] Approve canary scope and rollback trigger
- [X] Approve IDN, single-reviewer and reviewed-unclassifiable waivers
- Decision/date/owner: August 23, 2026 Vo Manh Cuong - Chooky
## Security owner decision

- [X] Approve source terms and updated evidence handling
- [X] Approve access, retention and reviewed-unclassifiable scope
- [X] Approve staging-to-canary rollout boundary
- Decision/date/owner: August 23, 2026 Vo Manh Cuong - Chooky

Do not enable `enforce` until both owner sections contain explicit approvals.
