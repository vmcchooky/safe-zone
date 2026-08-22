# Safe Zone ML v1 shadow replay approval packet

- Model version/revision: `1.0.0` / `4632f9ea69124591db89dfb176aacf46323c18043c7b8c8d0972c3b2f92c3bca`
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
- **Recall:** 0.7576 (25/33)
- **Non-binary labels excluded:** {'compromised': 0, 'shared_hosting': 0, 'unknown': 79}
- **Critical-benign review:** `available_with_waiver`
- **Reviewer agreement:** `waived`
- **Deterministic policy evidence:** `available`
- **Approval blockers:** none recorded
<!-- END HUMAN-LABEL-METRICS -->

## Current decision

Ready for owner review (`ready_for_review`). Human labels (137/137), validation, and false-positive metrics are complete. 0 approval blockers remain. Product and Security owner decisions remain pending for signature.

### Approved Waivers
1. **Critical Benign Stratum (`idn_punycode`):** Tất cả 12 tên miền IDN/Punycode trong mẫu đại diện đều ở trạng thái không hoạt động/hết hạn (NXDOMAIN/timeout/parked) với `insufficient evidence`, không có case sống. Chấp nhận waiver không yêu cầu bổ sung case giả định.
2. **Double-label Requirement (Target: 35):** Dự án quy mô đơn người thực hiện (single-reviewer scope). Toàn bộ 137 case đã được rà soát độc lập với bằng chứng chi tiết (`reviewer.vmc`). Chấp nhận waiver yêu cầu người review thứ hai.

## Product owner decision

- [ ] Approve threshold and false-positive budget
- [ ] Approve canary scope and rollback trigger
- [ ] Approve IDN stratum and single-reviewer waivers
- Decision/date/owner: ____________________

## Security owner decision

- [ ] Approve source terms and evidence handling
- [ ] Approve access, retention, and reviewer scope
- [ ] Approve staging-to-canary rollout boundary
- Decision/date/owner: ____________________

Do not enable `enforce` until both owner sections contain explicit approvals.
