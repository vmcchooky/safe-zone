# Xuất tập benign ML-candidate từ false-positive queue

> **Tài liệu Living Document** — Cập nhật đồng bộ mỗi khi có thay đổi.
> Tuân thủ quy tắc tại `.agents/AGENTS.md` Section 5.

## Tóm tắt (Abstract)

Replay bounded-canary đầu tiên không có benign case nào đi qua runtime ML-candidate path, nên `runtime_candidate_false_positive.fpr` không có mẫu số. Công cụ `cmd/ml-fp-candidates` tạo tập bổ sung từ các quyết định `resolved + allow` đã được người vận hành ghi trong false-positive queue. Công cụ lấy analysis config và trusted-brand snapshot đang chạy, bỏ qua override trong bước mô phỏng phản thực tế, rồi chỉ giữ domain có lexical verdict `SUSPICIOUS` — điều kiện để Custom ML được gọi trong runtime. Model bundle local phải khớp revision, version và threshold của `core-api`; runtime phải giữ `shadow/ready`. Contact, report note và review reason không được ghi vào dataset. Snapshot local ngày 2026-08-23 có 0 report, vì vậy công cụ phát hành manifest `empty_queue` và không tạo `labels.csv`; không có nhãn tổng hợp hoặc backfill được dùng thay cho quyết định người vận hành.

## Xuất targeted benign candidate trước staging canary

### Mục tiêu (Objectives)

1. Tạo mẫu số benign chỉ từ false-positive decision có provenance người vận hành.
2. Giữ candidate semantics đồng nhất với lexical gate và model contract đang chạy.
3. Không xuất contact, note hoặc review reason có thể chứa PII hay ticket nội bộ.
4. Chặn replay khi queue trống, candidate count dưới ngưỡng hoặc runtime/bundle bị lệch revision.
5. Không yêu cầu review lại 78 reviewed-unclassifiable case khi không có evidence mới.

### Phương pháp & Lý do (Methodology & Rationale)

| Quyết định | Phương pháp chọn | Các phương pháp thay thế | Lý do |
|---|---|---|---|
| Nguồn benign | Queue record `resolved + allow` có reviewer, review time và reason hợp lệ | Dùng toàn bộ 25 benign trong replay cũ; sinh domain tổng hợp | Queue phản ánh lỗi chặn vận hành; dữ liệu cũ không bảo đảm đi qua ML-candidate path, còn dữ liệu tổng hợp không phải human review |
| Candidate gate | Chạy lại lexical analyzer với config và trusted brands lấy từ runtime; chỉ giữ `SUSPICIOUS` | Lọc theo tên domain hoặc theo probability đã lưu | Cùng điều kiện đầu vào của `classifyML`; không suy diễn candidate từ prediction cũ |
| Model contract | Nạp bundle read-only và đối chiếu revision/version/threshold với status endpoint | Tin vào đường dẫn bundle do operator nhập | Ngăn đánh giá model khác model đang quan sát trong `shadow` |
| Dữ liệu nhạy cảm | Chỉ xuất report ID, reviewer, review time và domain | Copy nguyên API response | Contact, note và reason không cần cho probability/FPR replay |
| Queue trống | Ghi manifest `empty_queue`, không ghi `labels.csv` | Backfill signed packet hoặc tạo record giả | Giữ nguyên nghĩa của provenance và tránh biến test data thành operator evidence |
| Output | Thư mục private mới, tạo qua staging directory rồi rename | Ghi đè packet hoặc append CSV cũ | Tránh partial output và không sửa signed evidence |

Phép đo là counterfactual: domain đã được allow override sẽ không đi tới ML trong traffic thật. Exporter cố ý bỏ override khi chạy lexical gate để trả lời câu hỏi “nếu fix/override chưa tồn tại, model có chặn benign domain đã được xác nhận hay không?”. Kết quả này bổ sung cho telemetry, không thay thế số liệu canary từ traffic thật.

### Cách thức Thực hiện (Implementation Details)

`cmd/ml-fp-candidates` dùng admin API read-only để lấy hai snapshot status, analysis config, trusted brands và toàn bộ trang `status=resolved`. API key được đọc từ file private; biến tiến trình `SAFE_ZONE_ADMIN_API_KEY` chỉ là fallback khi môi trường local chưa provision secret file. Hai status phải giữ nguyên config revision, mode, model revision, version và threshold trong suốt lần chạy. Pagination thất bại nếu total/count thay đổi, report ID bị lặp hoặc số record vượt giới hạn cấu hình.

Mỗi queue record phải có `status=resolved`, `resolution_action=allow`, `review_reason` tối thiểu 8 ký tự, `reviewed_by`, `reviewed_at` và domain hợp lệ. Các report cùng normalized domain được gộp; case ID ổn định là tiền tố `fpq-` cộng 64 bit đầu của SHA-256 domain. CSV tương thích `cmd/ml-replay` qua ba cột bắt buộc `case_id`, `domain`, `human_label`, đồng thời ghi model probability và provenance tối thiểu. Manifest khóa source commit, SHA-256 của config/brand snapshot, hash `SHA256SUMS`, model contract, queue counters và selection statistics.

Output directory phải chưa tồn tại. Công cụ tạo một staging directory cùng filesystem, ghi file với permission `0600`, sau đó rename sang target. Khi không có candidate, manifest vẫn được phát hành nhưng binary trả exit code `2`; `go run` thông báo `exit status 2` nhưng có thể trả wrapper code `1` cho shell. `labels.csv` không tồn tại để tránh replay nhầm tập rỗng hoặc stale file.

Codex (GPT-5) thực hiện audit queue contract, thiết kế exporter, viết test và tài liệu trên một branch riêng. Chiến lược kiểm soát chất lượng sử dụng contract checks, unit/integration test, model/runtime revision comparison và repository CI. Không sử dụng subagent; số lượng subagent là 0. Human-in-the-loop vẫn quyết định một report có phải false positive hay không; AI agent không tạo hoặc sửa operator review.

### Số liệu (Metrics & Results)

| Chỉ số | Kết quả local 2026-08-23 | Ý nghĩa |
|---|---:|---|
| Queue pending/resolved/rejected | 0/0/0 report | Chưa có nguồn thật để tạo targeted dataset |
| Resolved allow có provenance | 0 report | Không phát hành benign label |
| Targeted candidates | 0 domain | `runtime-candidate FPR` vẫn chưa có mẫu số mới |
| Minimum mặc định | 25 domain | Gate ban đầu cho staging replay; không phải production sufficiency claim |
| Contact/note/reason trong CSV | 0 field | Dữ liệu không cần thiết không rời queue API response |
| Focused automated tests | 6 test | Selection, dedup/provenance, pagination, empty output, replay-compatible CSV, commit validation và API-key source |

FPR quan sát được chỉ được tính khi candidate count lớn hơn 0. Với 25 candidate và 0 false positive, zero-event sample vẫn có one-sided 95% upper bound xấp xỉ `1 - 0.05^(1/25) = 11.3%`; do đó ngưỡng 25 chỉ mở phép đo ban đầu, không đủ chứng minh budget FPR nhỏ cho production.

### Liên kết Artifacts

- Exporter: `cmd/ml-fp-candidates/main.go`
- Focused tests: `cmd/ml-fp-candidates/main_test.go`
- Replay evaluator: `cmd/ml-replay/main.go`
- False-positive workflow: `docs/runbooks/false-positive-workflow.md`
- Representative replay runbook: `docs/runbooks/ml-shadow-representative-replay.md`
- Bounded-canary design: `docs/research/ml/bounded-canary-routing-replay.md`

### Giới hạn và bước tiếp theo

- Queue local hiện trống; cần report thật được operator xác nhận `Allow` trước khi có targeted labels.
- Allow decision có thể là business exception. Operator phải chỉ dùng false-positive action khi evidence xác nhận domain benign; exporter không diễn giải free-text reason.
- Brand snapshot được hash nhưng API hiện không cung cấp atomic revision cho brand list. Hai status snapshot khóa config/model, còn thay đổi brand đồng thời vẫn cần operator tránh trong cửa sổ export ngắn.
- Dataset phản thực tế không thay thế fresh production-like telemetry, canary observation window hoặc owner approval.

## Lịch sử Thay đổi (Version History)

| Ngày | Thay đổi | Tác giả |
|---|---|---|
| 2026-08-23 | Thêm exporter có provenance gate, privacy filtering và empty-queue behavior | Codex (GPT-5) |
