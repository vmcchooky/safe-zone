# Đánh giá phản thực tế trên whitelist Việt Nam

> **Tài liệu Living Document** — Cập nhật đồng bộ mỗi khi có thay đổi.
> Tuân thủ quy tắc tại `.agents/AGENTS.md` Section 5.

## Tóm tắt (Abstract)

False-positive queue local chưa có report thật nên không thể tạo tập benign ML-candidate có nhãn người vận hành. `cmd/ml-whitelist-proxy` cung cấp phép đo bổ sung bằng cách chạy offline snapshot whitelist Việt Nam như thể runtime whitelist không tồn tại. Công cụ không tắt hoặc sửa whitelist, không gửi DNS/HTTP request tới domain, không tạo report hay quyết định `Allow`, và chỉ chạy ML cho domain có lexical verdict `SUSPICIOUS` giống candidate gate của runtime. Kết quả được gọi là `whitelist-proxy FPR`: đây là chỉ báo sàng lọc để tìm case cần review, không phải FPR đã xác nhận bằng human label.

## Mục tiêu (Objectives)

1. Tạo mẫu số benign proxy từ dữ liệu local có provenance thay vì chờ traffic thật.
2. Đo tỷ lệ domain trong snapshot sẽ bị model chặn nếu không có whitelist bảo vệ.
3. Xác định riêng danh sách `would-block` và probability gần threshold để ưu tiên review.
4. Khóa source SHA, data manifest, runtime config, trusted brands, bundle revision và threshold trong một report mới.
5. Giữ `core-api` ở `shadow/ready` và không thay đổi service, config, traffic hoặc signed evidence.

## Phương pháp & Lý do (Methodology & Rationale)

| Quyết định | Phương pháp chọn | Phương pháp thay thế | Lý do |
|---|---|---|---|
| Nguồn | `data/whitelist/vietnam/vietnam_domains.txt` được đối chiếu với `ml/data/data_manifest.json` | Truy cập trực tiếp hàng loạt website; tự tạo report giả | Snapshot local không tạo external side effect; report giả làm sai provenance vận hành |
| Nhãn | Ghi `proxy_label=benign_proxy` | Ghi `human_label=benign` | List membership không chứng minh domain hiện an toàn hoặc đã được con người duyệt |
| Candidate gate | Chỉ gọi model khi lexical verdict là `SUSPICIOUS` | Chạy model cho mọi domain | Khớp đường chạy ML thực tế và cho phép báo cả FPR trên toàn whitelist lẫn block rate có điều kiện |
| Runtime contract | Đọc status/config/brands, yêu cầu `shadow/ready/enabled`, đối chiếu bundle revision/version/threshold | Chỉ dùng config mặc định trong source code | Tránh đo một policy khác policy local staging đang quan sát |
| Near-threshold | `abs(probability - threshold) <= margin`, mặc định `0.05` | Chỉ xem case vượt threshold | Case sát biên dễ đổi quyết định khi calibration/threshold thay đổi |
| Output | Tạo thư mục private mới bằng staging + rename | Ghi đè representative packet | Giữ report tạm biệt lập và không sửa evidence đã ký |

`whitelist_proxy_fpr = would_block / unique_proxy_benign_domains`. Chỉ số phụ `candidate_conditional_block_rate = would_block / ml_candidate_domains` mô tả model sau lexical gate. Hai mẫu số phải được báo riêng; tỷ lệ có điều kiện không được trình bày như FPR trên toàn bộ whitelist.

## Cách thức Thực hiện (Implementation Details)

`cmd/ml-whitelist-proxy` đọc file newline-delimited một lần qua `io.TeeReader`: cùng luồng dữ liệu được đếm byte, băm SHA-256, chuẩn hóa, loại trùng và đánh giá. Công cụ dừng nếu logical source không tồn tại trong manifest, đường dẫn không khớp, SHA/byte size lệch hoặc số domain vượt giới hạn. Invalid/blank/duplicate được ghi riêng để không làm mờ mẫu số.

Trước đánh giá, công cụ lấy `/v1/status`, `/v1/config/analysis` và `/v1/brands` bằng admin API read-only. Model bundle local phải tự vượt checksum verification và khớp runtime model revision, version, threshold. Sau đánh giá, status được đọc lại; thay đổi config revision, mode, state hoặc model contract làm lần chạy thất bại. Ba CSV private được phát hành:

- `candidates.csv`: mọi lexical `SUSPICIOUS` domain đã đi qua model;
- `would-block.csv`: probability lớn hơn hoặc bằng threshold;
- `near-threshold.csv`: probability cách threshold không quá margin.

Manifest ghi SHA-256 và row count của từng CSV, cùng source/data-manifest/bundle/config/brand hashes. Case ID là tiền tố `wlp-` cộng 64 bit đầu SHA-256 của normalized domain. Output dùng permission riêng tư và target directory phải chưa tồn tại.

Codex (GPT-5) thực hiện thiết kế, triển khai, unit test và local replay theo chiến lược prompt contract-first: khóa các điều kiện bất biến về provenance, runtime mode và checksum trước khi xử lý domain. Không dùng subagent; số lượng subagent là 0 và không áp dụng bỏ phiếu. Cơ chế kiểm soát chất lượng gồm unit test, full Go test suite, static analysis, kiểm tra checksum và đối chiếu status đầu/cuối. AI agent không duyệt domain và không biến list membership thành operator decision. Human-in-the-loop chỉ cần review các case ưu tiên được report chỉ ra trước khi dùng chúng như ground truth hoặc quyết định policy.

## Lệnh chạy (Run Procedure)

```powershell
$env:SAFE_ZONE_ADMIN_API_KEY = <process-scoped-key>
go run ./cmd/ml-whitelist-proxy `
  --api-url http://127.0.0.1:8080 `
  --bundle <immutable-bundle> `
  --source data\whitelist\vietnam\vietnam_domains.txt `
  --data-manifest ml\data\data_manifest.json `
  --source-logical-name vietnam_domains.txt `
  --source-commit <exact-40-character-git-sha> `
  --near-threshold-margin 0.05 `
  --output <new-private-run>
Remove-Item Env:SAFE_ZONE_ADMIN_API_KEY
```

Không ghi API key vào history hoặc report. Có thể dùng `--admin-api-key-file` trỏ tới private secret file thay cho biến tiến trình.

## Số liệu (Metrics & Results)

| Chỉ số | Kết quả run `run-20260823-vietnam-whitelist-proxy-216a024` | Diễn giải |
|---|---:|---|
| Source lines | 656.983 domain | Snapshot whitelist Việt Nam ngày 2026-07-28 |
| Unique proxy-benign | 656.972 domain | Có 11 dòng bị normalizer loại và 0 normalized duplicate |
| Lexical `SAFE` | 425.713 domain | Không đi vào ML candidate path |
| Lexical `SUSPICIOUS` | 226.052 domain | 34,408% snapshot; toàn bộ được model đánh giá offline |
| Lexical `MALICIOUS` | 5.207 domain | 0,793% snapshot; bị deterministic policy loại trước ML |
| ML would-block | 37 domain | Probability lớn hơn hoặc bằng 0,85 |
| ML whitelist-proxy FPR | 0,005632% | 37 / 656.972; chỉ số proxy, không phải human-labelled FPR |
| Candidate-conditional block rate | 0,016368% | 37 / 226.052 lexical candidate |
| Near-threshold | 21 domain | Margin tuyệt đối 0,05 quanh threshold |
| Review union | 47 domain | Hợp của would-block và near-threshold, trùng 11 domain |
| Source SHA-256 | `5d8b902d...7c0c1807` | Phải khớp data manifest trước khi report hợp lệ |
| Trust tier trong manifest | `strong-safe` | Tên phân tầng của pipeline, không thay human label |
| Terms review | `pending-review` | Chưa đủ điều kiện để tuyên bố source terms đã được phê duyệt |
| Runtime contract | `shadow/ready`, model `1.0.0`, threshold `0,85` | Core API giữ nguyên contract ở status đầu/cuối |
| Runtime whitelist loaded | 0 domain | Agent local đang disabled; run đánh giá data snapshot, không phải active runtime list |
| Output checksum verification | 3/3 file khớp | `candidates.csv`, `would-block.csv`, `near-threshold.csv` |

Run dùng source commit `216a02458f8d4e5aba68f9f740a79c29053255f8`; manifest SHA-256 là `8d6b0ce6adf2536dbe4afe980778dfe9bb5e9d9ccb36d5edc94681571f730547`. Ba output CSV khớp checksum khai báo trong manifest. Core API và DNS resolver sau run cùng healthy, cùng config revision `ecb8a74f314e3df1`, model revision `4632f9ea...f92c3bca`, policy revision `5583f307...ae646`, threshold `0,85`, `ml_state=ready`, `errors=0` và `enforce_promotions=0`.

## Giới hạn và giải pháp tối ưu

- Snapshot trộn nguồn thu thập với candidate được sinh theo quy tắc rồi xác minh DNS/TCP; DNS/service availability tại thời điểm cũ không chứng minh an toàn nội dung hiện tại.
- Một số row would-block có pseudo-TLD hoặc chuỗi giống candidate sinh tự động. Chưa nên giao toàn bộ 47 row cho operator review trước khi lọc provenance mạnh hơn từ `vietnam_websites.csv`.
- `terms_review_id=pending-review` là provenance gap. Report phù hợp cho R&D local, chưa phù hợp để làm signed production approval evidence.
- Domain có thể đổi chủ hoặc bị compromise sau ngày retrieval. `would-block` là queue ưu tiên review, không phải lỗi model đã xác nhận.
- Giải pháp tối ưu trước staging canary là review có mục tiêu: ưu tiên toàn bộ `would-block`, sau đó near-threshold critical strata; không review lại hàng trăm nghìn domain và không review lại 79 case cũ nếu không có evidence mới.
- Khi có report thật, tập `cmd/ml-fp-candidates` vẫn là nguồn mạnh hơn vì có operator decision. Whitelist proxy bổ sung coverage, không thay thế feedback loop thật.

## Liên kết Artifacts

- Evaluator: `cmd/ml-whitelist-proxy/main.go`
- Unit tests: `cmd/ml-whitelist-proxy/main_test.go`
- Data manifest: `ml/data/data_manifest.json`
- Source provenance: `docs/research/ml/resource.md`
- Targeted queue exporter: `docs/research/ml/targeted-benign-candidate-export.md`
- Replay runbook: `docs/runbooks/ml-shadow-representative-replay.md`

## Lịch sử Thay đổi (Version History)

| Ngày | Thay đổi | Tác giả |
|---|---|---|
| 2026-08-23 | Thêm thiết kế whitelist-proxy replay, provenance gates và cách diễn giải FPR | Codex (GPT-5) |
| 2026-08-23 | Ghi kết quả replay 656.983 dòng, runtime parity và hạn chế chất lượng nguồn | Codex (GPT-5) |
