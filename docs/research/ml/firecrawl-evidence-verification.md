# Xác minh evidence có giới hạn bằng Firecrawl

> **Tài liệu Living Document** — Cập nhật đồng bộ mỗi khi có thay đổi.
> Tuân thủ quy tắc tại `.agents/AGENTS.md` Section 5.

## Tóm tắt (Abstract)

Curated whitelist replay tạo 14 review group cần đối chiếu evidence hiện tại trước khi xem chúng là false positive đã xác nhận. `cmd/ml-evidence-firecrawl` chuẩn bị và thực thi tối đa một Firecrawl `/scrape` JSON request cho mỗi group, chỉ tới hai evidence host đã phê duyệt trong selection policy. Runner không gọi candidate domain, không follow link, không dùng crawl/agent discovery và mặc định chạy dry-run. API key chỉ được đọc từ secret file local khi có `--execute`; key không được chấp nhận qua flag trực tiếp, source code hoặc output. Mọi input được khóa SHA-256 theo curated replay/data manifest, còn output được ghi vào private directory mới bằng staging + rename. Dry-run ngày 2026-08-23 chọn 14 group, tạo 0 network request và khóa `cases.json` để operator kiểm tra trước khi cấp key mới.

## Bounded Firecrawl evidence verification

### Mục tiêu (Objectives)

1. Xác minh record domain/license trên evidence page chính thức mà không truy cập website đích.
2. Giới hạn external requests ở cohort 14 group đã qua provenance/ICANN/ML gates.
3. Ngăn secret leak, URL expansion, host confusion và ghi đè evidence cũ.
4. Lưu raw Firecrawl envelope cùng structured record để có thể audit extraction.
5. Không biến kết quả LLM extraction thành human label hoặc rollout approval.

### Phương pháp & Lý do (Methodology & Rationale)

| Quyết định | Phương pháp chọn | Các phương pháp thay thế | Lý do |
|---|---|---|---|
| Firecrawl mode | `/v2/scrape` JSON, một exact URL mỗi case | Crawl, Agent, Extract nhiều URL | Scrape JSON là single-page synchronous path, không tự discovery URL |
| Client | Go `net/http` với request/response contract cục bộ | Hard-code code sinh từ SDK; thêm SDK dependency | Giảm dependency, cho phép mock transport và kiểm soát byte/time limits |
| Default | Dry-run, cần `--execute` để gọi API | Gọi API ngay sau khi parse key | Operator kiểm tra 14 prompts/URLs trước external side effect |
| URL scope | Exact HTTPS host `tinnhiemmang.vn`, `giayphep.abei.gov.vn` | Suffix match; follow link | Exact allowlist chặn host confusion và request tới candidate domain |
| Secret | File `ops/secrets/firecrawl_api_key` đã Git-ignore | Key trong code, CLI hoặc chat | Tránh key xuất hiện trong process arguments, source history và artifact |
| Data retention | Private raw envelope + structured record | Chỉ lưu summary | Raw envelope cho phép audit extraction mà không gọi lại API |
| Trust | Kết quả Firecrawl là evidence chưa tin cậy | Tự động tạo `Allow`/benign label | LLM extraction và source membership không chứng minh current safety |

Firecrawl xác nhận Go SDK và `/scrape` JSON mode trong tài liệu chính thức tại `https://docs.firecrawl.dev/sdks/go` và `https://docs.firecrawl.dev/api-reference/endpoint/scrape`. Runner dùng REST v2 trực tiếp nhưng giữ cùng JSON extraction contract.

### Cách thức Thực hiện (Implementation Details)

Runner đọc `manifest.json` và `candidates.csv` của curated replay, xác minh candidates hash được khai báo, rồi đối chiếu `vietnam_websites.csv` với `ml/data/data_manifest.json`. `--runner-commit` bắt buộc khóa exact Git SHA chứa executable logic vào output manifest. Chỉ row có `would_block=true` hoặc `near_threshold=true` được giữ. Tiền tố `www.` được gộp thành một review group; evidence URL giữa các alias phải giống nhau. ABEI group bắt buộc có license number trong snapshot.

Mỗi request body chỉ chứa exact evidence URL, JSON schema, case-specific prompt, `onlyMainContent=true`, `maxAge=0`, `storeInCache=false` và `blockAds=true`. Prompt coi page content là untrusted data, cấm follow link/suy diễn domain safety và yêu cầu `record_found=false` khi domain/license không xuất hiện. Local validator kiểm tra source host, exact evidence URL, canonical requested domain, evidence type, enum values và ABEI license number. Response vượt 4 MiB hoặc sai contract được đánh lỗi; API key không được serialize.

Output gồm `cases.json`, `results.jsonl` khi execute và `manifest.json`. `results.jsonl` lưu HTTP status, response SHA-256, raw response envelope, structured record và validation error. Output directory phải chưa tồn tại; file dùng permission riêng tư trước atomic rename.

Codex (GPT-5) triển khai theo chiến lược contract-first và threat-model prompt/URL/secret boundaries trước HTTP call. Số lượng subagent là 0; không áp dụng bỏ phiếu. Quality control gồm mock HTTP test, host-confusion test, www/bare grouping test, license mismatch test, full Go suite, race detector, static analysis và dry-run checksum verification. Human-in-the-loop rotate/provision key, kiểm tra planned URLs và quyết định evidence có đủ để gán nhãn hay không.

### Số liệu (Metrics & Results)

| Chỉ số dry-run | Kết quả | Diễn giải |
|---|---:|---|
| Planned groups | 14 group | Giới hạn dưới `--max-cases=20` |
| Tín Nhiệm Mạng | 10 exact URL | Mỗi group có detail page riêng |
| ABEI | 4 license group | Dùng 4 license number, cùng registry landing URL |
| Network requests | 0 request | `--execute=false` |
| Candidate-domain requests | 0 request | Candidate domains chỉ nằm trong prompt context |
| Replay manifest SHA-256 | `4d0f5675...d8be380` | Khớp curated run |
| Candidates SHA-256 | `7885591a...e82b0d` | Khớp replay manifest |
| Metadata SHA-256 | `9a3cacb2...76f58` | Khớp data manifest |
| Cases SHA-256 | `980088cf...6b445` | 14 prompts/URLs cố định trong dry-run |

External execution chưa chạy vì key đã xuất hiện trong một kênh không phù hợp để giữ secret và cần được rotate. Đây là intentional security gate, không phải evidence failure.

### Liên kết Artifacts

- Runner: `cmd/ml-evidence-firecrawl/main.go`
- Unit tests: `cmd/ml-evidence-firecrawl/main_test.go`
- Curated replay research: `docs/research/ml/vietnam-whitelist-proxy-replay.md`
- Shadow replay runbook: `docs/runbooks/ml-shadow-representative-replay.md`
- Secret handling: `ops/secrets/README.md`

## Lịch sử Thay đổi (Version History)

| Ngày | Thay đổi | Tác giả |
|---|---|---|
| 2026-08-23 | Thêm bounded Firecrawl runner, dry-run 14 group và secret/output controls | Codex (GPT-5) |
