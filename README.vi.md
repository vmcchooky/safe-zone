# Safe Zone

🌐 **Language / Ngôn ngữ:** [English](README.md) | [Tiếng Việt](README.vi.md)

Safe Zone là dự án mã nguồn mở, phi lợi nhuận phát triển hệ thống chống lừa đảo giả mạo ở cấp độ phân giải DNS, nhằm bảo vệ người dùng và tổ chức tại Việt Nam khỏi các trang web lừa đảo (phishing) và giả mạo thương hiệu.

Dự án đang trong giai đoạn phát triển tích cực. Kho chứa mã nguồn này mô tả kiến trúc và mã nguồn liên tục được hoàn thiện nhằm cung cấp một công cụ hữu ích cho cộng đồng; hệ thống không cam kết bao phủ 100% mối đe dọa hoặc sẵn sàng cho mọi kịch bản triển khai. Định hướng công khai được tóm tắt tại [trang dự án Safe Zone](https://www.quorix.io.vn/projects/safe-zone/).

Tài liệu chuẩn cho người vận hành triển khai production được lưu trữ tại [docs/production-completion-checklist.md](docs/production-completion-checklist.md). Các ghi chú thiết kế và tài liệu lịch sử nằm tại thư mục [docs/specs/](docs/specs/).

## Định hướng dự án

- **Phạm vi (Scope):** Chống lừa đảo ở cấp độ DNS và phân tích rủi ro tên miền cho người dùng và tổ chức tại Việt Nam.
- **Trạng thái hiện tại:** Đang phát triển; các tính năng, tích hợp và hướng dẫn vận hành liên tục được cập nhật.
- **Mục tiêu:** Hệ thống mã nguồn mở phục vụ cộng đồng, hỗ trợ lọc tên miền độc hại thông qua chính sách nội bộ và dữ liệu đe dọa (threat intelligence).
- **Phương pháp cốt lõi:** Các dịch vụ viết bằng Go, hỗ trợ DoH và DoT, phân tích cấu trúc ký tự (lexical analysis), dữ liệu đe dọa, tinh chỉnh tùy chọn qua AI nội bộ, và giao diện quản trị self-hosted.

## Các thành phần hiện tại

- `core-api`: HTTP API cung cấp kiểm tra trạng thái, cache kết quả phân tích tên miền, endpoint `/metrics`, và giao diện quản trị React self-hosted.
- `dns-resolver`: Dịch vụ chính sách phân giải DNS nội bộ hỗ trợ DoH (`/dns-query`), tùy chọn DoT, và `/metrics`.
- `feed-syncd`: Daemon chạy định kỳ tùy chọn để đồng bộ dữ liệu đe dọa từ các nguồn bên ngoài.
- `redis`: Bộ nhớ đệm (cache) tùy chọn lưu trữ kết quả phân tích và lịch sử dashboard.
- `internal/analysis`: Thư viện tính điểm rủi ro tên miền dựa trên quy tắc cấu trúc ký tự (lexical scoring).
- `internal/cache`: Thư viện thao tác Redis JSON hỗ trợ cơ chế fail-open.
- `internal/feed`: Thư viện phân tích và đồng bộ feed dùng chung cho CLI và daemon.
- `internal/ai`: Tùy chọn tinh chỉnh phân tích tên miền nghi ngờ qua Gemini 2.5 Flash Lite.
- `internal/observability`: Thư viện ghi nhận metrics trong bộ nhớ dùng chung cho các HTTP service.
- `internal/risk`: Dịch vụ phân tích rủi ro, cache, chính sách và trạng thái dùng chung.
- `internal/serve`: Thư viện hỗ trợ graceful shutdown cho container và runtime cục bộ.

## Không gian làm việc Frontend

- `ui/`: Mã nguồn React cho giao diện quản trị chính, được đóng gói và phục vụ bởi `core-api` tại `/app/*`.
- `internal/api/views`: HTML template tương thích cho legacy dashboard, màn hình đăng nhập và trang cảnh báo chặn.
- `internal/api/assets`: Tài nguyên CSS, JS, font được phục vụ tại `/assets/*` bởi `core-api`.
- `internal/api/handlers`: Xử lý logic cho các HTTP endpoint.

## Chạy cục bộ (Local Run)

```bash
go run ./cmd/core-api
go run ./cmd/dns-resolver
```

Cấu hình mặc định:

- `core-api` lắng nghe tại cổng `:8080`
- `dns-resolver` lắng nghe tại cổng `:8081`
- Redis mặc định tắt trừ khi biến `SAFE_ZONE_REDIS_ADDR` được thiết lập
- Dashboard chính: <http://localhost:8080/app/>
- Đường dẫn `/dashboard` sẽ tự động chuyển hướng về dashboard chính

Bật Redis cục bộ tùy chọn:

```bash
docker run --rm -p 6379:6379 redis:7-alpine
$env:SAFE_ZONE_REDIS_ADDR = "localhost:6379"
```

Các endpoint hữu ích:

```bash
curl "http://localhost:8080/"
curl "http://localhost:8080/metrics"
curl "http://localhost:8080/v1/analyze?domain=secure-login-wallet-example.com"
curl "http://localhost:8081/"
curl "http://localhost:8081/metrics"
curl "http://localhost:8081/v1/policy?domain=secure-login-wallet-example.com"
```

Trải nghiệm trang cảnh báo chặn (Block Page):

- `http://blocked.example.test/` có thể được điều hướng về trang cảnh báo Safe Zone trên môi trường production.
- `https://$SAFE_ZONE_PUBLIC_HOST/block?domain=blocked.example.test` cung cấp trang giải thích HTTPS chuẩn.
- Truy cập HTTPS trực tiếp tới tên miền bên thứ ba bị chặn vẫn phụ thuộc vào chứng chỉ SSL của tên miền đó và có thể hiển thị cảnh báo từ trình duyệt trước khi nạp trang block.

## Dữ liệu đe dọa (Threat Feed)

Danh sách tên miền đe dọa được chuẩn hóa và lưu trữ tại Redis Set `safe-zone:threat:feed`. Chạy đồng bộ thủ công qua `feed-sync`:

```bash
go run ./cmd/feed-sync -source ./feeds/local.txt -dry-run
go run ./cmd/feed-sync -source ./feeds/local.txt -redis-addr localhost:6379
```

Công cụ đồng bộ hỗ trợ các tệp tin `.gz` qua đường dẫn cục bộ hoặc URL HTTP(S).
Daemon tùy chọn có thể chạy bằng `go run ./cmd/feed-syncd --once` hoặc qua Docker Compose profile `feed-sync`.

Định dạng feed hỗ trợ gồm TXT, CSV, tệp nén gzip, và danh sách URL phân tách bằng khoảng trắng như OpenPhish. Các tên miền khớp chính xác hoặc khớp tên miền con đều trả về kết quả `MALICIOUS` với lý do `matched local threat feed`.

Đối với cấu hình production miễn phí chuẩn, thiết lập:

```env
SAFE_ZONE_AGENT_FEED_PRESET=production-free
```

Cấu hình này tự động mở rộng sang dữ liệu URLhaus CSV mới nhất và OpenPhish community feed. `core-api` cung cấp thông tin độ tươi dữ liệu, cảnh báo dữ liệu cũ, và metadata phiên bản feed trên endpoint `/` và `/metrics` khi Redis hoạt động.

Để mở rộng tập quét cho môi trường Việt Nam, sử dụng:
`SAFE_ZONE_AGENT_FEED_PRESET=production-vn`. Cấu hình này bổ sung PhishDestroy Primary Active và Phishing.Database Active vào tập toàn cầu. Đây là các tập dữ liệu toàn cầu được lựa chọn làm baseline mở rộng cho Việt Nam, không phải dữ liệu riêng biệt của Việt Nam. Các danh sách chặn quảng cáo/tracker thông thường được loại trừ chủ đích vì mọi kết quả khớp feed đe dọa đều xử lý ở mức độc hại (`MALICIOUS`). Chi tiết xem tại `docs/research/security/threat-intelligence-sources.md`.

Endpoint DoH hỗ trợ các yêu cầu DNS chuẩn dạng GET hoặc POST tại:

```text
http://localhost:8081/dns-query
```

Khi chạy Docker dev stack, dịch vụ DoT hỗ trợ tại:

```text
tls://127.0.0.1:1853
```

## Động cơ AI (AI Engine)

Safe Zone duy trì cơ chế phân tích deterministic sẵn có và hỗ trợ tinh chỉnh các kết quả nghi ngờ thông qua các provider: `none`, `gemini`, `ollama`, hoặc chế độ ưu tiên Ollama `hybrid`. Bộ phân loại ML tên miền tùy chỉnh (Custom Domain ML) đã được tích hợp thành lớp chấm điểm local độc lập với các chế độ `disabled`, `shadow`, và `enforce`; mặc định vẫn là `disabled` cho tới khi hoàn tất provisioning artifact và evidence rollout của Phase 5.

Các sự cố từ AI/ML/provider luôn tuân thủ nguyên tắc **fail-open** ngoại trừ trường hợp người vận hành yêu cầu bắt buộc bundle mô hình khi khởi động. Chi tiết kiến trúc, cấu hình, vòng đời dữ liệu và quy trình vận hành được mô tả tại [docs/specs/safe-zone-ai-plan.md](docs/specs/safe-zone-ai-plan.md). Trạng thái phát hành được theo dõi tại [docs/production-completion-checklist.md](docs/production-completion-checklist.md).

Cấu hình runtime Custom ML:

```env
SAFE_ZONE_ML_MODE=disabled
SAFE_ZONE_ML_BUNDLE_DIR=/app/models/safe-zone/current
SAFE_ZONE_ML_REQUIRED=false
SAFE_ZONE_ML_BLOCK_THRESHOLD=
```

Bundle v1 gồm 534 features, suy luận LightGBM bằng `leaves`, Platt calibration, policy metadata và kiểm tra SHA-256. `shadow` chỉ ghi prediction/telemetry; `enforce` chỉ được promote kết quả lexical `SUSPICIOUS` khi xác suất calibrated đạt threshold đã phê duyệt. Bundle lỗi vẫn fail-open, trừ khi đặt `SAFE_ZONE_ML_REQUIRED=true`.

## Cấu hình Phân tích Động (Dynamic Analysis Configuration)

Phản hồi WHOIS được cache trong SQLite mặc định 7 ngày. Có thể ghi đè thời gian sống qua biến `SAFE_ZONE_WHOIS_CACHE_TTL_DAYS`.

Quản trị viên có thể xem và tinh chỉnh cấu hình chấm điểm cấu trúc ký tự mà không cần khởi động lại dịch vụ:

- `GET /v1/config/analysis`
- `PUT /v1/config/analysis`
- `POST /v1/config/analysis/reset`

Các cập nhật được xác thực, lưu vào SQLite, nạp lại tự động vào bộ phân tích (hot-reload), và hủy hiệu lực cache qua phiên bản cấu hình.

Trong môi trường triển khai multi-node, việc đồng bộ cấu hình giữa các node được kiểm soát qua:

- `SAFE_ZONE_CONFIG_RELOAD_ENABLED=true`
- `SAFE_ZONE_CONFIG_RELOAD_CHANNEL=safe-zone:config:analysis:updated`
- `SAFE_ZONE_CONFIG_RELOAD_POLL_SECONDS=30`

## Môi trường Bảo mật (Secrets)

Cấu hình bảo mật có thể truyền qua biến môi trường `VAR=value` hoặc tệp tin `VAR_FILE=./ops/secrets/name`.

Thư mục bí mật dùng chung [ops/secrets/README.md](ops/secrets/README.md) áp dụng cho:

- Lệnh `go run` cục bộ từ gốc dự án
- Các dịch vụ Docker Compose (gắn kết `./ops/secrets` vào `/app/ops/secrets`)
- Cập nhật DuckDNS từ phía host

Khi cấu hình `SAFE_ZONE_ENV=production`, `core-api` sẽ dừng khởi động nếu:

- `SAFE_ZONE_ADMIN_PASSWORD` thiếu hoặc yếu
- `SAFE_ZONE_ADMIN_API_KEY` thiếu hoặc yếu

Ở chế độ cục bộ, các khóa thiếu sẽ tự động sinh giá trị tạm thời để thuận tiện phát triển.

## Tiến trình Agent (Agent Workflow)

`core-api` có thể kích hoạt Agent Engine nội bộ phục vụ kiểm toán, đồng bộ đa nguồn feed, kiểm toán OSINT, phát cảnh báo đa kênh và làm sạch danh sách trắng (whitelist). Dashboard cung cấp giao diện theo dõi trạng thái và kích hoạt thủ công cho admin.

## Ghi nhật ký và Cảnh báo (Logging and Alerts)

Phản hồi HTTP trả về header `X-Request-ID`. Pipeline yêu cầu chính xuất log JSON có cấu trúc cho `core-api` và `dns-resolver`, các tác vụ nền sử dụng chung `run_id` để liên kết nhật ký.

Bộ quy tắc cảnh báo JSON metrics nằm tại [ops/alerts/safe-zone-alert-rules.yaml](ops/alerts/safe-zone-alert-rules.yaml), quy trình kiểm tra nằm tại [docs/runbooks/alert-rules.md](docs/runbooks/alert-rules.md).

## Kiểm tra Bảo mật (Security Review)

Trước khi phát hành bản phát hành lớn, sử dụng danh sách kiểm tra bảo mật tiền phát hành tại [docs/security/pre-release-security-checklist.md](docs/security/pre-release-security-checklist.md) kết hợp với [docs/runbooks/pre-release-checklist.md](docs/runbooks/pre-release-checklist.md).

## Biên dịch (Build)

```bash
go build ./...
```

## Kiểm thử CI (CI Release Gate)

GitHub Actions chạy lệnh `mise run ci` trên mỗi lượt push và pull request. Tiến trình kiểm tra bao gồm Go lint/test/build, kiểm tra kiểu React và đóng gói bundle, kiểm thử E2E Playwright cô lập, `gosec`, `govulncheck`, và đóng gói Docker cho từng dịch vụ.

## Docker

```bash
cp .env.example .env
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

Môi trường dev chỉ lắng nghe cổng loopback cho `core-api`, `dns-resolver`, và DoT. Môi trường production sử dụng `docker-compose.production.yml`, giữ `8080` và `8081` trên loopback, chỉ mở công khai cổng `80`, `443`, và `853`.

## Vận hành (Operations)

Sử dụng công cụ PowerShell helper cho công việc vận hành và bảo trì hàng ngày:

```powershell
pwsh ./scripts/ops/safe-zone.ps1 deploy
pwsh ./scripts/ops/safe-zone.ps1 deploy-dev
pwsh ./scripts/ops/safe-zone.ps1 status
pwsh ./scripts/ops/safe-zone.ps1 backup
pwsh ./scripts/ops/safe-zone.ps1 restore
pwsh ./scripts/ops/safe-zone.ps1 prune
pwsh ./scripts/ops/safe-zone.ps1 feed-sync
```

- `deploy`: Biên dịch, khởi chạy Compose stack, và chờ kiểm tra sức khỏe dịch vụ.
- `deploy-dev`: Khởi chạy dev stack nội bộ lắng nghe cổng loopback.
- `backup`: Tạo bản sao lưu Redis RDB vào `backups/redis/<timestamp>/dump.rdb`.
- `restore`: Nạp lại dữ liệu Redis từ bản sao lưu mới nhất hoặc đường dẫn chỉ định.
- `prune`: Dọn dẹp bản sao lưu cũ và xóa các tệp `tmp/*.log` hết hạn.
- `feed-sync`: Đồng bộ dữ liệu đe dọa từ các nguồn cấu hình.

Trên Linux host, script tương đương `scripts/ops/safe-zone.sh` hỗ trợ các tham số tương tự.
Các thao tác trên cũng có sẵn dưới dạng các task `mise` định nghĩa tại [mise.toml](mise.toml).

## Cấu hình Hạ tầng Cơ bản (Deployment Baseline)

- Mục tiêu triển khai production mặc định: 1 máy chủ VPS tiết kiệm chi phí
- Cấu hình đề xuất: Hetzner CPX21 hoặc tương đương (2 vCPU / 4 GB RAM)
- Ngân sách hạ tầng tối đa: khoảng $10/tháng

## Dịch vụ Tùy chọn (Optional Services)

- Redis là tùy chọn cho môi trường phát triển cục bộ và giữ trạng thái tắt trừ khi cài đặt `SAFE_ZONE_REDIS_ADDR`.
- `feed-syncd` là tùy chọn và chỉ chạy khi kích hoạt profile Compose `feed-sync`.
- Metrics, kiểm tra sức khỏe và giao diện quản trị hoạt động ở chế độ self-hosted, không phụ thuộc vào hạ tầng SaaS bên ngoài.

## Giấy phép (License)

Dự án được phân phối theo giấy phép mã nguồn mở MIT - xem chi tiết tại tệp [LICENSE](LICENSE).
