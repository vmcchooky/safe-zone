# Ổn định Task Graph và Toolchain của CI (`mise.toml`)

> **Tài liệu Living Document** — Cập nhật đồng bộ mỗi khi CI, toolchain hoặc release preflight thay đổi.
> Tuân thủ quy tắc tại `.agents/AGENTS.md` Section 5.

## Tóm tắt (Abstract)

Safe-Zone từng có lỗi CI tại `golangci-lint`: module khai báo Go 1.25.0 nhưng `mise` và Docker vẫn dùng Go 1.24, trong khi linter được build bằng Go 1.24 không thể phân tích target Go 1.25. Sau đó CI còn phát hiện checksum model khác nhau giữa Windows CRLF và Ubuntu LF. Bản vá ban đầu đồng bộ runtime về Go 1.25.12, nâng cấu hình linter sang schema v2, pin các scanner bảo mật và canonicalize line ending trước khi hash bundle. Preflight ngày 2026-08-22 tiếp tục nâng toolchain build lên Go 1.26.7 sau khi Go 1.26.4 phát hiện vulnerability reachable trong standard library, đồng thời pin Python 3.13.14 cho ML verification.

## Mục tiêu (Objectives)

- Khôi phục `mise run ci` với toolchain có thể tái lập.
- Giữ `go.mod`, `mise.toml`, Docker build và release preflight trên cùng nhánh tương thích Go.
- Pin Python dùng cho ML verification và khai báo đầy đủ dependency import trực tiếp.
- Bảo toàn hành vi model/feature contract; các thay đổi mã nguồn chỉ xử lý lỗi kiểm tra tài nguyên, invariant biên và đóng tài nguyên.
- Đảm bảo checksum model bundle cho kết quả giống nhau trên checkout Windows CRLF và Linux LF.
- Đảm bảo UI bundle, Go test/build/vet, linter, security scan và E2E có bằng chứng kiểm thử rõ ràng.

## Phương pháp và lý do (Methodology & Rationale)

| Quyết định | Phương pháp chọn | Phương án thay thế | Lý do |
|---|---|---|---|
| Đồng bộ Go | Pin `go = "1.26.7"` trong `mise.toml` và `golang:1.26.7-alpine` trong Docker; giữ `go 1.25.0` là language target tối thiểu trong `go.mod` | Giữ 1.25.12/1.26.4 hoặc hạ module target | Go 1.26.4 còn vulnerability standard-library có đường gọi; 1.26.7 là patch release đã xác minh và vẫn build module target 1.25. |
| Đồng bộ Python ML | Pin `python = "3.13.14"`; khai báo `pandas==2.2.3` và `idna==3.18` bên cạnh các dependency hiện có | Dựa vào package global cài ngầm | Import trực tiếp nhưng không khai báo làm full suite không tái lập; môi trường biệt lập xác nhận toàn bộ pin tương thích. |
| Nâng linter | Pin `golangci-lint = "2.12.2"`, thêm `version: "2"`, migrate `default: none`, gộp `gosimple` vào `staticcheck` | Giữ `golangci-lint` v1.64.5 hoặc tắt linter | Binary v1 hiện tại được build bằng Go 1.24 nên không đọc được target Go 1.25; tắt linter làm giảm coverage chất lượng mã. |
| Cách ly artifact local | Loại `^tmp/` khỏi package discovery của linter | Xóa artifact tạm trước mỗi lần lint hoặc sửa các script không tracked | `tmp/` bị Git ignore nhưng `go list ./...` vẫn nhìn thấy package Go local; exclusion giữ local CI tái lập mà không giảm coverage trên source tracked. |
| Pin security scanner | Dùng `gosec@v2.28.0` và `govulncheck@v1.4.0` trong `mise` và cả hai script release preflight | Tiếp tục dùng `@latest` | Phiên bản trôi nổi có thể tự yêu cầu toolchain mới hoặc thay đổi kết quả CI giữa hai lần chạy. |
| Xử lý security finding | Giữ invariant bundle file name cố định, ghi rõ suppression cục bộ có lý do, và thêm guard chỉ số TF-IDF | Tắt rule G304/G602 toàn cục | Giới hạn phạm vi suppression và giữ các rule khác hoạt động đầy đủ. |
| Canonicalize bundle checksum | Chuẩn hóa `CRLF` thành `LF` trước SHA-256 và lưu hash canonical trong `ml/models/v1/SHA256SUMS` | Lưu hash theo line ending của từng máy | Hash theo môi trường làm CI Linux từ chối bundle hợp lệ đã pass trên Windows. Canonical text hashing giữ integrity invariant mà không đổi nội dung model. |

## Chi tiết triển khai (Implementation Details)

- **Mô hình AI Agent:** Codex (GPT-5).
- **Chiến lược:** Audit tĩnh toàn bộ workflow, task, script và version pin; chạy từng task độc lập; sửa theo output thực tế; chạy lại bằng đúng Go/Python đã pin.
- **Subagents/voting:** Không sử dụng subagent hoặc voting; kết luận dựa trên output CI và các lệnh kiểm tra tái hiện được.
- `.golangci.yml` được migrate sang schema v2 và giữ tập linter có chủ đích: `errcheck`, `govet`, `ineffassign`, `staticcheck`, `unused`.
- `.golangci.yml` loại `tmp/` khỏi lint vì đây là vùng evidence/workbench bị
  Git ignore; source tracked vẫn được lint đầy đủ.
- Khóa v1 `issues.exclude-use-default` được loại bỏ sau khi `config verify`
  xác nhận khóa này không hợp lệ trong schema v2; cấu hình hiện được kiểm tra
  schema trước khi chạy lint.
- Các lỗi `errcheck` được sửa bằng cách xử lý tường minh kết quả `Close`; các lỗi `staticcheck` được sửa bằng tagged switch, selector được promote và `fmt.Fprintf`.
- `golang.org/x/text` được nâng lên `v0.39.0` cùng các module liên quan do `govulncheck` xác định bản `v0.38.0` có lỗi.
- `internal/analysis/ml_classifier.go` canonicalize `CRLF` → `LF` khi hash model/manifest/calibration/policy; `ml/tests/model_bundle_test.go` dùng cùng quy tắc để golden revision không phụ thuộc OS.
- `ml/models/v1/SHA256SUMS` và golden `bundle_revision` được cập nhật theo canonical hashes; model bytes, feature values và inference logic không thay đổi.
- Release preflight PowerShell và shell dùng cùng phiên bản scanner với task CI.
- Các runbook release gọi helper qua đường dẫn chuẩn `scripts/ops/`; đường dẫn
  cũ dưới `scripts/` bị loại vì không còn khớp cấu trúc script đã phân loại.
- `mise.toml` pin Go 1.26.7 và Python 3.13.14; Docker build stage dùng
  `golang:1.26.7-alpine`. `ml/pyproject.toml` khai báo thêm hai dependency
  import trực tiếp là `pandas` và `idna`.

## Số liệu và kết quả (Metrics & Results)

- `golangci-lint v2.12.2 run`: **0 issues**.
- `gosec v2.28.0` trên Go 1.25.12: **0 issues**.
- `govulncheck v1.4.0` trên Go 1.25.12: **0 vulnerabilities có đường gọi**.
- UI typecheck/build: pass; Playwright E2E: **4/4 pass**.
- Go test, build và vet: pass khi chạy tuần tự.
- Bundle parity tests: pass trên Windows checkout; canonical hash `4ced615d...`, revision `4632f9ea...`.
- Kết quả lịch sử 2026-08-08 dùng `golang:1.25.12-alpine`; Docker build local
  không chạy do daemon không khả dụng và được giao cho job `docker-build` sau
  `quality`.
- Preflight 2026-08-22 với Go 1.26.7: `go test ./...` pass, `go build ./...`
  pass và `govulncheck@v1.4.0` báo 0 vulnerability reachable. Tag
  `golang:1.26.7-alpine` tồn tại trên registry; Docker build local chưa chạy
  vì daemon không khả dụng.
- Python 3.13.14 isolated environment: `pip check` pass, 34/34 test ML pass,
  SciPy `_spropack` import pass và artifact validator pass 41/41 checks.

## Liên kết artifacts

- Cấu hình task và toolchain: `mise.toml`
- Module Go: `go.mod`, `go.sum`
- Cấu hình linter: `.golangci.yml`
- Docker build: `Dockerfile`
- Release preflight: `scripts/ops/release-preflight.sh`, `scripts/ops/release-preflight.ps1`
- Workflow CI: `.github/workflows/ci.yml`

---

## Lịch sử thay đổi (Version History)

| Ngày | Thay đổi | Tác giả |
|---|---|---|
| 2026-08-23 | Loại khóa linter v1 khỏi schema v2, cách ly `tmp/`, xác nhận `config verify`/lint 0 issue và đồng bộ đường dẫn release helper với `scripts/ops/` | Codex (GPT-5.6 Sol) |
| 2026-08-22 | Nâng Go build toolchain lên 1.26.7, pin Python 3.13.14 và khai báo dependency ML còn thiếu; xác nhận Go security scan, Python test và artifact validation | Codex (GPT-5) |
| 2026-08-08 | Sửa checksum bundle lệch CRLF/LF giữa Windows và GitHub Actions Ubuntu; đồng bộ golden revision | Codex (GPT-5) |
| 2026-08-08 | Đồng bộ Go 1.25.12, migrate golangci-lint v2, pin scanner, xử lý finding linter/gosec và cập nhật bằng chứng CI | Codex (GPT-5) |
| 2026-08-06 | Chuẩn hóa độ sâu thư mục gốc trong `scripts/ops/` và bổ sung quy tắc CI vào `AGENTS.md` | Antigravity AI Agent |
| 2026-08-02 | Khởi tạo tài liệu và khắc phục đường dẫn script CI | Antigravity AI Agent |
