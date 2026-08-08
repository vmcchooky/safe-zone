# Ổn định Task Graph và Toolchain của CI (`mise.toml`)

> **Tài liệu Living Document** — Cập nhật đồng bộ mỗi khi CI, toolchain hoặc release preflight thay đổi.
> Tuân thủ quy tắc tại `.agents/AGENTS.md` Section 5.

## Tóm tắt (Abstract)

Safe-Zone từng có lỗi CI tại `golangci-lint`: module khai báo Go 1.25.0 nhưng `mise` và Docker vẫn dùng Go 1.24, trong khi linter được build bằng Go 1.24 không thể phân tích target Go 1.25. Sau đó CI còn phát hiện checksum model khác nhau giữa Windows CRLF và Ubuntu LF. Bản vá đồng bộ runtime về Go 1.25.12, nâng cấu hình linter sang schema v2, pin các scanner bảo mật và canonicalize line ending trước khi hash bundle. Audit toàn bộ task graph cũng phát hiện và xử lý các finding mã nguồn của `errcheck`, `staticcheck` và `gosec`, đồng thời cập nhật release preflight để không còn phụ thuộc vào `@latest`.

## Mục tiêu (Objectives)

- Khôi phục `mise run ci` với toolchain có thể tái lập.
- Giữ `go.mod`, `mise.toml`, Docker build và release preflight trên cùng nhánh tương thích Go.
- Bảo toàn hành vi model/feature contract; các thay đổi mã nguồn chỉ xử lý lỗi kiểm tra tài nguyên, invariant biên và đóng tài nguyên.
- Đảm bảo checksum model bundle cho kết quả giống nhau trên checkout Windows CRLF và Linux LF.
- Đảm bảo UI bundle, Go test/build/vet, linter, security scan và E2E có bằng chứng kiểm thử rõ ràng.

## Phương pháp và lý do (Methodology & Rationale)

| Quyết định | Phương pháp chọn | Phương án thay thế | Lý do |
|---|---|---|---|
| Đồng bộ Go | Pin `go = "1.25.12"` trong `mise.toml` và `golang:1.25.12-alpine` trong Docker; giữ `go 1.25.0` là language target trong `go.mod` | Hạ module về Go 1.24 | Hạ target sẽ xung đột với module/dependency hiện tại và không đáp ứng yêu cầu Go tối thiểu của `gosec` đang dùng. |
| Nâng linter | Pin `golangci-lint = "2.12.2"`, thêm `version: "2"`, migrate `default: none`, gộp `gosimple` vào `staticcheck` | Giữ `golangci-lint` v1.64.5 hoặc tắt linter | Binary v1 hiện tại được build bằng Go 1.24 nên không đọc được target Go 1.25; tắt linter làm giảm coverage chất lượng mã. |
| Pin security scanner | Dùng `gosec@v2.28.0` và `govulncheck@v1.4.0` trong `mise` và cả hai script release preflight | Tiếp tục dùng `@latest` | Phiên bản trôi nổi có thể tự yêu cầu toolchain mới hoặc thay đổi kết quả CI giữa hai lần chạy. |
| Xử lý security finding | Giữ invariant bundle file name cố định, ghi rõ suppression cục bộ có lý do, và thêm guard chỉ số TF-IDF | Tắt rule G304/G602 toàn cục | Giới hạn phạm vi suppression và giữ các rule khác hoạt động đầy đủ. |
| Canonicalize bundle checksum | Chuẩn hóa `CRLF` thành `LF` trước SHA-256 và lưu hash canonical trong `ml/models/v1/SHA256SUMS` | Lưu hash theo line ending của từng máy | Hash theo môi trường làm CI Linux từ chối bundle hợp lệ đã pass trên Windows. Canonical text hashing giữ integrity invariant mà không đổi nội dung model. |

## Chi tiết triển khai (Implementation Details)

- **Mô hình AI Agent:** Codex (GPT-5).
- **Chiến lược:** Audit tĩnh toàn bộ workflow, task, script và version pin; chạy từng task độc lập; sửa theo output thực tế; chạy lại bằng Go 1.25.12.
- **Subagents/voting:** Không sử dụng subagent hoặc voting; kết luận dựa trên output CI và các lệnh kiểm tra tái hiện được.
- `.golangci.yml` được migrate sang schema v2 và giữ tập linter có chủ đích: `errcheck`, `govet`, `ineffassign`, `staticcheck`, `unused`.
- Các lỗi `errcheck` được sửa bằng cách xử lý tường minh kết quả `Close`; các lỗi `staticcheck` được sửa bằng tagged switch, selector được promote và `fmt.Fprintf`.
- `golang.org/x/text` được nâng lên `v0.39.0` cùng các module liên quan do `govulncheck` xác định bản `v0.38.0` có lỗi.
- `internal/analysis/ml_classifier.go` canonicalize `CRLF` → `LF` khi hash model/manifest/calibration/policy; `ml/tests/model_bundle_test.go` dùng cùng quy tắc để golden revision không phụ thuộc OS.
- `ml/models/v1/SHA256SUMS` và golden `bundle_revision` được cập nhật theo canonical hashes; model bytes, feature values và inference logic không thay đổi.
- Release preflight PowerShell và shell dùng cùng phiên bản scanner với task CI.

## Số liệu và kết quả (Metrics & Results)

- `golangci-lint v2.12.2 run`: **0 issues**.
- `gosec v2.28.0` trên Go 1.25.12: **0 issues**.
- `govulncheck v1.4.0` trên Go 1.25.12: **0 vulnerabilities có đường gọi**.
- UI typecheck/build: pass; Playwright E2E: **4/4 pass**.
- Go test, build và vet: pass khi chạy tuần tự.
- Bundle parity tests: pass trên Windows checkout; canonical hash `4ced615d...`, revision `4632f9ea...`.
- Docker build chưa chạy được trong môi trường local do Docker không khả dụng; tag `golang:1.25.12-alpine` đã được kiểm tra tồn tại, còn job `docker-build` vẫn được thực thi trong GitHub Actions sau `quality`.

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
| 2026-08-08 | Sửa checksum bundle lệch CRLF/LF giữa Windows và GitHub Actions Ubuntu; đồng bộ golden revision | Codex (GPT-5) |
| 2026-08-08 | Đồng bộ Go 1.25.12, migrate golangci-lint v2, pin scanner, xử lý finding linter/gosec và cập nhật bằng chứng CI | Codex (GPT-5) |
| 2026-08-06 | Chuẩn hóa độ sâu thư mục gốc trong `scripts/ops/` và bổ sung quy tắc CI vào `AGENTS.md` | Antigravity AI Agent |
| 2026-08-02 | Khởi tạo tài liệu và khắc phục đường dẫn script CI | Antigravity AI Agent |
