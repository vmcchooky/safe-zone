# Cô lập URL-ML theo service role

> **Tài liệu Living Document** — Cập nhật đồng bộ mỗi khi có thay đổi.
> Tuân thủ quy tắc tại `.agents/AGENTS.md` Section 5.

## Tóm tắt (Abstract)

URL-ML chỉ nhận URL context từ `core-api`, nhưng constructor dùng chung trước đây vẫn đọc và khởi tạo URL model trong `dns-resolver`. Khi production đặt `SAFE_ZONE_URL_ML_MODE=shadow` và `SAFE_ZONE_URL_ML_REQUIRED=true` qua `.env`, `env_file` chuyển hai biến này sang cả hai container. Resolver không mount `/app/models/safe-zone/url-v1`, do đó startup panic vì thiếu `url_model.v1.json` và DoH/DoT gián đoạn cho tới khi rollback. Bản vá đặt URL-ML về disabled theo service role trong code và thêm override tương ứng ở Compose. Unit test tái tạo đúng trường hợp URL model bị yêu cầu nhưng không tồn tại trên resolver. URL-ML shadow vẫn hoạt động ở `core-api`; domain-only DNS path không tải model, không ghi URL feedback và không phát sinh URL inference.

## Cô lập URL-ML khỏi DNS resolver

### Mục tiêu (Objectives)

- Cho phép bật URL-ML shadow ở `core-api` mà không ảnh hưởng startup của `dns-resolver`.
- Duy trì nguyên tắc URL-ML chỉ xử lý caller-supplied URL context, không chạy trên DNS traffic.
- Bảo vệ cả deployment Compose và caller không dùng Compose.
- Tạo regression test với URL bundle bắt buộc nhưng thiếu trên resolver.

### Phương pháp & Lý do (Methodology & Rationale)

| Quyết định | Phương pháp chọn | Các phương pháp thay thế | Lý do |
|---|---|---|---|
| Runtime isolation | `NewServiceFromEnvForRoleE` bỏ qua toàn bộ URL-ML config khi role là `dns-resolver` | Mount URL model vào resolver; dùng `.env` riêng; chỉ sửa Compose | Role gate bảo vệ mọi kiểu triển khai và tránh tải model không phục vụ DNS path. |
| Compose defense | Resolver ghi đè `SAFE_ZONE_URL_ML_MODE=disabled` và `SAFE_ZONE_URL_ML_REQUIRED=false` | Dựa hoàn toàn vào code | Override làm contract vận hành hiển thị rõ trong rendered Compose và bảo vệ image cũ khi rollout cấu hình. |
| Failure policy | URL bundle required tiếp tục fail startup ở `core-api` | Luôn fail-open | `required=true` vẫn phát hiện artifact thiếu tại đúng service cần model, thay vì vô hiệu hóa kiểm tra cấu hình. |
| Kiểm thử | Khởi tạo service với role resolver và đường dẫn bundle không tồn tại | Chỉ kiểm tra YAML | Test trực tiếp constructor đã gây panic trong production và xác nhận status URL-ML là disabled. |

### Cách thức Thực hiện (Implementation Details)

`internal/risk/env.go` khởi tạo URL-ML ở trạng thái disabled, sau đó chỉ gọi loader model, sampling, feedback và baseline khi `nodeRole` khác `dns-resolver`. `docker-compose.yml` đồng thời đặt hai biến URL-ML của resolver về giá trị disabled, ghi đè biến kế thừa từ `env_file`.

`internal/risk/env_mode_test.go` tạo SQLite tạm, cấu hình URL-ML shadow bắt buộc với một đường dẫn bundle không tồn tại, rồi khởi tạo role `dns-resolver`. Test yêu cầu constructor không trả lỗi và status phải có `mode=disabled`, `enabled=false`, `state=disabled`.

Codex dựa trên GPT-5 thực hiện truy nguyên log startup, so sánh mounts giữa hai container, sửa runtime và Compose, sau đó chạy test package. Không sử dụng subagent; số lượng subagent là 0 và không dùng voting. Người vận hành cho phép bật các tính năng cuối trên production; cơ chế health check và backup `.env` giữ vai trò kiểm soát human-in-the-loop cho rollback.

### Số liệu (Metrics & Results)

| Chỉ số | Trước bản vá | Sau bản vá cục bộ |
|---|---:|---:|
| Resolver restart trong lần thử đầu | 9 | Không áp dụng |
| Resolver restart trong lần thử URL-only | 6 | Không áp dụng |
| URL model mount ở resolver | 0 file | Không cần mount |
| Regression test role isolation | 0 | 1 pass |
| Package test | Không áp dụng | 3/3 package pass |
| Compose render validation | Không áp dụng | 1/1 pass |

Lệnh tái kiểm chứng:

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml config --quiet
go test ./internal/analysis ./internal/risk ./internal/dns/resolver -count=1
```

### Liên kết Artifacts

- `internal/risk/env.go`
- `internal/risk/env_mode_test.go`
- `docker-compose.yml`
- `internal/risk/url_ml.go`
- `cmd/core-api/main.go`
- `cmd/dns-resolver/main.go`

---

## Lịch sử Thay đổi (Version History)

| Ngày | Thay đổi | Tác giả |
|---|---|---|
| 2026-09-06 | Ghi nhận incident, role gate, Compose defense và regression test | Codex (GPT-5), human-in-the-loop |
