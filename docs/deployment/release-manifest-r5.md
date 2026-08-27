# Release Manifest — Round 5 (Release Convergence & Shadow Launch Candidate)

> **Canonical Release Status Document**
> Ngày: 2026-08-27 · Branch: `main` · Base commit: `4f1f323`
> Hai release gates độc lập được định nghĩa tại [docs/runbooks/release-gate.md](../runbooks/release-gate.md) (Section 8).

---

## 1. Trạng Thái Phát Hành Canonical (Canonical Release Status)

Hệ thống Safe-Zone áp dụng mô hình hai release gates hoàn toàn độc lập:

```text
Overall Release Status:           RELEASE_CANDIDATE_SHADOW_READY
Gate A (Product Release Gate):    READY_FOR_VPS_VALIDATION (Deployment: PENDING_VPS)
Gate B (URL ML Promotion Gate):   SHADOW_OBSERVER_ONLY (Promotion: PENDING_EXTERNAL_EVIDENCE)
```

- **Sản phẩm sẵn sàng phát hành ở chế độ Shadow hoặc Disabled:** Safe-Zone deterministic/domain engine, threat-feed syncer, DNS DoH/DoT resolver, và bộ tích hợp URL ML shadow đã vượt qua toàn bộ kiểm thử local regression, race tests, failure injection, và local capacity test.
- **Tiến độ triển khai (PENDING_VPS):** Kết quả kiểm thử tải local không thay thế kiểm tra trên VPS. Trước khi đưa vào production release chính thức, cần hoàn tất bài kiểm tra rút gọn trên VPS đích theo [docs/runbooks/vps-load-test.md](../runbooks/vps-load-test.md) để xác nhận CPU/RAM, throughput, latency, TLS, port/firewall, container restart, rollback, tốc độ phình đĩa, và monitoring.
- **URL ML Promotion độc lập (PENDING_EXTERNAL_EVIDENCE):** URL ML chuyên biệt chỉ hoạt động ở chế độ `SHADOW_OBSERVER_ONLY`. Chế độ `enforce` tiếp tục bị khóa cứng ở cả parser cấu hình và runtime. Hiện tại vẫn thiếu lưu lượng URL-context thực tế từ external callers (`ui/sdk/extension`) và operational evidence thật. Synthetic replay hoặc local benchmark không được coi là production evidence. Việc URL ML chưa đủ điều kiện enforce **không bao giờ** làm Product Release Gate thành `NO_GO`.
- **Phân biệt baseline lịch sử:** Mốc representative recall 22/34 là baseline lịch sử riêng của domain-only candidate (v3/v4/v7); không được nhầm lẫn với kết quả của URL-aware V10 specialist (+33 TP / +0 FP).

---

## 2. Release Identity & Artifacts

| Thành phần | Giá trị / Nguồn bằng chứng |
|---|---|
| Source Commit | `4f1f323` (hoặc commit mới nhất trên `main` khi phát hành) |
| Runtime Go Toolchain | Go `1.26.7` (`mise.toml`, `Dockerfile`) · Target language `1.25.0` (`go.mod`) |
| URL ML Bundle | `ml/models/url-v1/` — `url_model.v1.json` (`eea78a5d…`), golden vectors (`0c00aa15…`), checksums tại `SHA256SUMS` |
| Operational Drift Baseline | `ml/models/url-baseline/operational-baseline.json` — SHA-256 `29b8bb723cc6f9e0cac0aac81c264efb4462f7eee358d7e47b70d5129924445f1`<br>*(Lưu ý: Đây là **staging operational baseline** từ 34 mẫu canary staging, KHÔNG phải production baseline)* |
| Domain ML Bundle | Mount `${SAFE_ZONE_ML_BUNDLE_HOST_DIR}`; mặc định production là `disabled` |
| Local Capacity Benchmark | [docs/benchmarks/local-capacity-loadtest-20260827.md](../benchmarks/local-capacity-loadtest-20260827.md) — Verdict: `LOCAL_CAPACITY_PASS_BELOW_200K` |
| VPS Test Runbook | [docs/runbooks/vps-load-test.md](../runbooks/vps-load-test.md) |

---

## 3. Cấu Hình Release Profile Khai Báo

Cấu hình vận hành tiêu chuẩn cho bản Release Candidate:

- **Compose Layering:**
  - Base / Development: `docker-compose.yml` (+ `docker-compose.dev.yml` cho dev loopback UI/API). Telemetry write sampling mặc định **100%**.
  - Production: `docker-compose.yml` + `docker-compose.production.yml`. Public ports `80`, `443`, `853`; internal ports `8080`, `8081` bind `127.0.0.1`. Telemetry write sampling mặc định **5%**.
  - Load-test: `docker-compose.yml` + `docker-compose.loadtest.yml` với project cô lập `safe-zone-loadtest`.
  - Canary: `docker-compose.canary.yml` (chỉ dùng cho bounded shadow testing có seed).
- **URL ML Mode:**
  - `SAFE_ZONE_URL_ML_MODE=shadow` (hoặc `disabled`).
  - `SAFE_ZONE_URL_ML_SHADOW_PERCENT=100` (hoặc 1–99 kèm `SAFE_ZONE_URL_ML_SHADOW_SEED`).
  - `enforce` bị từ chối khởi động ở cả env loader và runtime contract.
- **URL ML Durable Feedback:**
  - Secret inject qua `SAFE_ZONE_URL_ML_FEEDBACK_SECRET` hoặc `SAFE_ZONE_URL_ML_FEEDBACK_SECRET_FILE` (`ops/secrets/url_feedback_hmac`).
  - Key version 1 (`..._KEY_VERSION=1`), TTL mặc định 168 giờ (`..._RETENTION_HOURS=168`), giới hạn 65.536 dòng (`..._MAX_ROWS=65536`).
  - Hỗ trợ xoay key một bước qua `_PREVIOUS_SECRET` và `_PREVIOUS_KEY_VERSION`.
  - Nếu không cấu hình secret: tự động fallback về in-memory ring buffer (ephemeral, không bền vững qua restart).
- **Telemetry Write Sampling Policy:**
  - `SAFE_ZONE_TELEMETRY_WRITE_PERCENT`: Production override mặc định **5%**; có thể hạ xuống **1%** cho các host có lượng truy cập cao kéo dài hoặc disk budget hạn hẹp.
  - Chỉ áp dụng cho telemetry phân tích chi tiết tại `RecordAnalysis`. Audit log, URL feedback durability, overrides, và brand tables là các writer riêng biệt và **không bị sample**.
  - Công thức ước tính kích thước đĩa:
    $$\text{Dung lượng steady-state} \approx W \times 71\text{ bytes} \times \text{RPS} \times 86.400 \times \text{retention\_days}$$
  - Khuyến nghị: Dự toán telemetry trong retention window không nên vượt quá **20–25%** dung lượng đĩa khả dụng dành cho Safe-Zone.

---

## 4. Tóm Tắt Kết Quả Local Capacity Load Test

Kết quả đo lường chính thức từ benchmark canonical ([docs/benchmarks/local-capacity-loadtest-20260827.md](../benchmarks/local-capacity-loadtest-20260827.md)):

- **Verdict:** `LOCAL_CAPACITY_PASS_BELOW_200K`.
- **Workload A (Health ceiling):** Đạt ~24.958 RPS (99.8% achieved, zero error, p99 2.1–10.8 ms) trong môi trường Docker Desktop WSL2 dùng chung (8 vCPU / 7.67 GB RAM).
- **Workload B (Analyze mixed pool):** Đạt ~4.900–4.930 RPS clean trên process mới; bão hòa server-side plateau tại 5–6.1k RPS.
- **Workload C (URL ML shadow A/B):** Phụ trội shadow ở mức 2.500 RPS là +23% CPU; giảm khoảng 9–10% công suất gần ngưỡng saturation; response parity giữa disabled và shadow đạt 100%.
- **Soak release-mode (30 phút, Telemetry 5%):**
  - Cung cấp: 2.200 RPS; Đạt được: 2.190.97 RPS (99.6%).
  - Tổng số request: 3.943.744 completed; Scheduler drops: 240 (0.006% $\approx$ zero-drop).
  - Ứng dụng: **0 error, 0 timeout, 0 connection reset**.
  - Bộ nhớ: Live heap plateau vững chắc ở **~7 MB**; VmRSS dao động 28.5–40.4 MB; goroutines từ 111–132 quay về đúng baseline **15** sau khi cooldown.
  - Không có OOM, không data race, không hỏng dữ liệu.
- **Lưu ý trần công suất:** Mức trần đo được là giới hạn của môi trường shared-VM nội bộ, không phải cam kết trên VPS độc lập. Dự án không đặt mục tiêu hay tuyên bố production 200k RPS dựa trên kết quả test này.

---

## 5. URL Feedback Correlation & Error-Path Contract

Cơ chế tương quan nhãn URL phản hồi đảm bảo:

1. **Caller cung cấp opaque `event_id`:** Client tạo định danh sự kiện; server không lưu raw URL, query parameters hay credentials.
2. **Ghi nhận sự kiện tức thì (kể cả error-path):** Mọi observation được sample và có `event_id` đều được ghi fingerprint HMAC trước khi HTTP analyze response trả về caller.
3. **Xử lý error-path với probability sentinel `-1`:** Khi phân loại gặp lỗi (`invalid_url_context` hoặc `prediction_error`), xác suất được ghi nhận bằng sentinel `-1` (biểu thị không có prediction, tuyệt đối không rơi vào bucket $[0, 0.1)$). Nhờ đó, caller gán nhãn ngay sau khi phân tích thất bại sẽ không gặp lỗi `unknown_event` giả mạo.
4. **Nguyên tắc an toàn:**
   - Phân tích tên miền luôn **fail-open** khi URL classifier lỗi.
   - Lưu trữ feedback lỗi chỉ làm feedback **fail-closed** (HTTP 503 `persistence_error`), hoàn toàn không làm gián đoạn phân tích tên miền chính.
   - `unknown_event` là hợp lệ và chỉ xảy ra khi: sự kiện thực sự không tồn tại, observation không được sample / không có `event_id`, sự kiện đã quá TTL 168 giờ, hoặc secret đã bị xoay ra ngoài rotation window.

---

## 6. Gate Status Chi Tiết

### Gate A — Product Release Gate (Deterministic & Domain Engine)

| # | Tiêu chí | Trạng thái | Ghi chú bằng chứng |
|---|---|---|---|
| A1 | Full test, race test, vet trên release commit | **PASS** | `go test ./...`, race tests, golangci-lint v2 đạt 0 issue |
| A2 | Fail-fast khi thiếu production secrets | **PASS** | `SAFE_ZONE_ENV=production` kiểm tra bắt buộc secret |
| A3 | Loopback-only cho internal ports, Caddy public edge | **PASS** | Kiểm tra cấu hình Compose production |
| A4 | Health/Readiness sau restart | **PASS** | Restart drill đạt downtime 2.2s dưới tải nặng |
| A5 | Image provenance & tag pinning | **PASS** | Preflight helper ghi nhận metadata đầy đủ |
| A6 | Load test trên VPS đích | **PENDING_VPS** | Local capacity test đã PASS (`LOCAL_CAPACITY_PASS_BELOW_200K`); cần chạy bài rút gọn trên VPS đích theo runbook |
| A7 | Rollback & dependency fault drills | **PASS** | Redis pause/unpause drill và URL rollback 5/5 đạt PASS |
| A8 | JSON metrics & alerts tối thiểu | **PASS** | Endpoint `/metrics` tích hợp khối `runtime` memory và alert rules |
| A9 | Runbooks cài đặt, nâng cấp, rollback, privacy | **PASS** | Toàn bộ runbooks đã được đồng bộ hóa |
| A10 | UI/API compatibility & degraded mode | **PASS** | Browser E2E Playwright 4/4 PASS; degraded UI hoạt động |
| A11 | Safe URL ML profile | **PASS** | Shadow-only, enforce rejected, fail-open độc lập |

### Gate B — URL ML Promotion Gate (Chuyên gia URL ML)

Trạng thái: **SHADOW_OBSERVER_ONLY** (Blocker: `PENDING_EXTERNAL_EVIDENCE`).
- Parity, privacy, failure injection, rollback drills đã hoàn thành.
- Thiếu lưu lượng URL-context thực tế từ external clients ($\ge 1.000$ evaluated events hoặc một representative window có xác nhận).
- Chưa có operational baseline đóng băng từ traffic production ngoài đời thật.

---

## 7. Hướng Dẫn Vận Hành & Rollback

### Khởi động Production Stack chuẩn:
```sh
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d --build
```

### Rollback khẩn cấp URL ML (chỉ tác động `core-api`, DNS không bị ảnh hưởng):
```sh
# 1. Tắt URL ML
SAFE_ZONE_URL_ML_MODE=disabled SAFE_ZONE_URL_ML_REQUIRED=false \
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d --force-recreate core-api

# 2. Xác minh trạng thái rollback
python ml/src/check_v10_url_rollback.py --base-url http://127.0.0.1:8080

# 3. Khôi phục shadow mode có kiểm soát (kèm seed):
docker compose -f docker-compose.yml -f docker-compose.production.yml -f docker-compose.canary.yml up -d --force-recreate core-api
```
