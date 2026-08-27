# Alert rules runbook

Safe Zone keeps `/metrics` as JSON for the single-VPS MVP. The baseline alert rules live in `ops/alerts/safe-zone-alert-rules.yaml`.

## Covered alerts

- core-api down
- dns-resolver down
- Redis unavailable
- threat-feed stale
- parser drift
- high HTTP 5xx rate
- upstream DoH failure
- high DoH latency
- URL ML shadow degraded state
- URL ML prediction/input errors and high inference latency
- URL ML distribution drift after an operational baseline exists
- URL ML context coverage drop (Vòng 4: gates canary conclusions)
- URL ML operational baseline unavailable (fail-open, drift non-operational)

## Data sources

```sh
curl -fsS http://127.0.0.1:8080/
curl -fsS http://127.0.0.1:8080/metrics
curl -fsS http://127.0.0.1:8081/
curl -fsS http://127.0.0.1:8081/metrics
```

## Runtime Memory & Observability Metrics

Endpoint `GET /metrics` trên `core-api` cung cấp trực tiếp các thông số runtime cơ bản (qua `runtime.ReadMemStats` với chu kỳ thăm dò khuyến nghị ~1 Hz) để phục vụ giám sát tải và soak test mà không bắt buộc phải kích hoạt profiler:

```json
{
  "runtime": {
    "goroutines": 15,
    "heap_alloc_mb": 6.39,
    "sys_mb": 25.12,
    "num_gc": 42
  }
}
```

### Phân biệt Container RSS và Go Live Heap:
- **Go Live Heap (`heap_alloc_mb`):** Đo lường lượng bộ nhớ thực tế đang được các đối tượng Go đang hoạt động sử dụng. Trong soak test tải cao, heap live-set đạt bình nguyên (plateau) tại **~7 MB**.
- **Container RSS (`docker stats`):** Thường dao động 28–40 MB. Sự gia tăng của RSS trong container SQLite chủ yếu do Linux kernel page cache (bộ đệm file database/WAL trên cgroup `file` thay vì `anon`).
- **Quy tắc chẩn đoán:** Việc Container RSS tăng nhưng `heap_alloc_mb` và `goroutines` đạt trạng thái bình nguyên (hoặc quay về baseline 15 sau khi hết tải) **hoàn toàn KHÔNG phải là memory leak**.

### URL ML Shadow & Feedback Persistence Metrics:
`GET /metrics` cung cấp aggregate metrics bảo đảm an toàn quyền riêng tư (tuyệt đối không chứa raw URL, query parameters hay credentials):

```sh
curl -fsS http://127.0.0.1:8080/metrics | jq '.ml.url | {state, prediction_attempts, error_histogram, latency_p95_us, sampling, drift, feedback}'
```

- **Health checks:**
  - `state == "ready"`, `prediction_error == 0`, `latency_p95_us < 2000`.
  - `drift.state`: Ở môi trường staging/dev chưa có external baseline, `proxy_shift` là cảnh báo chẩn đoán tham chiếu. Chỉ kích hoạt cảnh báo chặn khi `operational_reference == true`.
- **Feedback persistence status:**
  - `persistence`: Báo `"sqlite"` (bền vững) hoặc `"memory"` (buffer tạm).
  - `degraded`: Báo `true` nếu xảy ra lỗi ghi/đọc nhãn vào SQLite.
  - `persistence_errors`: Đếm số lần lỗi persistence (fail-closed riêng cho feedback, không ảnh hưởng analyze).

### Lưu ý về Telemetry Sampling trong Giám sát:
- Khi `SAFE_ZONE_TELEMETRY_WRITE_PERCENT` được cấu hình $< 100\%$ (mặc định production là **5%**), các query đếm số bản ghi trong bảng `telemetry` SQLite chỉ phản ánh số mẫu được ghi.
- **Quy tắc vận hành:** Tuyệt đối không trình bày sampled count như tổng lượng request thực tế trên dashboard hoặc alert rules. Cần nhân ngược với tỉ lệ lấy mẫu ($1 / \text{write\_fraction}$) hoặc sử dụng bộ đếm request in-memory (`metrics.summary`) để tính tổng số request thực tế.

## Quick checks

When following logs during an incident, group HTTP traffic with `request_id` and scheduled/background work with `run_id`.

Redis health:

```sh
curl -fsS http://127.0.0.1:8080/ | jq '.redis'
```

Threat-feed freshness:

```sh
curl -fsS http://127.0.0.1:8080/ | jq '.feed_sync'
```

Upstream DoH failure count:

```sh
curl -fsS http://127.0.0.1:8081/metrics | jq '.upstream_doh.failures_total'
```

Runtime memory status:

```sh
curl -fsS http://127.0.0.1:8080/metrics | jq '.runtime'
```

## Log retention

Docker JSON logs are capped through Compose with:

- `SAFE_ZONE_DOCKER_LOG_MAX_SIZE`
- `SAFE_ZONE_DOCKER_LOG_MAX_FILE`

The defaults in `.env.example` keep five files of ten megabytes per container.
