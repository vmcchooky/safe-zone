# Alert rules runbook

Safe Zone keeps `/metrics` as JSON for the single-VPS MVP. The baseline alert rules live in `ops/alerts/safe-zone-alert-rules.yaml`.

> Subsystem detail (redis, `feed_sync`, `ml`, analysis config) lives behind
> authenticated `GET /v1/status`, not on `/metrics` (request counters only).
> Every `curl` below targeting `core-api` — `/v1/status` **and `/metrics`** —
> needs admin auth, e.g. `-H "Authorization: Bearer $SAFE_ZONE_ADMIN_API_KEY"`.
> The YAML rule file already uses these exact sources and field paths.
>
> `/metrics` became authenticated on 2026-09-29. It previously exposed the
> per-endpoint request summary to anonymous callers, which let anyone
> fingerprint the API surface and read 401/403/429 rates as a brute-force
> progress signal. A stale unauthenticated scrape now returns 401 and every
> `core_api_*` rule fires as "down". `dns-resolver` (`:8081`) is unaffected.

## Covered alerts

- core-api down
- dns-resolver down
- Redis unavailable
- unsafe Redis eviction policy and sustained Redis memory pressure
- threat-feed stale
- threat-feed missing after a recorded successful sync
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
AUTH_HEADER="Authorization: Bearer $SAFE_ZONE_ADMIN_API_KEY"
curl -fsS -H "$AUTH_HEADER" http://127.0.0.1:8080/v1/status
curl -fsS -H "$AUTH_HEADER" http://127.0.0.1:8080/metrics
curl -fsS http://127.0.0.1:8081/
curl -fsS http://127.0.0.1:8081/metrics
```

Locally, `core-api` generates a temporary key on first start and writes it to
`tmp/local_admin_secrets.txt`; `export SAFE_ZONE_ADMIN_API_KEY=$(grep
'^SAFE_ZONE_ADMIN_API_KEY=' tmp/local_admin_secrets.txt | cut -d= -f2)` reuses
it across restarts. In production set `SAFE_ZONE_ADMIN_API_KEY` (or
`..._FILE`) explicitly — an empty key is rejected and no bearer can match.

## Grafana

`ops/grafana/safe-zone-dashboard.json` reads the same endpoints. Add
`Authorization: Bearer <key>` to the Infinity datasource ("Additional
headers"); without it the `core-api` panels render 401.

## Adblock source cache is invalidated once on upgrade (2026-09-29)

`adblockSourceCachePath` keys the per-source download cache by the canonical
source URL (scheme and host lowercased) instead of the raw string, so one source
has one identity across the policy fingerprint, the policy lookup, the cache
path and the rule provenance digest. Cache files written by an earlier build are
keyed by the raw string and no longer match.

Expect one full re-download of every configured adblock source on the first
start after upgrading, and a correspondingly longer first sync tick. The cost is
one-off; steady state is unchanged. If the operator's `SAFE_ZONE_ADBLOCK_SOURCES`
spells a source differently from what an older build stored, that is the trigger.

Separately, a per-source policy document is canonicalized when it is read, so a
stored document whose keys are not already canonical produces a different
`adblock.source_policies_fingerprint` than before the upgrade. That fires one
extra rule rebuild, then settles. The two digests across nodes still have to
match — that is what the fingerprint is for.

## Runtime Memory & Observability Metrics

Heap/goroutine internals are intentionally NOT on `/metrics`
(stop-the-world cost + info minimization). For soak/load diagnosis use
`docker stats` (container RSS) plus the authenticated status surface:

```sh
curl -fsS -H "$AUTH_HEADER" http://127.0.0.1:8080/v1/status \
  | jq '{redis: .redis, feed_sync: {status: .feed_sync.status, active_entries: .feed_sync.active_entries}, ml: .ml}'
```

### Phân biệt Container RSS và Go Live Heap:
- **Container RSS (`docker stats`):** Thường dao động 28–40 MB cho core-api.
  Sự gia tăng của RSS trong container SQLite chủ yếu do Linux kernel page
  cache (bộ đệm file database/WAL trên cgroup `file` thay vì `anon`).
- **Quy tắc chẩn đoán:** RSS tăng trong khi verdict/latency/5xx-rate giữ
  baseline và không có OOM **hoàn toàn KHÔNG phải là memory leak**. Đối
  chiếu bằng pprof nội bộ khi cần số heap chính xác (không expose public).

### URL ML Shadow & Feedback Persistence Metrics:
`GET /v1/status` cung cấp aggregate metrics bảo đảm an toàn quyền riêng tư
(tuyệt đối không chứa raw URL, query parameters hay credentials):

```sh
curl -fsS -H "$AUTH_HEADER" http://127.0.0.1:8080/v1/status \
  | jq '.ml.url | {state, prediction_attempts, error_histogram, latency_p95_us, sampling, drift, feedback}'
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
curl -fsS -H "$AUTH_HEADER" http://127.0.0.1:8080/v1/status | jq '.redis'
```

The shared Redis is safe for the non-expiring threat-feed key when
`eviction_policy_safe` is `true`. The production baseline uses `volatile-lru`;
`allkeys-*` is a critical configuration error because it can evict the entire
feed key under memory pressure.

Threat-feed freshness:

```sh
curl -fsS -H "$AUTH_HEADER" http://127.0.0.1:8080/v1/status | jq '.feed_sync'
```

After at least one successful sync, `active_entries` must stay above zero. A
`status` of `missing` indicates lost or fully expired feed coverage and pages
the operator independently of ordinary freshness warnings.

Upstream DoH failure count:

```sh
curl -fsS http://127.0.0.1:8081/metrics | jq '.upstream_doh.failures_total'
```

Runtime memory status (request counters; heap internals are not public —
see the section above):

```sh
curl -fsS -H "$AUTH_HEADER" http://127.0.0.1:8080/metrics | jq '.metrics.request_summary'
```

## Log retention

Docker JSON logs are capped through Compose with:

- `SAFE_ZONE_DOCKER_LOG_MAX_SIZE`
- `SAFE_ZONE_DOCKER_LOG_MAX_FILE`

The defaults in `.env.example` keep five files of ten megabytes per container.
