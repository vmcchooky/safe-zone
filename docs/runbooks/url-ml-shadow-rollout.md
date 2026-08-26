# URL ML shadow rollout

This runbook operates the caller-supplied URL specialist without changing any user verdict. The URL route is available only in `core-api`; DNS and GET analysis remain domain-only.

## Start a full shadow window

Set the following values and restart only `core-api`:

```env
SAFE_ZONE_URL_ML_MODE=shadow
SAFE_ZONE_URL_ML_BUNDLE_DIR=/app/models/safe-zone/url-v1
SAFE_ZONE_URL_ML_REQUIRED=true
SAFE_ZONE_URL_ML_SHADOW_PERCENT=100
SAFE_ZONE_URL_ML_SHADOW_SEED=
```

For a stable partial cohort, set `SAFE_ZONE_URL_ML_SHADOW_PERCENT` to `1`–`99` and provide a non-empty `SAFE_ZONE_URL_ML_SHADOW_SEED`. The selector hashes the normalized domain; the same domain stays in the same cohort across restarts.

## Verify readiness

```sh
curl -fsS http://127.0.0.1:8080/v1/status | jq '.ml.url'
```

Required state:

- `mode=shadow`, `enabled=true`, `state=ready`;
- expected `model_version`, `revision` and `policy_revision`;
- `sampling.percent` matches the approved traffic scope;
- `prediction_error=0` and latency p95 remains below `2.000 µs`.

The runtime exports only aggregate counters. Do not add raw URL, path, query values or redirect targets to logs, telemetry, reports or support tickets.

## Replay labelled staging evidence

With a shadow core API listening locally:

```sh
python ml/src/replay_v10_url_shadow.py --base-url http://127.0.0.1:8080 --workers 12
```

The tool sends the frozen final cohort through GET and POST, checks response parity, privacy, invalid-context fail-open behavior, latency and labelled calibration. Its report contains aggregates only at `ml/experiments/v10-url-shadow-staging.json`.

## Hold or advance

Advance toward canary only when all conditions remain true for the approved observation window:

- no valid prediction errors and no response parity mismatch;
- no raw-context leak;
- URL inference p95 below `2.000 µs`;
- invalid-context rate below `5%` after at least `100` attempts;
- labelled/reviewed benign incremental promotions equal `0`;
- rollback drill passes.

`drift.state=proxy_shift` is non-blocking while `operational_reference=false`. It compares live traffic with a balanced development proxy and therefore also reacts to prevalence changes. Freeze a representative live baseline before treating PSI as an operational gate.

## Roll back

Set:

```env
SAFE_ZONE_URL_ML_MODE=disabled
SAFE_ZONE_URL_ML_REQUIRED=false
```

Restart only `core-api`, then run:

```sh
python ml/src/check_v10_url_rollback.py --base-url http://127.0.0.1:8080
```

The check requires `mode=disabled`, classifier disabled, URL not evaluated, domain response parity and zero raw-context leakage. No DNS restart is required because DNS never loads the URL bundle.

## Canary scope stepping (Vòng 4)

Scope thay đổi luôn qua tool để có audit trail và policy revision mới:

```sh
python ml/src/canary_scope.py --percent 1 --seed url-canary-v4-r4-20260826 --reason initial
python ml/src/canary_scope.py --percent 5 --reason gates_green
python ml/src/canary_scope.py --rollback            # về percent trước đó
```

Mỗi bước ghi `from/to percent`, selector revision và policy revision vào
`ml/experiments/v10-url-canary-scope-changes.json`. Giữ nguyên seed giữa các
bước để cohort ổn định theo normalized domain. Không đổi scope trực tiếp
trong `.env` mà không đi qua tool (hoặc tự append entry tương đương).

## Operational drift baseline

Baseline operational thật được đóng băng từ telemetry canary live:

```sh
python ml/src/freeze_url_canary_baseline.py \
  --traffic-scope "<mô tả trung thực về traffic scope>" \
  --window-seconds 60 --min-samples 25
```

File ghi tại `ml/models/url-baseline/operational-baseline.json` (mount ro
vào core-api) và bản evidence tại `ml/experiments/`. Set env:

```env
SAFE_ZONE_URL_ML_BASELINE_PATH=/app/models/safe-zone/url-baseline/operational-baseline.json
```

Sau khi restart `core-api`, kiểm tra `/v1/status → ml.url`:

- `operational_baseline.loaded=true`, `sha256` khớp artifact;
- `drift.operational_reference=true`,
  `reference_kind=frozen_operational_shadow_traffic`.

Lỗi load (missing/corrupt/model mismatch) đều fail-open: classifier vẫn
ready, chỉ drift monitoring quay về reference phi-operational.

## Evidence window (snapshot-delta)

```sh
python ml/src/canary_snapshot_delta.py --window-seconds 45 \
  --workers 12 --concurrency 8 [--drive-count N] \
  --traffic-kind external|synthetic \
  --output ml/experiments/<ten-window>.json
```

Mọi số liệu là delta giữa hai snapshot `/v1/status`; report chỉ chứa
aggregate, kèm `workers`, duration và rate exact + round-half-up 4dp.

## Privacy-safe label feedback

Caller gửi label mà server không cần giữ raw URL:

```sh
curl -fsS -X POST http://127.0.0.1:8080/v1/url-ml/feedback \
  -H 'Content-Type: application/json' \
  -d '{"event_id":"<opaque-id-tu-client>","label":"benign"}'
```

Server chỉ lưu HMAC fingerprint (salt per-process) + bucket xác suất + cờ
would-promote. Calibration/FPR chỉ tính trên event đã nhãn; không suy
calibration từ traffic không nhãn.


## Durable label feedback (Vòng 5)

Feedback không còn chỉ-in-memory. Khi `SAFE_ZONE_URL_ML_FEEDBACK_SECRET` được
inject (env hoặc `*_FILE` dưới secret root), fingerprint HMAC trở nên ổn định
giữa các restart và nhãn được lưu vào bảng bounded `url_ml_feedback` trong
SQLite sẵn có:

- Chỉ lưu: HMAC-SHA256(event_id) cắt 16 byte (hex), key version, bucket xác
  suất (0–9), cờ would-promote, cờ nhãn. Không URL, query, hostname hay dữ
  liệu khôi phục được URL.
- TTL mặc định 168 giờ (`..._RETENTION_HOURS`), trần 65.536 dòng
  (`..._MAX_ROWS`); prune chạy lúc khởi động và mỗi ~10 phút.
- Dedupe: cùng event_id ghi đè bản ghi cũ (không nhân đôi). Anti-replay:
  một event chỉ nhận đúng một nhãn; nhãn lại trả `already_labeled`.
- Xoay key có version: đặt `..._KEY_VERSION=2` + secret mới; giữ
  `..._PREVIOUS_SECRET` + `..._PREVIOUS_KEY_VERSION=1` trong thời gian chuyển
  tiếp để event cũ vẫn correlate được, rồi tháo biến khi hết TTL.
- Fail closed cho riêng feedback: thiếu store/secret lỗi runtime → nhãn bị
  từ chối HTTP 503 (`reason=persistence_error`) và status báo
  `degraded=true,persistence_errors>0`; analyze không bao giờ đi qua đường
  này. Không có secret → buffer in-memory cũ (ephemeral, ghi rõ trong
  `persistence:"memory"`).
- Rate limit riêng `/v1/url-ml/feedback` qua
  `SAFE_ZONE_RATELIMIT_FEEDBACK_RPM/BURST`; payload giới hạn 4 KB.

Kiểm chứng: restart test, rotation test, privacy scan (DB file không chứa
marker) nằm trong `internal/risk/url_feedback_durable_test.go`.

## Promotion gate

URL ML promotion (shadow → cân nhắc enforce) tuân theo Gate B trong
`docs/runbooks/release-gate.md#8-two-independent-release-gates-round-5`.
Gate này độc lập với Product Release Gate; chưa đạt Gate B không chặn phát
hành sản phẩm.
