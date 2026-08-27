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

- Server chỉ lưu HMAC fingerprint (salt per-process hoặc keyed SQLite) + bucket xác suất + cờ would-promote.
- Calibration/FPR chỉ tính trên event đã nhãn; không suy calibration từ traffic không nhãn.

## Durable label feedback & Error-Path Correlation (Vòng 5)

Feedback hỗ trợ cả in-memory buffer và backend lưu trữ SQLite bền vững. Khi `SAFE_ZONE_URL_ML_FEEDBACK_SECRET` được inject (qua env hoặc `*_FILE` dưới secret root), fingerprint HMAC trở nên ổn định qua các lần restart và nhãn được lưu vào bảng bounded `url_ml_feedback` trong SQLite:

### Cơ chế ghi nhận sự kiện & Error-Path Sentinel:
- **Ghi nhận đồng bộ trước khi trả response:** Với mọi observation được chọn mẫu (`sampled=true`) và có `event_id`, fingerprint của sự kiện được ghi vào store trước khi request analyze hoàn tất.
- **Bảo đảm tương quan trên nhánh lỗi (Error-Path):** Cơ chế này áp dụng cả khi phân loại thành công lẫn khi gặp lỗi:
  - `invalid_url_context` (ví dụ hostname mismatch, scheme không hợp lệ, URL dị dạng);
  - `prediction_error` (lỗi nội bộ của classifier).
- **Probability Sentinel `-1`:** Trên nhánh lỗi, xác suất được ghi nhận bằng giá trị sentinel `-1` (biểu thị không có prediction), hoàn toàn tách biệt khỏi bucket $[0, 0.1)$. Caller có thể gán nhãn ngay sau khi quan sát mà không gặp lỗi `unknown_event` giả mạo.
- **Fail-Open cho phân tích, Fail-Closed cho feedback:** Lỗi phân loại URL classifier luôn fail-open (kết quả phân tích tên miền chính vẫn trả về bình thường). Ngược lại, nếu lưu trữ feedback lỗi (database lỗi hoặc nạp secret thất bại), chỉ riêng route feedback fail-closed (trả về HTTP 503 `persistence_error`); analyze hoàn toàn không bị ảnh hưởng.

### Đặc tả lưu trữ & Vận hành:
- **Dữ liệu lưu trữ:** Chỉ lưu HMAC-SHA256(event_id) cắt 16 byte (hex), key version, bucket xác suất (0–9 hoặc sentinel -1), cờ would-promote, cờ nhãn. Không lưu URL, query, credentials, hay redirect target.
- **Retention & Bound:** TTL mặc định 168 giờ (`SAFE_ZONE_URL_ML_FEEDBACK_RETENTION_HOURS`), trần 65.536 dòng (`SAFE_ZONE_URL_ML_FEEDBACK_MAX_ROWS`); tác vụ dọn dẹp (prune) chạy lúc khởi động và định kỳ mỗi ~10 phút.
- **Dedupe & Anti-replay:** Cùng `event_id` sẽ ghi đè bản ghi cũ; mỗi sự kiện chỉ nhận đúng một nhãn hợp lệ duy nhất (`malicious` hoặc `benign`), nhãn lặp lại trả lỗi `already_labeled`.
- **Key Rotation một bước:** Đổi sang key mới bằng cách đặt `..._KEY_VERSION=2` và secret mới, đồng thời giữ `..._PREVIOUS_SECRET` cùng `..._PREVIOUS_KEY_VERSION=1` trong thời gian chuyển tiếp để các event cũ vẫn correlate được cho tới khi hết TTL.
- **Ý nghĩa mã `unknown_event`:** Mã này hoàn toàn hợp lệ và chỉ xuất hiện khi:
  1. Sự kiện thực sự không tồn tại;
  2. Observation không được chọn mẫu (`sampled=false`) hoặc client không truyền `event_id`;
  3. Sự kiện đã quá hạn TTL (168h);
  4. Secret đã bị xoay ra ngoài rotation window (sau khi gỡ bỏ previous secret).
  *(Lưu ý lịch sử: Bug `unknown_event` trước đây do UI hiển thị nút feedback khi `sampled=false`, kết hợp lỗi thiếu lệnh record trên nhánh classifier error-path. Cả hai lỗi này đã được khắc phục triệt để).*
- **Rate Limit:** Áp dụng rate limit riêng cho `/v1/url-ml/feedback` qua `SAFE_ZONE_RATELIMIT_FEEDBACK_RPM/BURST` (mặc định 30/10); payload giới hạn tối đa 4 KB.

## Promotion gate

URL ML promotion (shadow → cân nhắc enforce) tuân theo Gate B trong
[docs/runbooks/release-gate.md#8-two-independent-release-gates-round-5](release-gate.md#8-two-independent-release-gates-round-5).
Gate này độc lập với Product Release Gate; việc URL ML duy trì `SHADOW_OBSERVER_ONLY` (do thiếu external URL-context evidence) không bao giờ chặn phát hành sản phẩm.
