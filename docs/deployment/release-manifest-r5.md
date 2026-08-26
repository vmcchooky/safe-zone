# Release Manifest — Round 5 (Release Convergence & Shadow Launch Candidate)

Ngày: 2026-08-26 · Branch: `codex/url-aware-signal-round` · Base commit: `c7f4a03` + Round 5 commits

Manifest này mô tả release candidate Safe-Zone với URL ML ở chế độ **observer
shadow**. Hai gate độc lập được chốt tại `docs/runbooks/release-gate.md`
(Section 8); kết luận từng gate ghi ở cuối file.

## 1. Release identity

| Thành phần | Giá trị |
|---|---|
| Source commit | Vòng 5 head trên `codex/url-aware-signal-round` (xem `git rev-parse HEAD` khi phát hành) |
| Image `core-api` (staging build) | `safe-zone-phase5-staging-core-api@sha256:22499d41487ba93081e5af053173df17f9eb36f85dfd8c47994eb68c8b9d12ca` |
| URL ML bundle | `ml/models/url-v1/` — `url_model.v1.json` = `eea78a5d…`, golden vectors = `0c00aa15…`, checksums trong `SHA256SUMS` |
| Operational drift baseline | `ml/models/url-baseline/operational-baseline.json` — SHA-256 `29b8bb723cc6f9e0cac0aac81c264efb4462f7eee358d7e47b70d5129924445f1`, **staging operational baseline** (synthetic-driven canary traffic, 34 mẫu tham chiếu) — KHÔNG phải production baseline |
| Domain ML bundle | mount `${SAFE_ZONE_ML_BUNDLE_HOST_DIR}` theo profile; mặc định Deterministic dùng `disabled` |

## 2. Release profile khai báo

Profile phát hành an toàn cho bản RC này:

- `SAFE_ZONE_ML_MODE=shadow` (domain v3) và `SAFE_ZONE_URL_ML_MODE=shadow`
  trên staging scope có seed; **production mặc định `disabled/disabled`**
  (compose defaults không đổi).
- URL ML `enforce`: bị từ chối ở env loader lẫn runtime contract.
- Feedback durable: secret inject qua `SAFE_ZONE_URL_ML_FEEDBACK_SECRET_FILE`
  (`ops/secrets/url_feedback_hmac`, ngoài git), key version 1, TTL 168h,
  cap 65.536 dòng.

## 3. Gate status tại thời điểm manifest

### Gate A — Product Release (rút gọn)

| Criterion | Trạng thái |
|---|---|
| A1 full test/vet/race | PASS (Round 5 regression, xem evidence) |
| A2 production secrets fail-fast | PASS (đã có từ trước, kiểm tra lại bằng unit test) |
| A3 edge loopback-only + Caddy-only | PASS (script sẵn, cần chạy lại trên VPS thật `[!]`) |
| A4 health/readiness sau restart | PASS — drill restart nhiều lần trong Vòng 5 |
| A5 image/provenance pinning | PASS (preflight tooling có sẵn) |
| A6 load test target VPS | `[!]` chưa chạy trên VPS class thật (blocker vận hành môi trường, không phải code) |
| A7 rollback/backup/dependency drills | PASS — rollback URL ML 5/5, Redis-fail-open thiết kế sẵn |
| A8 telemetry/alerts tối thiểu | PASS (JSON metrics + alert rules hiện có) |
| A9 docs cài/nâng cấp/rollback/privacy | PASS (runbooks index cập nhật Vòng 5) |
| A10 UI/API compat + degraded UX | PASS — browser e2e login→analyze→feedback qua UI thật |
| A11 safe URL ML profile | PASS — shadow-only, fail-open, disable chỉ cần restart core-api |

### Gate B — URL ML Promotion

`SHADOW_OBSERVER_ONLY`. Blocker duy nhất còn lại là **external URL-context
volume** (B6): các cửa sổ Vòng 5 đều synthetic-driven và gate tool chủ động
từ chối nâng scope khi thiếu volume/rate-inconclusive. Không có calibration/
FPR nào được tuyên bố từ traffic không nhãn.

## 4. Rollback instructions

Toàn bộ chỉ tác động `core-api`; DNS không bao giờ tải URL bundle:

```sh
# 1) Tắt URL ML (và domain ML nếu cần) — recreate core-api
SAFE_ZONE_URL_ML_MODE=disabled SAFE_ZONE_URL_ML_REQUIRED=false \
docker compose -p <project> -f docker-compose.yml -f docker-compose.dev.yml up -d --force-recreate core-api

# 2) Xác minh rollback 5/5
python ml/src/check_v10_url_rollback.py --base-url http://127.0.0.1:8080

# 3) Khôi phục shadow 10% seeded (trạng thái đã kiểm chứng của Vòng 5)
docker compose -p <project> -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.canary.yml up -d --force-recreate core-api
```

Rollback feedback về memory (mất tính bền vững, không ảnh hưởng analyze):
bỏ `SAFE_ZONE_URL_ML_FEEDBACK_SECRET*` khỏi `.env` rồi recreate `core-api`.
Xoay key: tăng `SAFE_ZONE_URL_ML_FEEDBACK_KEY_VERSION`, đặt secret mới,
giữ `_PREVIOUS_SECRET`/`_PREVIOUS_KEY_VERSION` trong thời gian chuyển tiếp.

## 5. Evidence bundle Vòng 5

| Artifact | Nội dung |
|---|---|
| `ml/experiments/v10-url-canary-scope-changes.json` | audit trail scope 10→1→5→10 (seed `url-canary-v5-r5-20260826`) |
| `ml/experiments/v10-url-r5-window-{1,5,10}pct.json` | cửa sổ delta synthetic-driven; gate tool từ chối volume thiếu |
| `ml/experiments/v10-url-r5-failure-injection.json` | 4/4 PASS fail-open baseline/context |
| `ml/experiments/v10-url-r5-rollback-drill.json` | 5/5 PASS disabled→verify |
| `ml/experiments/v10-url-r5-ui-e2e-loop.json` | UI thật: analyze→sample→label→SQLite |
| `internal/risk/url_feedback_durable_test.go` | restart/rotation/privacy/fail-closed tests |
