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
