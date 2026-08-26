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

URL ML shadow health:

```sh
curl -fsS http://127.0.0.1:8080/metrics | jq '.ml.url | {state, prediction_attempts, error_histogram, latency_p95_us, sampling, drift}'
```

`drift.state=proxy_shift` is diagnostic only because the bundled reference is a balanced offline cohort. The drift alert becomes blocking only when `operational_reference=true` after a representative live baseline has been frozen.

## Log retention

Docker JSON logs are capped through Compose with:

- `SAFE_ZONE_DOCKER_LOG_MAX_SIZE`
- `SAFE_ZONE_DOCKER_LOG_MAX_FILE`

The defaults in `.env.example` keep five files of ten megabytes per container.
