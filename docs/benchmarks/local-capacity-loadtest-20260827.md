# Safe Zone — Local Capacity Load Test (2026-08-27)

Scope: isolated Docker Compose project `safe-zone-loadtest` on the same host
(Windows 11 + Docker Desktop WSL2 VM: 8 vCPU / 7.67 GB RAM, engine 29.4.0,
Go 1.26.7). No public traffic, staging untouched, no signed evidence modified.

## Verdict

```
LOCAL_CAPACITY_PASS_BELOW_200K
```

Max sustainable per workload (generator+app share one 8-vCPU VM):

| Workload | Max sustainable | Saturation | Bottleneck class |
|---|---|---|---|
| A health `GET /healthz` | ~24,958 RPS (99.8%) | 25–27k | DOCKER_LIMITED / OS_LIMITED |
| B analyze-mixed | ~4,930 RPS clean fresh process | 5–6.1k hard plateau | APP_LIMITED (in-process) |
| C url-shadow disabled→shadow overhead | +23% CPU mid-load, −9..10% capacity near plateau | — | pure URL ML shadow cost |
| B with telemetry sampling 5% | same throughput, DB writes ÷~6+ | — | FIX shipped |

200k was not forced once the shared environment saturated first; generator never
saturated before the server (achieved tracked requested up to each ceiling).

## Key measurements

### A. HTTP ceiling ramp (10 s warm-up + 30 s windows)

1k→25k all ≥99.7% achieved, 0 errors, keep-alive 1.0, p99 2.1→10.8 ms.
Offering beyond ceiling: absorbed by bounded backpressure (`scheduler_queue_drops`)
with 0 timeout/reset/OOM at 50k and a confirm overload window at 100k (27.4k served,
837k dropped-by-design, max latency 126 ms).

### B. Analyze mixed pool (8192 rotating domains)

* Steady state touches Redis exactly once per multi-minute window (in-process cache).
* Telemetry insert is async with bounded channel and non-blocking drop-on-full
  (`internal/store/sqlite.go`), so SQLite cannot stall request handling.
* Fresh-process window @5k offer: 96.6% achieved, p99 27 ms → clean ceiling ~4.9–5k.
* Plateau across offers 6.5k/10k regardless of client concurrency ⇒ server-side cap.

### C. URL ML shadow A/B (same pool both sides)

| Level | Achieved Δ | Latency Δ | CPU api Δ |
|---|---|---|---|
| 2,500 RPS | ±0% | p50 +3%, p99 −5% | **+42 pp (+23%)** |
| 4,500 RPS | −9.3% | p50 ×1.9, p99 ×2.6 | +43 pp |

Response parity verified field-by-field (verdict/confidence/score/reasons/category/
cache_hit identical); only `url_ml` observation block differs by design.
Invalid URL contexts classified as `invalid_url_context` with `prediction_error: 0`.

## Stability windows

* Spike to 20k×15 s on analyze path: zero errors, max latency 160 ms, instant recovery.
* Soak 15 min @3.2k: 0 errors; Soak 30 min @2.2k: **zero drops**, 0 errors,
  p50 8.1 ms cumulative. GC `gctrace=1`: live heap flat `→7 MB`, pauses 2–9 ms.
* Heap exonerated end-to-end: VmRSS 31–40 MB constant, VmHWM 40.5 MB; docker-stats
  “RSS” growth was kernel page-cache of the growing SQLite file (cgroup `file` vs
  `anon`). Heap-live after cooldown: 6 MB.
* Container restart under load: **downtime 2.2 s**, 98.2% window throughput held,
  remaining failures were pre-gap transport errors only; rc=0, oom=false.
* Redis pause/unpause drill: `/healthz` stayed 200 during outage; recovery immediate.
* Race stress window (30 s @300 RPS through full analyze pipeline on `-race` build):
  **DATA RACE COUNT = 0** (numbers excluded from benchmarks by policy).

## Fix shipped from findings

Telemetry storage grew at **71.0 bytes/request** (measured over 30-min soak):
unsustainable high-water at sustained rates (e.g., ~402 GB @2,185 RPS with 30-day
retention because SQLite reuses freed pages instead of shrinking).

Fix: `SAFE_ZONE_TELEMETRY_WRITE_PERCENT` (default 100 = unchanged behavior) samples
analysis-log writes uniformly at the single choke point `RecordAnalysis`; validated
live at 5%: identical success rates, api CPU ↓18%, main-file growth nearly flat,
WAL bounded at its normal checkpoint size (~4.2 MB). Unit test covers 100%/0%/10%
buckets (`internal/store/sqlite_sampling_test.go`).

Ops sizing formula (write-percent W, sustained rate R):

```
steady_state ≈ W × 71 B × R × 86,400 × retention_days
```

Example: budget-VPS wanting ≤2 GB steady state at 500 RPS must set W ≤ 6%.

Also fixed during this effort: the load-ramp scheduler previously leaked a 5 s grace
past the measurement window via a shared context; it now stops exactly at `duration`
and leftover queued tokens are accounted as drops, keeping Sent == Completed+Errors+
Drops reconcilable (validated by wall-clock and accounting parity smoke tests).

## Remaining local-test limitations

* Generator and target share one WSL2 VM ⇒ absolute ceilings are lower-bound;
  reproduce on the target VPS for production numbers (commands below).
* Goroutine counts require an exported endpoint (`/debug/pprof`) — recommended
  follow-up instrumentation; race detector already covered hot paths meanwhile.
* Feedback chain validated end-to-end (analyze with `event_id` → recorded:true,
  labelled_events counters, HMAC fingerprints only) plus its own limiter burst.

## Reproduce commands (target host, loopback only)

```bash
docker compose -p <proj> -f docker-compose.yml -f docker-compose.loadtest.yml \
  up -d --build core-api
docker compose -p <proj> -f docker-compose.yml -f docker-compose.loadtest.yml \
  run --rm loadgen -url http://core-api:8080 -workload health \
  -rate 25000 -duration 30s -warmup 10s -conns 64
# workloads: health | analyze-mixed | url-shadow
# URL ML shadow A/B: add `-f tmp/loadtest-shadow.yml`, toggle mode, repeat windows
```

Artifacts (checksummed): `tmp/bench/loadtest-{a,b,c,d,e,f}/` including every JSON
window result, docker-stats snapshots, gctrace marks and external sampler logs.
Raw payloads are discarded by the generator (drained, never stored).
