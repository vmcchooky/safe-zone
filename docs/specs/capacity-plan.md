# Capacity plan for 10x traffic

This document proposes how Safe Zone should scale if production traffic grows by roughly 10x from the current single-VPS MVP baseline.

## Scope

The plan covers:

- public edge
- DoH and DoT request handling
- `core-api`
- Redis cache
- SQLite-backed operator state
- feed sync and background enrichment

It does not claim the 10x target is already proven. It is the operating plan once benchmarks and production evidence show current limits.

## Current baseline assumptions

- Single VPS is the default deployment model.
- Redis is used for cache and threat-feed state.
- SQLite is used for telemetry and operator data.
- Enrichment and feed sync are backgrounded but still share the same host in the MVP.

## Main scaling pressure points

At 10x traffic, expect pressure first on:

1. DoH/DoT request concurrency
2. Redis memory and connection count
3. `core-api` CPU from lexical analysis, JSON, and cache churn
4. background enrichment queue depth
5. SQLite write pressure from telemetry

## Proposed scale strategy

### Phase 1: Stretch the single-node design

Use this first because it is cheapest and matches the current repo:

- Increase VPS size to at least 4 vCPU / 8 GB RAM
- Keep Redis on the same host but assign explicit memory limits
- Keep telemetry retention short and bounded
- Disable optional AI paths if they become the main latency or cost driver
- Benchmark cache-hit and cache-miss paths after each size increase

Exit phase 1 when:

- cache-hit latency or Redis memory becomes unstable under expected peak load
- enrichment queue delay becomes operationally visible

### Phase 2: Split hot paths by role

Recommended next step:

- Node A: public edge + `dns-resolver`
- Node B: `core-api` + operator dashboard + background jobs
- Node C: Redis + SQLite-backed persistent storage or a managed equivalent

Benefits:

- DNS traffic no longer competes with dashboard/API requests
- Redis and persistence get cleaner resource isolation
- `core-api` can be tuned without moving the DNS edge at the same time

### Phase 3: Add horizontal replicas where it actually helps

Once split by role:

- Run multiple `core-api` instances behind a private reverse proxy or load balancer
- Run multiple `dns-resolver` instances behind edge routing if public demand requires it
- Keep Redis as a dedicated service, then decide whether HA Redis is worth the cost

SQLite note:

- SQLite is fine for the MVP and low-to-moderate telemetry volumes
- If telemetry writes become the bottleneck, move only telemetry and audit storage first; do not migrate operator control-plane data blindly

## 10x target architecture recommendation

For a practical 10x path, prefer:

1. Keep one public edge hostname and TLS termination layer
2. Separate `dns-resolver` from `core-api`
3. Move Redis to its own protected node or managed service
4. Keep feed sync and enrichment on the `core-api` side, but rate-limit them aggressively
5. Re-evaluate SQLite once telemetry volume proves it is the bottleneck

## Guardrails

- Do not add multi-node complexity before benchmark evidence justifies it
- Preserve fail-open behavior where optional dependencies are unavailable
- Keep backup, restore, and onboarding docs in sync with any topology change
- Repeat the performance proof after every architecture phase change

## Trigger table

| Trigger | Action |
| --- | --- |
| Redis memory or CPU becomes the first limiter | Move Redis off the app node first |
| DoH/DoT latency rises while dashboard/API remains healthy | Split `dns-resolver` from `core-api` |
| Telemetry writes lag or cleanup windows become noisy | Shorten retention first, then reassess storage split |
| Enrichment jobs create queue backlog under attack traffic | Tighten suspicious thresholds, rate limits, and worker concurrency before adding more outbound capacity |
