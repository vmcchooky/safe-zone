# Local Release-Gate Evidence — 2026-11-19

> **Scope:** executable Gate A validation on a production-like Docker stack on
> the operator workstation. This record proves the release candidate can boot,
> serve, sync feeds, survive backup/restore, and carry load in a
> `SAFE_ZONE_ENV=production` configuration. It **does not** close the
> target-VPS gates (RB-1, A6) or the clean-machine restore gate (RB-2).

## Release identity

| Item | Value |
| --- | --- |
| Candidate | `1.10.22-rc.2` |
| Runtime commit | `68d6bc162a9ee9c0cdb35784cc3bdae03ea001a5` |
| Preflight commit | `69a4618` (docs-only delta from the runtime commit) |
| Compose follow-up | `0fe544e` — disable the inherited HTTP healthcheck on the feed workers |
| Go toolchain | `1.26.11` (`go.mod`, `mise.toml`, `Dockerfile`) |
| Edge mode | `production-edge` |
| Deployment tier | `production-edge-staging` |

The candidate fixes three release-gate defects found during this validation:

1. `GO-2026-6859` in Go 1.26.10, fixed by moving the toolchain to 1.26.11.
2. The retired anonymous URLhaus download endpoints (HTTP 410), replaced in
   the `production-free` / `production-vn` presets with
   `malware-filter/phishing-filter-domains.txt`.
3. The inherited `/readyz` healthcheck on `feed-syncd`, which reported the
   worker permanently unhealthy because it has no HTTP listener.

## Preflight

```powershell
.\scripts\ops\release-preflight.ps1 -EdgeMode production-edge -Version 1.10.22-rc.1
# after the fixes, on the release branch head:
.\scripts\ops\release-preflight.ps1 -EdgeMode production-edge -Version 1.10.22-rc.2
```

- The first run failed `govulncheck` on GO-2026-6859.
- After the Go 1.26.11 bump and the feed fixes, the full rc.2 preflight passed:
  `ui-bundle`, `go-test`, `go-build`, `gosec`, `govulncheck`, both Go service
  builds, and all four Docker image builds.
- Evidence: `tmp/release-gate/20261119-142420_production-edge/` (rc.1
  discovery run) and `tmp/release-gate/20261120-075115_production-edge/`
  (rc.2 passing run at `69a4618`).

PR [#260](https://github.com/vmcchooky/safe-zone/pull/260) (toolchain) has a
green CI run: all required check runs completed successfully.

## Local production-like staging

Environment differences from the target VPS, and why they matter:

| Setting | Local value | Consequence |
| --- | --- | --- |
| `SAFE_ZONE_PUBLIC_HOST` | `localhost` | Caddy uses its internal CA; this is not an ACME/Let's Encrypt proof. |
| `SAFE_ZONE_BLOCK_PAGE_IP` | `192.168.1.4` (LAN) | Production correctly rejects loopback; HTTPS block-page checks target the canonical host. |
| Host | Windows 11 + Docker Desktop 29.4.0, WSL2 Ubuntu | Not the target VPS class. |

Stack: `docker compose -f docker-compose.yml -f docker-compose.production.yml
--profile production-edge` with `caddy`, `core-api`, `dns-resolver`,
`feed-syncd`, and `redis`.

Recorded checks:

| Check | Result |
| --- | --- |
| `/healthz` | 200 |
| `/readyz` | 200 |
| `/v1/version` (`core-api`, `dns-resolver`) | both report `1.10.22-rc.2`, commit `68d6bc1…` |
| `GET /app/` | 200 |
| `POST /v1/analyze` | 200, `example.com` → `SAFE` |
| `/metrics` unauthenticated / authenticated | 401 / 200 |
| Dashboard login + session | 200, `admin` session with mutate rights |
| DoH through Caddy (`/dns-query`) | 200, `rcode=0` |
| Block page over HTTP and canonical HTTPS | pass (`check-block-page.sh`) |
| Public-edge smoke (`--no-dot`) | pass (`public-edge-smoke.sh`) |
| Remote port scan of the published host | 80/443 open; 8080/8081/6379/11434/853 closed |
| Container bindings / internal listeners | pass; only warning `ufw not installed` |

Evidence: `tmp/release-gate/local-staging-20261119/` (`verify.sh` output,
`public-edge-smoke-after-feed-fix.log`, `check-block-page-after-feed-fix.log`,
`check-production-ports-after-feed-fix.log`, `check-feed.log`).

Limitations:

- DoT was not exercised (`--no-dot`). RB-4 remains conditional and open.
- The Caddy internal CA and `localhost` hostname do not prove public DNS,
  ACME issuance, or an external client's trust path.
- The port scan ran from the same LAN, not from an independent network.

## Feed pipeline

The first local sync exposed a real release blocker: URLhaus now answers every
anonymous `https://urlhaus.abuse.ch/downloads/` path with **HTTP 410**, leaving
`feed_sync.status=stale` on a fresh deployment. The presets now use:

- `https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt`
- `https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt`

Post-fix status:

```text
feed_sync.status      ok
feed_sync.stale       false
feed_sync.revision    2
feed_sync.active      17312 entries
OpenPhish             ok, 0 new entries (already present)
malware-filter        ok, 17029 written
```

The same sync also exposed a further defect: `feed-syncd` inherited the image
`/readyz` healthcheck although it has no HTTP listener, so it was permanently
`unhealthy`. The production Compose stack now disables the healthcheck for
`feed-syncd` and the one-shot `feed-sync` job; liveness stays visible through
`/v1/status` and the sync log.

## Restore drill

```powershell
.\scripts\ops\tests\restore-drill-test.ps1
```

The drill boots an isolated Compose project, seeds brands and one Redis cache
entry through the admin API, backs up, verifies the checksum manifest, deletes
the seeded state, restores through `scripts/ops/safe-zone.ps1`, and verifies the
restored SQLite file, Redis state, and live API.

| Metric | Result |
| --- | --- |
| Verdict | `RESTORE DRILL PASS` |
| Wall clock | 3.42 minutes |
| RTO target | 60 minutes |
| RPO target | 24 hours |
| SQLite checksum | matched the backup (`97e8d54f8a72…`) |
| Redis cache entry | survived the restore |
| Restored API state | 3 seeded brands and names verified |

Evidence: `tmp/release-gate/local-staging-20261119/restore-drill.log` and
`restore-drill-summary.txt`.

Limitations: the drill ran on the operator workstation with cached Docker
images and an existing repository checkout. It does not prove a clean-VM
recovery where the operator must install Docker, fetch the release, and
reconstruct secrets from outside the host. RB-2 stays open for that step.

## Local capacity check

Hardware: 11th Gen Intel Core i7-1185G7, 4 cores / 8 threads, 7.67 GB RAM
available to Docker Desktop (WSL2), Docker Engine 29.4.0. The load generator and
the target share the same Docker VM, so this is a **generator-limited** setup,
not an independent VPS measurement.

| Workload | Offered | Achieved | Errors / 5xx | p95 | p99 | Classification |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Health | 3,000 RPS / 15 s | 2,998 RPS | 0 / 0 | 4.6 ms | 6.8 ms | clean |
| Health | 10,000 RPS / 30 s | 9,990 RPS | 0 / 0 | 9.3 ms | 15.1 ms | 0 errors; p99 marginally above the 15 ms expectation |
| Analyze mixed | 2,500 RPS / 45 s | 2,045.6 RPS | 0 / 0 | 59.4 ms | 203.4 ms | `GENERATOR_LIMITED` — 20,373 scheduler drops |
| Analyze mixed | 1,500 RPS / 45 s | 1,494.5 RPS | 0 / 0 | 138.4 ms | 210.5 ms | 202 scheduler drops (0.3%) |
| Analyze mixed short soak | 1,200 RPS / 5 min | 1,199.2 RPS | 0 / 0 | 81.9 ms | 199.9 ms | 0 drops; RSS 67.5 MiB at the end, no restart/OOM |

The analyze path produced no HTTP errors or timeouts at any rate; the shortfall
appears as open-loop scheduler queue drops, which is the documented
`GENERATOR_LIMITED` signal. The 5-minute run is a bounded stability check, not a
memory-leak proof; the canonical 30-minute soak remains
`docs/benchmarks/local-capacity-loadtest-20260827.md`. These numbers must not be
reported as `VPS_CAPACITY_PASS`.

Evidence: `tmp/bench/local-workstation-20261119/` (`health-3000rps.log`,
`health-10000rps.log`, `analyze-2500rps.log`, `analyze-1500rps.log`,
`analyze-soak-1200rps-5m.log`, `docker-stats-after-soak.txt`,
`wsl-hardware.txt`, `docker-info.txt`).

## Remaining external gates

| Gate | Status | Why it remains open |
| --- | --- | --- |
| RB-1 / A3 edge proof on the target VPS | **OPEN** | The target VPS `85.211.194.199` timed out on SSH/22 and HTTPS/443 on 2026-11-19 and again on 2026-11-20; no Azure CLI is installed on the workstation. `safe-zone.duckdns.org` currently resolves to `93.127.213.60`, where port 80 serves an unrelated nginx 403 and 22/443 are closed, so that address is not the Safe Zone edge. Local staging ports/smoke pass does not replace target execution. |
| A6 VPS capacity | **OPEN** | No access to the target VPS class; local numbers are generator-limited. |
| RB-2 clean-machine restore | **OPEN** | Local isolated-stack drill passed, clean-host variables unproven. |
| RB-4 public DoT | **OPEN / conditional** | DoT was not part of this run (`--no-dot`); requires configured cert/key and a verified handshake. |

Go/No-Go: **Gate A remains `PENDING_VPS`.** The deterministic product surface is
validated locally, but the target-environment evidence above is still required
before a public production release.
