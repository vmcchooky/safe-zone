# Safe Zone

Safe Zone is a zero-cost-first anti-phishing system whose default deployment target is a single budget VPS, with local-friendly Go services for development and validation.

Legacy note: [docs/Safe_Zone_SRS_Zero_Cost_v1.0.md](docs/Safe_Zone_SRS_Zero_Cost_v1.0.md) is kept for historical reference only. The operator-facing production source of truth is [docs/production-completion-checklist.md](docs/production-completion-checklist.md), with deeper implementation detail kept under [docs/specs/](docs/specs/).

## Current build

- `core-api`: HTTP API for health checks, cached domain analysis, `/metrics`, and the local dashboard
- `dns-resolver`: local policy service with a real DoH `/dns-query` endpoint and `/metrics`
- `feed-syncd`: optional interval-based threat-feed sync daemon for scheduled updates
- `redis`: optional local cache for analysis results and dashboard history
- `internal/analysis`: deterministic lexical scoring for the first release
- `internal/cache`: Redis JSON helpers with fail-open behavior
- `internal/feed`: feed parsing and sync helpers shared by the CLI and daemon
- `internal/ai`: optional Gemini 2.5 Flash Lite refinement for ambiguous domains
- `internal/observability`: in-memory request metrics registry used by both HTTP services
- `internal/risk`: shared analysis, cache, policy, and status service used by both binaries
- `internal/serve`: graceful shutdown helper for local and container runs

## Run locally

```bash
go run ./cmd/core-api
go run ./cmd/dns-resolver
```

Defaults:

- `core-api` listens on `:8080`
- `dns-resolver` listens on `:8081`
- Redis is disabled unless `SAFE_ZONE_REDIS_ADDR` is set
- Dashboard: <http://localhost:8080/dashboard>

Optional local Redis:

```bash
docker run --rm -p 6379:6379 redis:7-alpine
$env:SAFE_ZONE_REDIS_ADDR = "localhost:6379"
```

Useful endpoints:

```bash
curl "http://localhost:8080/"
curl "http://localhost:8080/metrics"
curl "http://localhost:8080/v1/analyze?domain=secure-login-wallet-example.com"
curl "http://localhost:8081/"
curl "http://localhost:8081/metrics"
curl "http://localhost:8081/v1/policy?domain=secure-login-wallet-example.com"
```

Blocked-domain UX:

- `http://blocked.example.test/` can be sinkholed to the Safe Zone block page in production.
- `https://$SAFE_ZONE_PUBLIC_HOST/block?domain=blocked.example.test` provides the canonical HTTPS explanation page.
- Direct HTTPS to an arbitrary blocked third-party domain still depends on that domain's certificate and may show a browser warning before any block page can render.

## Threat feed

Threat feed entries are normalized domains stored in Redis Set `safe-zone:threat:feed`. Use `feed-sync` manually first:

```bash
go run ./cmd/feed-sync -source ./feeds/local.txt -dry-run
go run ./cmd/feed-sync -source ./feeds/local.txt -redis-addr localhost:6379
```

Threat feed sync also accepts `.gz` feeds over local file paths or HTTP(S) URLs.
The optional daemon is available as `go run ./cmd/feed-syncd --once` or through the Compose `feed-sync` profile.

Accepted feed formats are TXT, CSV, gzip-compressed files, and whitespace-separated URL lists such as the OpenPhish community feed. Exact matches and subdomain suffix matches return `MALICIOUS` with reason `matched local threat feed`.

For the first-class free production preset, set:

```env
SAFE_ZONE_AGENT_FEED_PRESET=production-free
```

That preset currently expands to URLhaus recent CSV plus the OpenPhish community feed. `core-api` exposes feed freshness, stale warnings, parser-drift warnings, and feed revision metadata on `/` and `/metrics` when Redis is enabled.

The DoH endpoint accepts standard DNS wire-format GET or POST requests at:

```text
http://localhost:8081/dns-query
```

If you start the Docker dev stack, DoT is also exposed on loopback at:

```text
tls://127.0.0.1:1853
```

## Local AI

Safe Zone can optionally refine ambiguous risk results using Gemini 2.5 Flash Lite.

Defaults:

- `SAFE_ZONE_GEMINI_BASE_URL`: `https://generativelanguage.googleapis.com/v1beta`
- `SAFE_ZONE_GEMINI_API_KEY`: empty, so AI is disabled unless explicitly configured
- `SAFE_ZONE_GEMINI_MODEL`: `gemini-2.5-flash-lite`
- `SAFE_ZONE_GEMINI_TIMEOUT_MS`: `3000`

The AI path is fail-open: if Gemini is unavailable or returns invalid JSON, analysis continues with lexical and threat-feed results.

## Secrets

Sensitive settings can be supplied either directly as `VAR=value` or indirectly through `VAR_FILE=./ops/secrets/name`.

The shared [ops/secrets/README.md](</D:/Quorix/services/safe-zone/ops/secrets/README.md>) path works for:

- local `go run` from the repo root
- Docker Compose services, which mount `./ops/secrets` into `/app/ops/secrets`
- host-side DuckDNS updates

Production should set `SAFE_ZONE_ENV=production`. In that mode, `core-api` now fails startup when:

- `SAFE_ZONE_ADMIN_PASSWORD` is missing or weak
- `SAFE_ZONE_ADMIN_API_KEY` is missing or weak

In local mode, missing admin secrets still fall back to generated temporary values for convenience.

## Agent workflow

`core-api` can optionally start the internal agent engine for audit, multi-source feed sync, webhook alerts, and whitelist refresh tasks.

Enable it through `.env`:

```env
SAFE_ZONE_AGENT_ENABLED=true
SAFE_ZONE_AGENT_FEED_PRESET=production-free
SAFE_ZONE_AGENT_WEBHOOK_URL=
```

The dashboard System tab exposes `/v1/agent/status` and manual trigger buttons for registered tasks.

## Logging and alerts

HTTP responses now carry `X-Request-ID`, the main request pipeline emits structured JSON request logs for `core-api` and `dns-resolver`, and scheduled/background jobs emit a shared `run_id` for log correlation.

The baseline JSON-metrics alert rules live in [ops/alerts/safe-zone-alert-rules.yaml](ops/alerts/safe-zone-alert-rules.yaml), and the operator checklist is in [docs/runbooks/alert-rules.md](docs/runbooks/alert-rules.md).

## Build

```bash
go build ./...
```

## Docker

```bash
cp .env.example .env
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

The dev stack binds `core-api`, `dns-resolver`, and DoT to loopback only for local validation.
The production stack uses `docker-compose.production.yml`, keeps `8080` and `8081` on loopback, and publishes only `80`, `443`, and `853`.
The runtime image includes an internal HTTP healthcheck, and the optional `feed-syncd` service is gated behind the `feed-sync` Compose profile.

## Operations

Use the PowerShell helper for day-to-day deployment and storage maintenance:

```powershell
pwsh ./scripts/safe-zone.ps1 deploy
pwsh ./scripts/safe-zone.ps1 deploy-dev
pwsh ./scripts/safe-zone.ps1 status
pwsh ./scripts/safe-zone.ps1 backup
pwsh ./scripts/safe-zone.ps1 restore
pwsh ./scripts/safe-zone.ps1 prune
pwsh ./scripts/safe-zone.ps1 feed-sync
```

- `deploy` builds and starts the Compose stack, then waits for the health endpoints.
- `deploy-dev` starts the local dev stack with loopback-only bindings.
- `backup` writes a Redis RDB snapshot to `backups/redis/<timestamp>/dump.rdb`.
- `restore` reloads Redis from the newest snapshot or a path you pass in.
- `prune` keeps the newest backups and removes stale `tmp/*.log` files.
- `feed-sync` resolves `SAFE_ZONE_AGENT_FEED_SOURCES`, then `SAFE_ZONE_AGENT_FEED_PRESET`, then `SAFE_ZONE_THREAT_FEED_SOURCE`, and runs each source once.

For Linux hosts, the equivalent shell helper supports `deploy`, `deploy-dev`, and the `SAFE_ZONE_STACK=production|dev` selector for status/log/backup helpers.

The same actions are also available as VS Code tasks in [.vscode/tasks.json](.vscode/tasks.json).

For a Linux VPS, [ops/cron/safe-zone.cron.example](ops/cron/safe-zone.cron.example) provides a ready-made cron template for daily backup and prune jobs.

## Deployment Baseline

- Default production target: single budget VPS
- Preferred node: Hetzner CPX21 or equivalent 2 vCPU / 4 GB RAM
- Budget ceiling for the baseline path: about $10/month
- Higher tiers such as Vultr, DigitalOcean, Linode, or HA multi-node setups require explicit exception and cost justification

## Optional Services

- Redis is optional for local development and stays disabled unless `SAFE_ZONE_REDIS_ADDR` is set.
- `feed-syncd` is optional and only runs when the `feed-sync` Compose profile is enabled.
- Metrics, health checks, and the current local dashboard remain self-hosted and dependency-free.

## Notes

This build is still local-first. DoT, Gemini, public TLS, DuckDNS, and production Caddy wiring can layer on top of the current Redis and DoH foundation.
Roadmap decisions should follow [docs/Safe_Zone_OPEX_Estimate.md](docs/Safe_Zone_OPEX_Estimate.md) as the source of truth for cost and deployment targets.
Cost-sensitive changes should follow [docs/specs/opex-cost-optimization/policy.md](docs/specs/opex-cost-optimization/policy.md) and the PR checklist at [.github/pull_request_template.md](.github/pull_request_template.md).
