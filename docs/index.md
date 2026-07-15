# Safe Zone

Safe Zone is an open-source, nonprofit project developing a DNS-level anti-phishing system for protecting users and organizations from phishing and impersonation websites in Vietnam.

The project is currently in active development. This repository describes an evolving implementation intended to become a useful community-serving tool; it does not claim complete coverage or production readiness for every deployment scenario. The public project direction is summarized on the [Safe Zone project page](https://www.quorix.io.vn/projects/safe-zone/).

The operator-facing production source of truth is [production-completion-checklist.md](production-completion-checklist.md). Historical design notes and implementation records remain under [specs/](specs/).

## Project direction

- **Scope:** DNS-level anti-phishing and domain-risk analysis for Vietnamese users and organizations.
- **Current status:** In development; features, integrations, and operational guidance continue to evolve.
- **Target outcome:** An open-source, community-serving system for filtering malicious domains through local policy and threat intelligence.
- **Core approach:** Go services, DoH and DoT, lexical analysis, threat feeds, optional local AI refinement, and a self-hosted operator control plane.

## Current build

- `core-api`: HTTP API for health checks, cached domain analysis, `/metrics`, and the self-hosted operator UI
- `dns-resolver`: local policy service with DoH `/dns-query`, optional DoT, and `/metrics`
- `feed-syncd`: optional interval-based threat-feed sync daemon for scheduled updates
- `redis`: optional local cache for analysis results and dashboard history
- `internal/analysis`: deterministic lexical scoring foundation
- `internal/cache`: Redis JSON helpers with fail-open behavior
- `internal/feed`: feed parsing and sync helpers shared by the CLI and daemon
- `internal/ai`: optional Gemini 2.5 Flash Lite refinement for ambiguous domains
- `internal/observability`: in-memory request metrics registry used by both HTTP services
- `internal/risk`: shared analysis, cache, policy, and status service used by both binaries
- `internal/serve`: graceful shutdown helper for local and container runs

## Frontend workspaces

- `ui/`: React source workspace for the primary operator UI, embedded and served by `core-api` at `/app/*`
- `internal/api/views`: embedded HTML templates for the legacy compatibility dashboard, login, and block page
- `internal/api/assets`: embedded CSS, JS, and font assets served at `/assets/*` by `core-api`
- `internal/api/handlers`: HTTP handler logic only

## Run locally

```bash
go run ./cmd/core-api
go run ./cmd/dns-resolver
```

Defaults:

- `core-api` listens on `:8080`
- `dns-resolver` listens on `:8081`
- Redis is disabled unless `SAFE_ZONE_REDIS_ADDR` is set
- Primary dashboard: <http://localhost:8080/app/>
- Legacy compatibility dashboard: <http://localhost:8080/dashboard>

`/app/*` is the production UI path. `/dashboard` remains available only during
the post-release stability period and will be deprecated after the React UI
passes its release gate and production smoke checks.

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

For a broader phishing/scam set suited to Vietnamese deployments, use
`SAFE_ZONE_AGENT_FEED_PRESET=production-vn`. It adds PhishDestroy Primary
Active and Phishing.Database Active to the minimal global preset. These are
global feeds selected as a broader baseline for Vietnamese deployments, not
Vietnam-specific feeds. General ad/tracker hosts lists are intentionally
excluded because every threat-feed match is treated as malicious. See
`docs/threat-intelligence-sources.md` for the source policy, additive-sync
retention limitation, and planned API/DNSBL/STIX/TAXII connectors.

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

The AI path is fail-open: if Gemini is unavailable or returns invalid JSON, analysis continues with lexical and threat-feed results. OSINT warning-page checks use deterministic attacker/victim context rules first and ask the configured AI provider only when the role is unclear.

## Dynamic Analysis Configuration

WHOIS responses are cached in SQLite for seven days by default. Override the
TTL with `SAFE_ZONE_WHOIS_CACHE_TTL_DAYS`.

Authenticated administrators can inspect and tune lexical scoring without
restarting the service:

- `GET /v1/config/analysis`
- `PUT /v1/config/analysis`
- `POST /v1/config/analysis/reset`

Updates are validated, persisted in SQLite, hot-reloaded into the analyzer, and
invalidate analysis cache entries through a deterministic configuration
revision.

For multi-node deployments, analysis-config propagation is controlled by:

- `SAFE_ZONE_CONFIG_RELOAD_ENABLED=true`
- `SAFE_ZONE_CONFIG_RELOAD_CHANNEL=safe-zone:config:analysis:updated`
- `SAFE_ZONE_CONFIG_RELOAD_POLL_SECONDS=30`

`core-api` and `dns-resolver` now tag reload events with their process role by
default, publish only revision invalidations over Redis Pub/Sub, and fall back
to periodic SQLite reconciliation when a node misses an event.

Operator visibility:

- `GET /` exposes `analysis_config_reload` with the loaded revision, last reload source, channel, and runtime subscriber/reconciler state.
- `GET /metrics` includes the same `analysis_config_reload` snapshot for lightweight debugging.
- Structured logs now show publish success/failure, duplicate or self-loop ignores, subscriber retries, Pub/Sub applies, and reconciliation self-heals.

## Secrets

Sensitive settings can be supplied either directly as `VAR=value` or indirectly through `VAR_FILE=./ops/secrets/name`.

The shared [ops/secrets/README.md](../ops/secrets/README.md) path works for:

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

The baseline JSON-metrics alert rules live in [ops/alerts/safe-zone-alert-rules.yaml](../ops/alerts/safe-zone-alert-rules.yaml), and the operator checklist is in [runbooks/alert-rules.md](runbooks/alert-rules.md).

## Security review

Before major releases, use the formal pre-release security checklist at [security/pre-release-security-checklist.md](security/pre-release-security-checklist.md) together with the main [runbooks/pre-release-checklist.md](runbooks/pre-release-checklist.md).

## Build

```bash
go build ./...
```

## CI release gate

GitHub Actions runs `mise run ci` on every push and pull request. The gate
includes Go lint/test/build, the React typecheck and embedded bundle build,
isolated Playwright E2E, `gosec`, `govulncheck`, and Docker builds for every
service. Playwright uses private test ports `15173` and `18080`, so it never
attaches to the normal local development pair on `5173` and `8080`.

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

The same actions are also available as `mise` tasks defined in [mise.toml](../mise.toml).

For a Linux VPS, [ops/cron/safe-zone.cron.example](../ops/cron/safe-zone.cron.example) provides a ready-made cron template for daily backup and prune jobs.

## Deployment Baseline

- Default production target: single budget VPS
- Preferred node: Hetzner CPX21 or equivalent 2 vCPU / 4 GB RAM
- Budget ceiling for the baseline path: about $10/month
- Higher tiers such as Vultr, DigitalOcean, Linode, or HA multi-node setups require explicit exception and cost justification

## Optional Services

- Redis is optional for local development and stays disabled unless `SAFE_ZONE_REDIS_ADDR` is set.
- `feed-syncd` is optional and only runs when the `feed-sync` Compose profile is enabled.
- Metrics, health checks, and the operator UI remain self-hosted; the runtime does not depend on a hosted SaaS control plane.

## Notes

This project remains in active development. DoT, Gemini, public TLS, DuckDNS, and production Caddy wiring are available as optional capabilities, while real-environment validation and release hardening continue.
Roadmap decisions should follow [Safe_Zone_OPEX_Estimate.md](Safe_Zone_OPEX_Estimate.md) as the source of truth for cost and deployment targets.
Cost-sensitive changes should follow [specs/opex-cost-optimization/policy.md](specs/opex-cost-optimization/policy.md) and the PR checklist at [.github/pull_request_template.md](../.github/pull_request_template.md).
