<div align="center">
  <img src="ui/public/favicon.svg" width="96" alt="Safe Zone logo">
  <h1>Safe Zone</h1>
  <p><strong>DNS-level anti-phishing for Vietnam.</strong></p>
  <p>
    <a href="https://github.com/vmcchooky/safe-zone/actions/workflows/ci.yml"><img src="https://github.com/vmcchooky/safe-zone/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="https://github.com/vmcchooky/safe-zone/actions/workflows/security.yml"><img src="https://github.com/vmcchooky/safe-zone/actions/workflows/security.yml/badge.svg" alt="Security"></a>
    <a href="https://go.dev/"><img src="https://img.shields.io/github/go-mod/go-version/vmcchooky/safe-zone" alt="Go Version"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
    <a href="docs/runbooks/production-edge.md"><img src="https://img.shields.io/badge/DNS-DoH_%2F_DoT-blue" alt="DNS"></a>
    <a href="docker-compose.production.yml"><img src="https://img.shields.io/badge/platform-linux--amd64-lightgrey" alt="Platform"></a>
  </p>
  <p>English | <a href="README.vi.md">Tiếng Việt</a></p>
</div>

![Safe Zone overview](docs/diagrams/hero.png)

Safe Zone is an open-source, nonprofit project that blocks phishing and
impersonation websites at the DNS layer — before the browser ever loads them.
It runs as a self-hosted operator control plane you fully own: no SaaS
account, no third-party control plane, no data leaving your VPS.

> **Status: Release Candidate** (`RELEASE_CANDIDATE_SHADOW_READY`). The core
> engine and URL-ML shadow integration passed local capacity testing; final
> VPS validation is in progress. Not every deployment scenario is
> production-ready — see [Project status](#project-status) and the operator
> source of truth,
> [docs/production-completion-checklist.md](docs/production-completion-checklist.md).

## Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quickstart](#quickstart)
- [Try it](#try-it)
- [Configuration](#configuration)
- [Threat intel and ML](#threat-intel-and-ml)
- [Evaluation](#evaluation)
- [Security](#security)
- [Deployment](#deployment)
- [Project status](#project-status)
- [Contributing](#contributing)
- [Credits](#credits)
- [License](#license)

## Features

**Protection**
- **Layered domain verdicts** — deterministic lexical scoring (typosquat,
  brand abuse, DGA and entropy analysis, IDN homoglyphs), live threat-feed
  matching, and background TLS/WHOIS enrichment that only promotes a verdict
  with corroborating evidence.
- **DoH and DoT out of the box** — DNS-over-HTTPS at `/dns-query` and
  DNS-over-TLS on port `853`, with CNAME uncloaking and sinkhole, NXDOMAIN,
  refused, and null-IP block strategies.
- **Ads, trackers, and telemetry as policy** — content blocking stays a
  *policy action* and is never mislabeled as malware. Telemetry endpoints,
  for example, are `SUSPICIOUS` with a policy block, not `MALICIOUS`.

**Operations**
- **Operator UI and API** — React dashboard at `/app/`, cached analysis,
  overrides, client groups, user reports, and Prometheus-style `/metrics`.
- **Fail-open by design** — outages in Redis, feeds, OSINT, AI, or enrichment
  degrade coverage but never take down resolution. SQLite persistence is
  required in production, so operator intent is never lost silently.
- **Budget-VPS friendly** — single-node Compose stack, roughly $10/month
  baseline, with 5% telemetry write sampling in production.

**Extensibility**
- **Optional local AI/ML** — Gemini/Ollama refinement plus a LightGBM domain
  classifier behind `disabled → shadow → canary → enforce` gates. Off by
  default.
- **Evidence-led evaluation** — versioned truth and contract corpora with
  provenance discipline: `unknown` never counts toward precision or recall.

## Architecture

![Safe Zone edge architecture](docs/diagrams/edge-architecture.png)

Internal ports `:8080` and `:8081` stay **loopback-only** in production; only
`80`, `443`, and `853` are published (verified — see
[edge verification](docs/deployment/edge-verification-2026-09-20.md)).

| Decision pipeline | Scoring |
|---|---|
| ![Verdict pipeline](docs/diagrams/verdict-pipeline.png) | ![Scoring](docs/diagrams/scoring.png) |

Further diagrams: [deployment](docs/diagrams/deployment.png) ·
[DoH sequence](docs/diagrams/doh-sequence.png) ·
[defense layers](docs/diagrams/defense-layers.png).
Interactive HTML versions live alongside the PNGs in [`docs/diagrams/`](docs/diagrams/).

## Quickstart

Prerequisites: Go 1.26+ (or Docker).

```bash
git clone https://github.com/vmcchooky/safe-zone.git
cd safe-zone

# Terminal 1 — API and dashboard at http://localhost:8080/app/
go run ./cmd/core-api

# Terminal 2 — DNS policy and DoH at http://localhost:8081/dns-query
go run ./cmd/dns-resolver
```

With Docker (development stack, loopback-only bindings):

```bash
cp .env.example .env
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

Point a test client at it and query:

```bash
# DNS-over-HTTPS (RFC 8484): example.com IN A
curl -s 'http://localhost:8081/dns-query?dns=EjQBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE' \
  -H 'accept: application/dns-message' | xxd | head -3
```

## Try it

```bash
# Verdict and reasons for a suspicious domain
curl "http://localhost:8080/v1/analyze?domain=secure-login-wallet-example.com"

# The policy decision the DNS layer will enforce
curl "http://localhost:8081/v1/policy?domain=secure-login-wallet-example.com"

# Service health and feed freshness
curl "http://localhost:8080/v1/status"
curl "http://localhost:8080/metrics"
```

Blocked-domain behavior: plain-HTTP sinkhole renders the block page with a
user report form, and
`https://$SAFE_ZONE_PUBLIC_HOST/block?domain=…` is the canonical HTTPS
explanation page. Direct HTTPS to an arbitrary blocked third-party domain
still shows that domain's certificate warning first — a TLS limitation shared
by every non-MITM DNS filter, not a bug.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SAFE_ZONE_ENV` | `local` | Set `production` to require strong admin secrets and SQLite |
| `SAFE_ZONE_REDIS_ADDR` | _(unset)_ | Enables Redis cache and feeds, e.g. `localhost:6379` |
| `SAFE_ZONE_PUBLIC_HOST` | `localhost` | Public hostname for Caddy TLS and DoH |
| `SAFE_ZONE_ADMIN_PASSWORD` / `SAFE_ZONE_ADMIN_API_KEY` | _(generated locally)_ | Required (or `*_FILE`) in production |
| `SAFE_ZONE_ML_MODE` | `disabled` | `disabled` / `shadow` / canary / `enforce` (gated) |
| `SAFE_ZONE_TELEMETRY_WRITE_PERCENT` | `100` locally, `5` in prod | Telemetry sampling ([sizing](docs/runbooks/production-edge.md)) |
| `SAFE_ZONE_WHOIS_CACHE_TTL_DAYS` | `7` | WHOIS cache TTL in SQLite |

Secrets accept `VAR_FILE=./ops/secrets/name` (local runs, Compose, and
host-side helpers — see [ops/secrets/README.md](ops/secrets/README.md)).
Administrators can hot-tune lexical scoring without restarts via
`GET/PUT /v1/config/analysis` (revisioned, with multi-node propagation).

## Threat intel and ML

- **Feeds** live in the Redis set `safe-zone:threat:feed`. Start manually,
  then schedule the daemon:
  ```bash
  go run ./cmd/feed-sync -source ./feeds/local.txt -dry-run
  go run ./cmd/feed-sync -source ./feeds/local.txt -redis-addr localhost:6379
  ```
  Free presets: `SAFE_ZONE_AGENT_FEED_PRESET=production-free` (URLhaus and
  OpenPhish) or `production-vn` (adds PhishDestroy and Phishing.Database for
  Vietnamese deployments). Source policy:
  [threat-intelligence-sources.md](docs/research/security/threat-intelligence-sources.md).
- **Domain ML** (LightGBM, 534 features, calibrated) ships as a signed bundle
  mounted read-only; `shadow` mode observes without changing verdicts until
  the promotion gates pass. See [safe-zone-ai-plan.md](docs/specs/safe-zone-ai-plan.md).
- **Agent engine** (audit, feed sync, OSINT, alerts, whitelist refresh) is
  opt-in with per-task configuration and rollback drills. Do not enable
  production schedules from the minimal example alone.

## Evaluation

Behavior is pinned by frozen offline corpora — truth, contract, and FP-guard
(21 production hosts, 21 of 21 allow, FPR 0):

```bash
mise run eval:decision
# go run ./cmd/eval-decision check --corpus internal/eval/testdata/corpus.v2.json \
#   --expected internal/eval/testdata/expected.v2.json   (+ 3 more pairs)
```

Labels require provenance (capture, warning, ownership document, or recorded
owner review). `unknown` never enters precision, recall, or FPR denominators.
Full gate definition:
[decision-engine-rebuttal-plan.md](docs/research/security/decision-engine-rebuttal-plan.md).

## Security

- Threat model with release blockers: [docs/security/threat-model.md](docs/security/threat-model.md)
- Pre-release checklist: [docs/security/pre-release-security-checklist.md](docs/security/pre-release-security-checklist.md)
- Found a vulnerability? **Do not open a public issue.** See
  [docs/runbooks/credential-rotation.md](docs/runbooks/credential-rotation.md)
  for secret handling, and contact the maintainers privately via the project
  page: <https://www.quorix.io.vn/projects/safe-zone/>.

## Deployment

Single budget VPS (Hetzner CPX21 class, 2 vCPU / 4 GB, about $10/month ceiling):

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d --build
```

Day-to-day operations (`pwsh ./scripts/ops/safe-zone.ps1 …`, or
`scripts/ops/safe-zone.sh` on Linux): `deploy`, `status`, `backup`,
`restore`, `prune`, `feed-sync`. Full edge guide (firewall, DoT certificates,
DuckDNS, cron): [production-edge.md](docs/runbooks/production-edge.md).
Cost policy: [Safe_Zone_OPEX_Estimate.md](docs/deployment/Safe_Zone_OPEX_Estimate.md).

## Project status

Release Candidate (`RELEASE_CANDIDATE_SHADOW_READY`): the engine and URL-ML
shadow integration passed local capacity testing
(`LOCAL_CAPACITY_PASS_BELOW_200K`); production traffic validation is
`PENDING_VPS`, and URL-ML promotion stays `SHADOW_OBSERVER_ONLY` until
external evidence arrives. Canonical status:
[release-manifest-r5.md](docs/deployment/release-manifest-r5.md) ·
[production-completion-checklist.md](docs/production-completion-checklist.md).

## Contributing

Issues and pull requests are welcome. Please read the
[PR template](.github/pull_request_template.md) (includes a cost-sensitive
checklist) and run `mise run ci` before pushing — CI covers lint, tests,
React typecheck, Playwright end-to-end tests, `gosec`, `govulncheck`, and
Docker builds. Every claim in a PR needs evidence: tests run, numbers
measured, docs updated.

## Credits

Tools and organizations that supported development:

- [Codex](https://github.com/codex)
- [OpenCode](https://opencode.ai)
- [Kiro](https://kiro.dev)
- [Google Antigravity](https://github.com/google-antigravity)
- [Z.ai](https://github.com/zai-org)
- [dependabot\[bot\]](https://github.com/apps/dependabot) — automated dependency updates

## License

MIT — see [LICENSE](LICENSE).
