<div align="center">
  <h1>Safe Zone</h1>
  <p><strong>Self-hosted DNS filtering for phishing and impersonation domains.</strong></p>
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

Safe Zone is an open-source, self-hosted DNS resolver and operator console. It
blocks domains that match your policy at the DNS layer, before a client connects
to the origin. It is built for operators who want to run the service on their
own infrastructure, keep policy data local, and choose which optional feeds and
enrichment providers to use.

> **Latest tagged release:** [v1.10.21](https://github.com/vmcchooky/safe-zone/releases/tag/v1.10.21) (2026-10-21)<br>
> **Production status:** release candidate; validation on a provisioned VPS is
> still pending.<br>
> **ML status:** optional and disabled by default; URL-ML remains shadow-only.
>
> The operator source of truth is the
> [production completion checklist](docs/production-completion-checklist.md).
> The [v1.10.21 release notes](https://github.com/vmcchooky/safe-zone/releases/tag/v1.10.21)
> list the evidence and the checks that remain deferred.

<a id="contents"></a>
## Choose your path

| I want to... | Start here |
|---|---|
| Run a local demo | [Quickstart](#quickstart) |
| Deploy on a VPS | [Production checklist](#production-checklist) and the [edge runbook](docs/runbooks/production-edge.md) |
| Understand data handling | [Data flow and privacy](#data-flow-and-privacy) |
| Operate the service | [Operations](#operations) |
| Check current readiness | [Project status](#project-status) |
| Contribute | [Contributing](#contributing) and the [PR template](.github/pull_request_template.md) |

<a id="features"></a>
## What it does

Safe Zone combines several layers behind one DNS policy decision:

- **Deterministic domain verdicts** — lexical scoring for typosquatting, brand
  abuse, DGA/entropy, and IDN homoglyphs, with no external dependency required
  for the base decision.
- **Live threat intelligence** — feed matches for domains that are already known
  to be malicious, plus background TLS/WHOIS enrichment that only promotes a
  verdict when there is corroborating evidence.
- **Policy-aware blocking** — sinkhole, NXDOMAIN, refused, and null-IP
  strategies, with CNAME uncloaking. Ads, trackers, and telemetry are treated as
  policy actions, not mislabeled as malware.
- **Operator controls** — a React dashboard and API for analysis, overrides,
  client groups, user reports, metrics, and feed health.

| It is designed to | It is not designed to |
|---|---|
| Filter DNS answers for clients configured to use Safe Zone. | Replace endpoint protection or inspect arbitrary HTTPS payloads. |
| Serve DoH, with optional DoT when a trusted certificate is configured. | Guarantee a normal HTTPS block page for every blocked third-party domain. |
| Combine deterministic policy with optional feeds and enrichment. | Guarantee coverage when feeds are stale, missing, or poorly configured. |
| Surface status and evidence for operators. | Promise zero false positives; every policy needs review and rollback. |

<a id="threat-intel-and-ml"></a>
### Threat intelligence and ML

- The production stack runs `feed-syncd` and requires at least one usable feed
  source. Set `SAFE_ZONE_THREAT_FEED_SOURCE` and verify freshness in
  `/v1/status`; the opt-in agent feed task can use
  `SAFE_ZONE_AGENT_FEED_PRESET=production-free` or `production-vn`. See
  [threat intelligence sources](docs/research/security/threat-intelligence-sources.md).
- Domain ML is optional and disabled by default. Shadow, canary, and enforce
  modes are gated; URL-ML remains shadow-only in this release. See the
  [Safe Zone AI plan](docs/specs/safe-zone-ai-plan.md).
- The agent engine (audit, feed sync, OSINT, alerts, allow-list refresh) is
  opt-in. Do not enable production schedules from the minimal example alone.

<details>
<summary>Test a local feed file</summary>

```bash
go run ./cmd/feed-sync -source ./feeds/local.txt -dry-run
go run ./cmd/feed-sync -source ./feeds/local.txt -redis-addr localhost:6379
```

</details>

<a id="evaluation"></a>
### Evaluation

```bash
mise run eval:decision
```

The command runs the frozen truth, contract, and false-positive guard corpora.
On the current 21-host guard set, all 21 hosts are allowed; this is a regression
check, not a population-level FPR estimate. Labels require provenance, and
`unknown` never counts toward precision, recall, or FPR. The full gate is in the
[decision engine plan](docs/research/security/decision-engine-rebuttal-plan.md).

## Quickstart

Prerequisites: Go 1.26.10+ or Docker. `mise` is optional for the full
verification suite. The commands below assume a Unix shell; Windows notes are
included where they differ.

### Docker (recommended for a first run)

```bash
git clone https://github.com/vmcchooky/safe-zone.git
cd safe-zone
cp .env.example .env
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

On Windows PowerShell, use `Copy-Item .env.example .env`; `start.bat` is the
supported local launcher. Use `curl.exe` for the `curl` examples in this README.
The development stack binds to loopback.

The dashboard is at <http://localhost:8080/app/> and DoH is at
<http://localhost:8081/dns-query>.

### Go

Run each command in a separate terminal:

```bash
# Terminal 1 — API and dashboard at http://localhost:8080/app/
go run ./cmd/core-api

# Terminal 2 — DNS policy and DoH at http://localhost:8081/dns-query
go run ./cmd/dns-resolver
```

On first start, local admin secrets are written to
`tmp/local_admin_secrets.txt`.

### Try it

Query DoH (RFC 8484) and save the binary response:

```bash
curl -s 'http://localhost:8081/dns-query?dns=EjQBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE' \
  -H 'accept: application/dns-message' \
  -o doh-response.bin
```

Inspect `doh-response.bin` with `xxd` on Linux/macOS or `Format-Hex` in
PowerShell.

Analyze a suspicious domain and inspect the policy the DNS layer will enforce:

```bash
curl "http://localhost:8080/v1/analyze?domain=secure-login-wallet-example.com"
curl "http://localhost:8081/v1/policy?domain=secure-login-wallet-example.com"
```

`/v1/status` and core-api `/metrics` require admin authentication. Locally, the
key is generated on first start. On Linux/macOS:

```bash
export SAFE_ZONE_ADMIN_API_KEY=$(grep '^SAFE_ZONE_ADMIN_API_KEY=' tmp/local_admin_secrets.txt | cut -d= -f2)
curl -H "Authorization: Bearer $SAFE_ZONE_ADMIN_API_KEY" "http://localhost:8080/v1/status"
curl -H "Authorization: Bearer $SAFE_ZONE_ADMIN_API_KEY" "http://localhost:8080/metrics"
```

<details>
<summary>Windows PowerShell: read the generated admin key</summary>

```powershell
$env:SAFE_ZONE_ADMIN_API_KEY = (Get-Content tmp/local_admin_secrets.txt |
  Where-Object { $_ -like 'SAFE_ZONE_ADMIN_API_KEY=*' }) -replace '^SAFE_ZONE_ADMIN_API_KEY=', ''
curl.exe -H "Authorization: Bearer $env:SAFE_ZONE_ADMIN_API_KEY" "http://localhost:8080/v1/status"
```

</details>

`dns-resolver` metrics are unauthenticated:

```bash
curl "http://localhost:8081/metrics"
```

With the default `sinkhole` strategy and a reachable block-page IP, HTTP
requests to a blocked domain reach the block page and its user report form.
`https://$SAFE_ZONE_PUBLIC_HOST/block?domain=...` is the canonical HTTPS
explanation page. Direct HTTPS to the blocked third-party domain may show that
domain's certificate warning first; that is a TLS limitation of non-MITM DNS
filters, not a claim that the block failed. See [Limitations](#limitations).

## Architecture

![Safe Zone edge architecture](docs/diagrams/edge-architecture.png)

`core-api` owns policy, overrides, reports, feeds, and telemetry. `dns-resolver`
evaluates policy and serves DNS, DoH, and optional DoT. SQLite is the durable
store; Redis is optional for cache and feed state. Internal ports `8080` and
`8081` stay loopback-only in production; public ports are `80`, `443`, and
optionally `853`. See the
[edge verification record (2026-09-20)](docs/deployment/edge-verification-2026-09-20.md).

<details>
<summary>Decision pipeline and scoring diagrams</summary>

| Decision pipeline | Scoring |
|---|---|
| ![Verdict pipeline](docs/diagrams/verdict-pipeline.png) | ![Scoring](docs/diagrams/scoring.png) |

</details>

Further diagrams: [deployment](docs/diagrams/deployment.png) ·
[DoH sequence](docs/diagrams/doh-sequence.png) ·
[defense layers](docs/diagrams/defense-layers.png). Interactive HTML versions
live alongside the PNGs in [`docs/diagrams/`](docs/diagrams/).

## Data flow and privacy

Safe Zone does not require a SaaS control plane, and operator data stays in your
SQLite/Redis. Some optional features make outbound requests. The table describes
the example configuration; verify your `.env` before deployment.

| Function | Default in the example | External data | Control |
|---|---|---|---|
| DNS forwarding | Public DoH pool: Cloudflare, Google, Quad9, and AdGuard (`SAFE_ZONE_UPSTREAM_DOH_URLS`) | Forwarded queries go to one of the configured upstream DoH providers. | Point to your own upstream or providers you trust. |
| Threat feeds | `feed-syncd` downloads `SAFE_ZONE_THREAT_FEED_SOURCE` (URLhaus in the example) | The feed provider sees requests from your host. | Use approved or local sources; monitor feed freshness. |
| Adblock lists | Enabled; downloads StevenBlack hosts in the example | The host-list source sees requests from your host. | Set `SAFE_ZONE_ADBLOCK_ENABLED=false` or use your own source. |
| TLS/WHOIS enrichment | Enabled (`SAFE_ZONE_ENRICH_ENABLED=true`) | Outbound connections to target hosts and WHOIS services. | Disable or restrict if outbound enrichment is not acceptable. |
| OSINT | Enabled in the example (`SAFE_ZONE_OSINT_ENABLED=true`) | May query configured OSINT sources. | Set `SAFE_ZONE_OSINT_ENABLED=false` and review sources. |
| AI/ML | ML disabled; AI provider optional (Gemini by default); agent off | If enabled, domains and context may be sent to the configured provider; Ollama can run locally. | Review `SAFE_ZONE_ML_MODE`, `SAFE_ZONE_AI_PROVIDER`, and `SAFE_ZONE_AGENT_ENABLED`. |
| Operator data | SQLite/Redis on your host | No external telemetry by default; backups are operator-controlled. | Set retention and backup policy. |

These defaults mean that "no data leaves the VPS" is not accurate. Review the
table and disable or replace any provider you do not want to use. The full list
of settings is in [`.env.example`](.env.example).

<a id="deployment"></a>
## Production checklist

Use this as a starting point; the
[pre-release checklist](docs/runbooks/pre-release-checklist.md) and
[release gate](docs/runbooks/release-gate.md) are authoritative.

- [ ] Set `SAFE_ZONE_ENV=production`. The production Compose override pins it.
- [ ] Configure at least one feed source, keep `feed-syncd` running, and verify
      feed freshness in `/v1/status`. Production guards refuse a deployment with
      no usable feed path.
- [ ] Set strong admin secrets through `*_FILE`; do not ship development values.
- [ ] Set `SAFE_ZONE_WHITELIST_PATH` to the curated allow-list, or explicitly
      choose the documented DB-only mode. A configured path that cannot load is
      fatal in production.
- [ ] Leave `SAFE_ZONE_AGENT_WHITELIST_ENABLED=false` until the allow-list
      import, backup, and rollback drill has passed.
- [ ] Choose a block strategy and set a valid IPv4 `SAFE_ZONE_BLOCK_PAGE_IP` for
      sinkhole mode. Smoke-test the strategy you choose.
- [ ] DoT is enabled by default. Install a trusted DoT certificate/key, or set
      `SAFE_ZONE_DNS_DOT_ENABLED=false` if DoT is not used. A production start
      with DoT enabled and no usable certificate/key fails.
- [ ] Confirm `/readyz` is healthy and review `/v1/status` for SQLite, Redis,
      allow-list, and feed state. SQLite is mandatory; a configured allow-list
      that fails to load is fatal in production. Other optional dependencies may
      be reported as degraded.
- [ ] Run the backup/restore drill, external DoH/DoT/block-page smoke tests, and
      performance proof before exposing the service publicly.
- [ ] Review [Data flow and privacy](#data-flow-and-privacy) and approve or
      disable every external provider.

Deploy the production stack:

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d --build
```

Full edge setup (firewall, DoT certificates, DuckDNS, cron):
[production-edge.md](docs/runbooks/production-edge.md). Reference sizing, not a
price guarantee: [Safe Zone OPEX estimate](docs/deployment/Safe_Zone_OPEX_Estimate.md).

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SAFE_ZONE_ENV` | `local` | Set `production` to require strong admin secrets and SQLite. |
| `SAFE_ZONE_REDIS_ADDR` | unset | Enables Redis cache and feed state, for example `localhost:6379`. |
| `SAFE_ZONE_PUBLIC_HOST` | `safezone.example.com` in the example | Public hostname for Caddy TLS and DoH. |
| `SAFE_ZONE_ADMIN_PASSWORD` / `SAFE_ZONE_ADMIN_API_KEY` | generated locally | Required in production, or provide a `*_FILE` path. |
| `SAFE_ZONE_WHITELIST_PATH` | empty (DB-only mode) | Optional allow-list seed; a configured but unreadable path is fatal in production. |
| `SAFE_ZONE_THREAT_FEED_SOURCE` | URLhaus in `.env.example` | Feed source(s) for `feed-syncd`; comma-separated for several. |
| `SAFE_ZONE_DNS_BLOCK_STRATEGY` | `sinkhole` | `sinkhole`, `nxdomain`, `refused`, or `nullip`. |
| `SAFE_ZONE_BLOCK_PAGE_IP` | `127.0.0.1` | Public IPv4 for sinkhole block pages; validated at startup. |
| `SAFE_ZONE_DNS_DOT_ENABLED` | `true` | DoT listener; production needs a trusted cert/key, or set `false`. |
| `SAFE_ZONE_ML_MODE` | `disabled` | Optional ML mode; URL-ML remains shadow-only. |
| `SAFE_ZONE_TELEMETRY_WRITE_PERCENT` | `100` local; `5` in the production Compose file | Telemetry write sampling. |
| `SAFE_ZONE_TRUSTED_PROXIES` | loopback | CIDRs allowed to set forwarded headers; Compose adds the Docker bridge. |

The full reference, defaults, and comments live in [`.env.example`](.env.example).
Secrets accept `VAR_FILE=./ops/secrets/name`; see
[ops/secrets/README.md](ops/secrets/README.md). Administrators can tune lexical
scoring without a restart via `GET/PUT /v1/config/analysis` (revisioned, with
multi-node propagation).

## Operations

Day-to-day helper:

```bash
pwsh ./scripts/ops/safe-zone.ps1 status
# Linux:
./scripts/ops/safe-zone.sh status
```

Available commands: `deploy`, `status`, `backup`, `restore`, `prune`, and
`feed-sync`. Use the helper when you rely on `SAFE_ZONE_SCRIPT_FEED_SYNC=0`; a
direct `docker compose up` recreates `feed-syncd`.

<a id="documentation-map"></a>
### Documentation map

| Area | Start here |
|---|---|
| Deploy and operate | [production-edge.md](docs/runbooks/production-edge.md) · [operator-onboarding.md](docs/runbooks/operator-onboarding.md) |
| Production readiness | [production-completion-checklist.md](docs/production-completion-checklist.md) · [release-gate.md](docs/runbooks/release-gate.md) |
| Backup and restore | [restore-drill.md](docs/runbooks/restore-drill.md) · [release-rollback.md](docs/runbooks/release-rollback.md) |
| Security | [threat-model.md](docs/security/threat-model.md) · [pre-release-security-checklist.md](docs/security/pre-release-security-checklist.md) |
| Threat intelligence | [threat-intelligence-sources.md](docs/research/security/threat-intelligence-sources.md) · [feed-staleness.md](docs/runbooks/feed-staleness.md) |
| ML | [safe-zone-ai-plan.md](docs/specs/safe-zone-ai-plan.md) · [ml-canary-rollout.md](docs/runbooks/ml-canary-rollout.md) |
| Evaluation | [decision-engine-rebuttal-plan.md](docs/research/security/decision-engine-rebuttal-plan.md) |
| Release history | [Releases](https://github.com/vmcchooky/safe-zone/releases) · [round-5 manifest](docs/deployment/release-manifest-r5.md) (historical) |

## Project status

Safe Zone is a release candidate. The latest tag is
[v1.10.21](https://github.com/vmcchooky/safe-zone/releases/tag/v1.10.21)
(2026-10-21), and the tagged commit passed the release gates. Staging and
production VPS validation, including DoH/DoT/block-page smoke tests, the restore
drill, and performance proof, is still pending; the
[v1.10.21 release notes](https://github.com/vmcchooky/safe-zone/releases/tag/v1.10.21)
record these waivers.

ML is optional and disabled by default. URL-ML remains shadow-only and is not an
enforcement signal in this release.

- Operator checklist: [production-completion-checklist.md](docs/production-completion-checklist.md)
- Release gate: [release-gate.md](docs/runbooks/release-gate.md)
- Release evidence: [v1.10.21](https://github.com/vmcchooky/safe-zone/releases/tag/v1.10.21)
- Historical round-5 manifest: [release-manifest-r5.md](docs/deployment/release-manifest-r5.md) (2026-09-20; kept for history)

<a id="limitations"></a>
### Limitations

- DNS filtering only applies to clients configured to use Safe Zone; it is not
  endpoint protection.
- Safe Zone does not intercept TLS. Direct HTTPS to an arbitrary blocked
  third-party domain may show that domain's certificate warning before the block
  page is reachable.
- Protection depends on feed coverage, feed freshness, and operator policy.
  Monitor feed state rather than assuming the feed is current.
- ML is optional and off by default; it is not a substitute for policy review or
  feed monitoring.
- Startup validation is fail-closed for required production settings. Runtime
  behavior for optional dependencies may degrade or fail open depending on the
  feature, so a running resolver is not proof that feeds, enrichment, or the
  allow-list are healthy. Monitor `/v1/status` and `/readyz`.
- The Compose deployment is single-node and is not a high-availability design.
  Backups and restore drills remain the operator's responsibility.
- The 21-host false-positive guard is a regression check, not a population-level
  FPR guarantee.
- Optional external providers (upstream DoH, feeds, adblock lists, OSINT,
  TLS/WHOIS enrichment, and AI) can receive data depending on configuration.
- Staging and production VPS validation, restore, and performance drills are
  still pending; see [Project status](#project-status).

## Security

- Threat model and release blockers:
  [docs/security/threat-model.md](docs/security/threat-model.md)
- Pre-release security checklist:
  [docs/security/pre-release-security-checklist.md](docs/security/pre-release-security-checklist.md)
- Found a vulnerability? **Do not open a public issue.** Contact the maintainers
  privately via the project page:
  <https://www.quorix.io.vn/projects/safe-zone/>. Include the affected tag or
  commit, reproduction steps, and impact; do not include live secrets or customer
  data.
- Secret handling and rotation:
  [docs/runbooks/credential-rotation.md](docs/runbooks/credential-rotation.md)

## Contributing

Issues and pull requests are welcome. Please read the
[PR template](.github/pull_request_template.md) (it includes a cost-sensitive
checklist) and run `mise run ci` before pushing. CI covers Go lint, tests, race
tests, React typecheck, Playwright end-to-end tests, `gosec`, `govulncheck`, npm
audit, secret scanning, and Docker builds.

Every claim in a PR needs evidence: tests run, numbers measured, and docs
updated. Keep `README.md` and `README.vi.md` in sync.

<a id="credits"></a>
## Acknowledgements

Development and review tools used on this project:

- [Codex](https://github.com/codex)
- [OpenCode](https://opencode.ai)
- [Kiro](https://kiro.dev)
- [Google Antigravity](https://github.com/google-antigravity)
- [Z.ai](https://github.com/zai-org)
- [dependabot\[bot\]](https://github.com/apps/dependabot) — dependency updates

## License

MIT — see [LICENSE](LICENSE).
