# Safe Zone Threat Model

Status: Draft  
Date: 2026-05-26

This document is the first formal threat model for Safe Zone. It is intentionally practical: it focuses on the current repository shape, the single-VPS production baseline, and the risks that matter before a public production release.

It complements:

- `docs/analysis/safe-zone-project-assessment.md`
- `docs/production-completion-checklist.md`
- `docs/adr/0001-fail-open-runtime-behavior.md`
- `docs/runbooks/credential-rotation.md`

## 1. Scope

In scope:

- Public edge exposure through Caddy, HTTPS, DoH, and DoT
- Admin dashboard and authenticated control-plane APIs
- Core risk analysis service, including Redis cache and SQLite-backed persistence
- Threat-feed ingestion and scheduled sync
- Optional enrichment and provider integrations: TLS, WHOIS, OSINT, AI providers
- Secrets handling, deployment configuration, and backups

Out of scope for this draft:

- Multi-node or HA deployment patterns
- End-user device security
- Full privacy or retention policy analysis
- Third-party provider internals

## 2. Security Goals

Safe Zone should:

1. Keep the public attack surface narrow and intentional.
2. Prevent unauthorized use of admin APIs and dashboard actions.
3. Preserve the integrity of block/allow policy decisions.
4. Avoid turning optional dependency failures into total service outages.
5. Protect secrets and backup data from accidental exposure.
6. Make compromise or misconfiguration visible to operators quickly.

## 3. System Summary

At a high level, Safe Zone exposes a public DNS protection surface and an admin control plane:

- Caddy fronts HTTPS traffic and routes DoH and dashboard/API requests.
- `dns-resolver` serves DNS queries and optional DoT.
- `core-api` serves analysis APIs, dashboard UI, auth, telemetry, and agent triggers.
- Redis is used for threat-feed storage, caches, and recent activity.
- SQLite stores telemetry, overrides, mappings, groups, and related operator state.
- Background jobs fetch threat feeds and optional public-warning evidence.
- Backup scripts snapshot Redis, SQLite, `.env`-derived state, and selected config.

## 4. Assets

Primary assets:

- Admin credentials and API keys
- Session signing secret
- Threat-feed data and feed freshness metadata
- Local overrides, group overrides, client mappings, and whitelist state
- Telemetry and recent analysis history
- AI, alerting, and DNS-provider secrets
- Backup archives and offsite copies
- Public trust in DNS blocking behavior and admin actions

## 5. Trust Boundaries

1. Internet -> Caddy / public ports
2. Caddy -> `core-api`
3. DNS clients -> `dns-resolver`
4. `core-api` / `dns-resolver` -> Redis
5. `core-api` -> SQLite
6. Services -> external HTTP/TLS providers (feeds, OSINT, AI, WHOIS/TLS targets)
7. Host filesystem / secrets store -> running containers and processes
8. Local backup directory -> optional offsite backup target

## 6. Key Assumptions

- Production is expected to run with `SAFE_ZONE_ENV=production`.
- Public HTTP/HTTPS entry should go through Caddy only.
- Internal ports `8080` and `8081` are intended to stay loopback-only in production.
- Admin credentials are operator-managed and should come from env vars or `*_FILE` secrets.
- Redis, AI, TLS/WHOIS enrichment, and OSINT are optional dependencies from an availability perspective.
- SQLite-backed persistence is operationally important because it stores admin intent and audit-relevant history.

## 7. Release-Blocking Risks

These items block a public production release until they are closed or explicitly downgraded by an informed review.

| ID | Risk | Why it blocks release | Closure needed |
| --- | --- | --- | --- |
| RB-1 | Public-edge exposure is not yet verified on the target VPS. | A misconfigured firewall, security group, or Compose binding could expose internal admin or service ports, or publish DoH/DoT incorrectly. | Capture and retain real execution records for port checks, firewall validation, DoH through Caddy, and DoT on `853`. |
| RB-2 | Backup confidentiality and recoverability are not yet proven. | Current backup flow snapshots sensitive config and can copy it offsite, but there is no documented encryption requirement, checksum record, or clean restore drill. | Add backup secrets handling guidance or encryption, record checksums, and complete a clean-machine restore drill with RTO/RPO evidence. |
| RB-3 | Production currently continues when SQLite persistence initialization fails. | SQLite stores overrides, groups, mappings, and telemetry. Starting in a degraded mode can silently remove security control-plane state and auditability. | Either fail startup in production when SQLite is unavailable, or define an explicit degraded-mode policy with hard release approval and visible alerts. |
| RB-4 | Public DoT is unsafe to release if it still relies on the self-signed fallback certificate path. | Clients cannot establish trusted DoT to a public service with a temporary self-signed cert; this also increases misconfiguration risk at the edge. | For any public DoT release, require configured certificate files and verified handshake evidence. |

Notes:

- RB-3 and RB-4 are conditional on production configuration, but they should be treated as blockers whenever those features are part of the release surface.
- This document itself removes the "missing threat model" gap, but it still needs review before production sign-off.

## 8. STRIDE Threat Review

### 8.1 Public Edge: Caddy, HTTPS, DoH, DoT

| Threat | Current mitigation | Residual risk | Status |
| --- | --- | --- | --- |
| Spoofing | HTTPS and DoT TLS paths exist; DoT can use configured cert/key files. | Public DoT trust fails if production falls back to a generated self-signed certificate. | `RB-4` |
| Tampering | Intended production setup keeps internal ports loopback-only and uses Caddy as the public HTTP edge. | Real host/firewall drift is still possible until verified on the target environment. | `RB-1` |
| Repudiation | Structured logs and request IDs exist. | Environment proof and log review process are still manual. | Medium |
| Information disclosure | Production Compose and docs aim to avoid exposing `8080`/`8081` publicly. | A single binding or firewall mistake can expose dashboard/API internals. | `RB-1` |
| Denial of service | Rate limiting and timeouts exist for HTTP and DoT paths. | Real internet traffic patterns and amplification resistance still need public-environment validation. | Medium |
| Elevation of privilege | Narrow edge routing limits what reaches the control plane. | Misrouted public traffic could still expand access if the edge is misconfigured. | `RB-1` |

### 8.2 Admin Dashboard and Control Plane APIs

| Threat | Current mitigation | Residual risk | Status |
| --- | --- | --- | --- |
| Spoofing | Admin API key or signed `admin_session` cookie required; cookie uses HMAC-SHA256. | Stolen admin credentials remain high impact. | High |
| Tampering | Authenticated endpoints protect override, mapping, group, and agent actions. | Loss of SQLite persistence can undermine admin intent durability. | `RB-3` |
| Repudiation | Structured logs and request IDs are present. | Review workflow for admin actions is still lightweight. | Medium |
| Information disclosure | Cookies are `HttpOnly`; `Secure` is enabled on HTTPS requests; secrets can come from `*_FILE`. | A public edge exposure or backup leak would expose high-value admin material. | High |
| Denial of service | Request size caps and rate limiting exist across major POST/PUT routes. | Dashboard manual QA and sustained public load evidence are incomplete. | Medium |
| Elevation of privilege | Production rejects missing or weak admin password/API key. | Local mode still generates temporary admin secrets by design; safe for local use, not for production. | Low in prod, accepted in local |

### 8.3 Redis Cache and Threat-Feed State

| Threat | Current mitigation | Residual risk | Status |
| --- | --- | --- | --- |
| Spoofing / tampering | Redis credentials are configurable; feed writes can use replace-with-staging behavior. | A compromised Redis instance could poison cache or threat-feed state. | High |
| Repudiation | Sync metadata and warnings exist. | Redis changes are not an immutable audit log. | Medium |
| Information disclosure | Intended as an internal dependency. | Exposure depends on deployment hygiene and firewall correctness. | Tied to `RB-1` |
| Denial of service | System is designed to fail open when Redis is unavailable. | Detection quality and feed-backed blocking degrade during Redis outage. | Accepted MVP risk |
| Elevation of privilege | Redis is not the primary auth system. | Cache poisoning can still influence behavior indirectly. | Medium |

### 8.4 SQLite Persistence

| Threat | Current mitigation | Residual risk | Status |
| --- | --- | --- | --- |
| Tampering | Parameterized SQL, WAL mode, `busy_timeout`, and foreign keys are enabled. | Host compromise or file corruption can still alter persistent operator state. | Medium |
| Repudiation | Telemetry and override history improve traceability. | Startup currently continues if SQLite initialization fails, reducing auditability silently. | `RB-3` |
| Information disclosure | DB stays local to the deployment by default. | Backup snapshots can copy the DB without encryption requirements. | Tied to `RB-2` |
| Denial of service | Query limits and SQLite pragmas reduce abuse risk. | Disk exhaustion or DB corruption scenarios still need restore evidence. | Medium |

### 8.5 Threat-Feed and OSINT Ingestion

| Threat | Current mitigation | Residual risk | Status |
| --- | --- | --- | --- |
| Spoofing | OSINT sources are validated against trusted domains and blocked private IPs by default. | Feed sync accepts operator-supplied HTTP(S) sources; bad source selection is still a supply-chain risk. | Medium |
| Tampering | Feed parser drift detection and revision-based cache invalidation exist. | Malicious or malformed upstream content can still create false positives or stale protection until operators respond. | Medium |
| Repudiation | Feed sync success/failure metadata is recorded. | Source provenance review is still procedural rather than cryptographically enforced. | Medium |
| Information disclosure | OSINT fetches limit redirects and bytes; feed file access is constrained with `safefile.OpenWithin` for local paths. | Operator-configured remote sources still reveal outbound interest to external services. | Low |
| Denial of service | Timeouts and byte limits exist. | Upstream slowness or drift can degrade protection quality. | Accepted MVP risk |
| Elevation of privilege | OSINT blocks private-address lookups by default, reducing SSRF-style abuse. | Any future setting that allows private sources must stay off by default and be tightly reviewed. | Low currently |

### 8.6 Enrichment and AI Providers

| Threat | Current mitigation | Residual risk | Status |
| --- | --- | --- | --- |
| Spoofing / tampering | TLS minimum version is set on outbound AI/TLS paths; provider URLs are configurable. | Operator misconfiguration of provider endpoints could still redirect data or degrade trust. | Medium |
| Information disclosure | AI and alerting secrets support `*_FILE` loading. | Domain analysis data may be sent to third-party providers when those integrations are enabled. | Accepted with operator awareness |
| Denial of service | Timeouts are short and the service fails open when optional enrichment fails. | Attackers can still trigger slower analysis paths for suspicious domains. | Medium |
| Elevation of privilege | AI is not the sole decision engine. | Poor provider behavior should not become an automatic bypass, but can influence classification quality. | Accepted MVP risk |

### 8.7 Secrets, Deployment Config, and Backups

| Threat | Current mitigation | Residual risk | Status |
| --- | --- | --- | --- |
| Spoofing | Production requires explicit admin secrets. | Secret rotation still depends on operator discipline. | Medium |
| Tampering | Secret files can live under `./ops/secrets`; runbooks exist for rotation. | There is no signed configuration or release provenance flow yet. | Medium |
| Information disclosure | Production no longer prints generated admin secrets to logs. | Backup snapshots and optional offsite copies can contain sensitive material without mandatory encryption guidance. | `RB-2` |
| Denial of service | Backup and restore scripts exist. | Restore capability is unproven until drilled. | `RB-2` |
| Elevation of privilege | Limiting secret exposure reduces blast radius. | If `.env`, secret files, or backups leak, attackers gain direct admin and provider access. | High |

## 9. Accepted MVP Risks

These risks are currently acceptable for an MVP if they stay visible and documented:

- Redis outage degrades caching and feed-backed coverage, but should not become a total outage.
- TLS/WHOIS enrichment is fail-open and may miss signals during upstream failures.
- AI enrichment is optional and may be disabled or unavailable without blocking core service.
- Sinkhole block-page mode can still trigger HTTPS certificate warnings for arbitrary blocked third-party domains.
- OSINT evidence is best-effort and should influence suspicious cases, not replace deterministic controls.

## 10. Recommended Remediations

1. Close RB-1 by running and archiving real target-VPS edge checks before release.
2. Close RB-2 by defining backup secrecy rules, recording checksums, and completing a restore drill.
3. Close RB-3 by deciding whether SQLite is required for production startup and enforcing that choice in code.
4. Close RB-4 by requiring configured DoT cert/key files for any public DoT release.
5. Re-review this document whenever the public edge, auth model, feed pipeline, or storage model changes.

## 11. Production Go/No-Go Rule

Safe Zone should not be called production-ready while any release blocker in Section 7 remains open.
