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

### 8.2 DoH and DoT Request Handling

| Threat | Current mitigation | Residual risk | Status |
| --- | --- | --- | --- |
| Spoofing | DoH stays on HTTPS and DoT uses TLS; request handling is shared through the `risk.Service` policy layer. | Public DoT trust still depends on production certificate discipline. | `RB-4` |
| Tampering | DNS policy is centralized; block strategies are explicit (`sinkhole`, `nxdomain`, `refused`, `nullip`). | Mis-set block strategy can weaken operator intent or client UX. | Medium |
| Repudiation | Request IDs and structured logs exist across API and resolver flows. | DNS client identity is often IP-based only; attribution is imperfect without external network logs. | Accepted MVP limitation |
| Information disclosure | Resolver avoids exposing internal admin APIs on DNS paths. | Query metadata is still visible to the operator and any reverse proxy in front of DoH. | Accepted MVP risk |
| Denial of service | Rate limiting, request size caps, timeouts, and fail-open dependency handling are present. | DNS amplification and query-flood resistance still need target-environment evidence under public load. | Medium |
| Elevation of privilege | Resolver does not expose privileged mutation paths. | If client-to-policy mappings are misconfigured, some clients could receive the wrong policy group. | Medium |

### 8.3 Admin Dashboard and Control Plane APIs

| Threat | Current mitigation | Residual risk | Status |
| --- | --- | --- | --- |
| Spoofing | Dashboard and admin APIs require either bearer API key or signed `admin_session` cookie. | Stolen admin credentials remain high impact until rotated. | High |
| Tampering | Authenticated endpoints protect overrides, groups, mappings, telemetry access, agent triggers, and brand management. | SQLite durability and backup quality still determine whether operator intent survives incidents. | `RB-2`, `RB-3` |
| Repudiation | Structured JSON logs and request IDs exist. | There is no dedicated immutable audit log or per-admin change approval workflow. | Medium |
| Information disclosure | Cookies are `HttpOnly`; `Secure` is set on HTTPS; request bodies are size-limited. | Dashboard exposure through edge misconfiguration or backup leakage remains high impact. | High |
| Denial of service | POST/PUT/DELETE routes are rate-limited and body-capped. | Dashboard endpoints still share host resources with the analysis plane on the single-node MVP. | Accepted MVP risk |
| Elevation of privilege | Production validation rejects missing or weak admin password/API key. | Local auto-generated admin secrets are intentionally convenient and would be unsafe if reused outside local mode. | Low in prod, accepted in local |

### 8.4 Auth and Session Model

| Threat | Current mitigation | Residual risk | Status |
| --- | --- | --- | --- |
| Spoofing | Session cookies are HMAC-signed; API keys use constant-time comparisons; CSRF checks protect cookie-authenticated state-changing requests. | Credential theft, browser compromise, or leaked local secret files still bypass these checks. | High |
| Tampering | Session payload is signed; logout clears the cookie; bearer and cookie flows are explicit. | Session invalidation is coarse-grained because stateless cookies stay valid until expiry or server secret rotation. | Accepted MVP risk |
| Repudiation | Login/logout and admin API use are visible in HTTP logs. | Logs do not yet distinguish all mutation events into a dedicated audit stream with actor and diff semantics. | Medium |
| Information disclosure | `HttpOnly`, `SameSite=Lax`, and HTTPS-aware `Secure` reduce browser leakage. | Local generated secrets files and backups can still expose session material if mishandled. | Medium |
| Denial of service | Login bodies are capped and unauthenticated requests fail early. | Brute-force and credential-stuffing resistance depends mostly on rate limiting and operator monitoring, not MFA. | Medium |
| Elevation of privilege | CSRF is enforced for cookie-authenticated mutations; bearer auth bypasses CSRF by design. | There is no MFA, no IP allowlist, and no per-role separation in the current admin model. | Accepted MVP risk |

### 8.5 Redis Cache and Threat-Feed State

| Threat | Current mitigation | Residual risk | Status |
| --- | --- | --- | --- |
| Spoofing / tampering | Redis credentials are configurable; feed writes can use replace-with-staging behavior. | A compromised Redis instance could poison cache or threat-feed state. | High |
| Repudiation | Sync metadata and warnings exist. | Redis changes are not an immutable audit log. | Medium |
| Information disclosure | Intended as an internal dependency. | Exposure depends on deployment hygiene and firewall correctness. | Tied to `RB-1` |
| Denial of service | System is designed to fail open when Redis is unavailable. | Detection quality and feed-backed blocking degrade during Redis outage. | Accepted MVP risk |
| Elevation of privilege | Redis is not the primary auth system. | Cache poisoning can still influence behavior indirectly. | Medium |

### 8.6 SQLite Persistence

| Threat | Current mitigation | Residual risk | Status |
| --- | --- | --- | --- |
| Tampering | Parameterized SQL, WAL mode, `busy_timeout`, and foreign keys are enabled. | Host compromise or file corruption can still alter persistent operator state. | Medium |
| Repudiation | Telemetry and override history improve traceability. | Startup currently continues if SQLite initialization fails, reducing auditability silently. | `RB-3` |
| Information disclosure | DB stays local to the deployment by default. | Backup snapshots can copy the DB without encryption requirements. | Tied to `RB-2` |
| Denial of service | Query limits and SQLite pragmas reduce abuse risk. | Disk exhaustion or DB corruption scenarios still need restore evidence. | Medium |

### 8.7 Threat-Feed Ingestion and Scheduled Feed Sync

| Threat | Current mitigation | Residual risk | Status |
| --- | --- | --- | --- |
| Spoofing | Operators configure feed sources explicitly; parser normalization rejects malformed entries. | A malicious but syntactically valid source can still feed operator-approved bad data into Redis. | High |
| Tampering | Parser drift detection, duplicate filtering, normalization, and revision-based cache invalidation exist. | There is no signature verification, source pinning, or content attestation for feed payloads. | Medium |
| Repudiation | Feed sync records counts, invalid rows, drift warnings, and completion metadata. | Source provenance remains procedural and log-based rather than strongly attested. | Medium |
| Information disclosure | Local file access uses safe file-root restrictions; outbound feed fetches can be time-bounded. | Pulling remote feeds reveals operator IP, sync timing, and potentially interest in specific providers. | Accepted MVP risk |
| Denial of service | Max byte limits, timeouts, and fail-open handling reduce blast radius. | Large or slow upstream feeds can still delay freshness and consume resources during sync windows. | Accepted MVP risk |
| Elevation of privilege | Feed sync writes domains, not arbitrary code or SQL. | Poisoned feed content can still escalate from data-layer influence into unwanted blocking behavior. | Medium |

### 8.8 OSINT and External HTTP Evidence Fetching

| Threat | Current mitigation | Residual risk | Status |
| --- | --- | --- | --- |
| Spoofing | OSINT sources are validated against trusted domains and blocked private IPs by default. | Feed sync accepts operator-supplied HTTP(S) sources; bad source selection is still a supply-chain risk. | Medium |
| Tampering | Feed parser drift detection and revision-based cache invalidation exist. | Malicious or malformed upstream content can still create false positives or stale protection until operators respond. | Medium |
| Repudiation | Feed sync success/failure metadata is recorded. | Source provenance review is still procedural rather than cryptographically enforced. | Medium |
| Information disclosure | OSINT fetches limit redirects and bytes; feed file access is constrained with `safefile.OpenWithin` for local paths. | Operator-configured remote sources still reveal outbound interest to external services. | Low |
| Denial of service | Timeouts and byte limits exist. | Upstream slowness or drift can degrade protection quality. | Accepted MVP risk |
| Elevation of privilege | OSINT blocks private-address lookups by default, reducing SSRF-style abuse. | Any future setting that allows private sources must stay off by default and be tightly reviewed. | Low currently |

### 8.9 Enrichment, WHOIS/TLS, and AI Providers

| Threat | Current mitigation | Residual risk | Status |
| --- | --- | --- | --- |
| Spoofing / tampering | TLS minimum version is set on outbound AI/TLS paths; provider URLs are configurable; background enrichment updates cache instead of blocking the initial request path. | Operator misconfiguration of provider endpoints could still redirect traffic or produce misleading enrichment data. | Medium |
| Information disclosure | AI and alerting secrets support `*_FILE` loading. | Domain analysis data may be sent to third-party services when integrations are enabled. | Accepted with operator awareness |
| Denial of service | Enrichment is time-bounded and backgrounded; service fails open when optional providers fail. | Attackers can still manufacture many suspicious domains to increase outbound lookups and queue pressure. | Medium |
| Elevation of privilege | AI and enrichment can influence classification but do not directly grant admin access. | Poor provider behavior can still skew allow/block outcomes on ambiguous domains. | Accepted MVP risk |

### 8.10 Secrets, Deployment Config, and Backups

| Threat | Current mitigation | Residual risk | Status |
| --- | --- | --- | --- |
| Spoofing | Production requires explicit admin secrets. | Secret rotation still depends on operator discipline. | Medium |
| Tampering | Secret files can live under `./ops/secrets`; runbooks exist for rotation. | There is no signed configuration or release provenance flow yet. | Medium |
| Information disclosure | Production no longer prints generated admin secrets to logs. | Backup snapshots and optional offsite copies can contain sensitive material without mandatory encryption guidance. | `RB-2` |
| Denial of service | Backup and restore scripts exist. | Restore capability is unproven until drilled. | `RB-2` |
| Elevation of privilege | Limiting secret exposure reduces blast radius. | If `.env`, secret files, or backups leak, attackers gain direct admin and provider access. | High |

## 9. Abuse Cases

The following abuse cases should be assumed possible and reviewed before each public production release:

| Abuse case | Entry point | Likely impact | Current mitigation | Residual risk |
| --- | --- | --- | --- | --- |
| Malicious feed input from a compromised or operator-misconfigured source | Feed sync HTTP(S) source or local file source | False positives at scale, poisoning Redis threat-feed set, unwanted blocking | Source allowlisting by operator, parser normalization, drift warnings, revision-based cache invalidation | No cryptographic source verification; supply-chain trust remains procedural |
| Admin API key leakage | `.env`, secret files, terminal history, backups, screenshots, logs | Full control-plane takeover, override injection, telemetry access, agent triggering | Strong secrets required in production, `*_FILE` support, constant-time comparisons, runbooks for rotation | No MFA or role separation; one key is still high blast radius |
| Session secret leakage | Secret files, local admin secrets file, backup archives | Forged `admin_session` cookies until rotation | Signed stateless cookies, `HttpOnly`, HTTPS-aware `Secure`, operator secret handling | Rotation is manual; compromise impact is immediate and broad |
| Dashboard CSRF or same-origin abuse | Authenticated browser session | Unauthorized override or group mutation through the browser | Origin/Referer validation for cookie-authenticated state-changing requests | Same-site browser compromise or XSS in any trusted origin still bypasses intent |
| DNS amplification or query-flooding | Public DoH or DoT | Resource exhaustion, edge instability, degraded resolver quality | Rate limiting, request timeouts, block strategies, shared policy service | Public target-VPS proof is still required for confidence under real traffic |
| SSRF through OSINT or enrichment fetches | Operator-configured remote source, future private-source toggle, outbound enrichment targets | Internal network probing, metadata exposure, unexpected outbound traffic | Private-address blocking by default, timeout limits, redirect and byte caps | Operator misconfiguration or future feature drift could reopen SSRF paths |
| Redis exposure or poisoning | Internal network, bad Compose binding, leaked Redis credentials | Feed tampering, cache poisoning, degraded policy correctness | Redis expected to stay internal, credentials configurable, fail-open behavior | Internal network trust is still important; Redis is not an immutable source of truth |
| SQLite corruption or deletion | Host compromise, disk failure, unsafe restore, file tampering | Loss of overrides, groups, mappings, telemetry, and admin intent | WAL mode, foreign keys, backups, store APIs | Startup currently tolerates DB init failure unless production policy changes |
| Abuse of background enrichment queue | Many suspicious domains through public APIs | Outbound connection spikes, increased CPU, delayed cache enrichment | Queueing, timeouts, in-flight deduplication, initial response path stays non-blocking | Queue pressure is still a capacity concern on the single-node MVP |
| OSINT false-warning manipulation | Compromised public warning page or weakly reviewed source | Malicious escalation of suspicious domains to blocked | Trusted-domain allowlists, private-IP blocking, cached-evidence path separation | Trust still inherits from source-domain correctness and operator review |

## 10. Mitigations and Control Priorities

Priority mitigations for the MVP release:

1. Keep public exposure narrow: only intended Caddy/DoH/DoT ports should be reachable from the internet; archive real firewall and port-check evidence.
2. Treat admin secrets and backups as high-sensitivity artifacts: use `*_FILE` secrets, restrict filesystem access, rotate on suspicion, and define backup encryption or handling rules.
3. Make feed and Redis state replaceable: prefer revision-based cache invalidation, drift detection, and the ability to resync from known sources quickly.
4. Preserve operator intent in SQLite: either require SQLite for production startup or explicitly approve degraded mode with alerts and documented exception handling.
5. Keep optional outbound integrations bounded: short timeouts, byte caps, redirect limits, private-address blocking, and queue back-pressure for enrichment.
6. Require review discipline around source changes: new feed sources, OSINT allowlists, AI endpoints, and private-source toggles should be explicit operator decisions, not ad hoc edits.
7. Keep the public request path fail-open but observable: Redis, OSINT, AI, and enrichment failures should not cause a total outage, but they must remain visible in logs, alerts, and release evidence.

## 11. Accepted MVP Risks

These risks are currently acceptable for an MVP if they stay visible and documented:

- Redis outage degrades caching and feed-backed coverage, but should not become a total outage.
- TLS/WHOIS enrichment is fail-open and may miss signals during upstream failures.
- AI enrichment is optional and may be disabled or unavailable without blocking core service.
- Background enrichment may lag behind the first request for a suspicious domain; later requests should benefit from cache once enrichment completes.
- Sinkhole block-page mode can still trigger HTTPS certificate warnings for arbitrary blocked third-party domains.
- OSINT evidence is best-effort and should influence suspicious cases, not replace deterministic controls.
- Single-admin control plane without MFA or role-based access remains an MVP tradeoff; strong secret hygiene is therefore mandatory.
- Remote feed and evidence source trust is partly procedural because the MVP does not yet enforce signed feed provenance.

## 12. Recommended Remediations

1. Close RB-1 by running and archiving real target-VPS edge checks before release.
2. Close RB-2 by defining backup secrecy rules, recording checksums, and completing a restore drill.
3. Close RB-3 by deciding whether SQLite is required for production startup and enforcing that choice in code.
4. Close RB-4 by requiring configured DoT cert/key files for any public DoT release.
5. Add a stricter admin model for post-MVP: MFA, narrower API keys, or role separation for dashboard vs automation.
6. Add stronger source provenance for feeds and operator review gates for remote-source changes.
7. Re-review this document whenever the public edge, auth model, feed pipeline, or storage model changes.

## 13. Production Go/No-Go Rule

Safe Zone should not be called production-ready while any release blocker in Section 7 remains open.
