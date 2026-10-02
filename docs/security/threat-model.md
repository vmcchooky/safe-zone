# Safe Zone Threat Model

Status: Draft  
Date: 2026-05-26

This document is the first formal threat model for Safe Zone. It is intentionally practical: it focuses on the current repository shape, the single-VPS production baseline, and the risks that matter before a public production release.

It complements:

- `docs/production-completion-checklist.md`
- `docs/deployment/release-manifest-r5.md`
- `docs/adr/0001-fail-open-runtime-behavior.md`
- `docs/runbooks/credential-rotation.md`

(Historical reference `docs/analysis/safe-zone-project-assessment.md` no
longer exists in the tree; assessment history lives under `docs/specs/`.)

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
- Forwarded-client headers are only trusted from peers listed in `SAFE_ZONE_TRUSTED_PROXIES`. The default is loopback-only; the Compose stack adds the Docker bridge network because Caddy reaches the services over it. A client on the LAN can otherwise choose its own rate-limit key by setting `X-Forwarded-For`. See §6a for the sizing and the accepted residual.
- Rate-limiter key maps are capped (`SAFE_ZONE_RATELIMIT_MAX_KEYS`, default 50 000 per limiter) and trimmed by an intrusive LRU split into keys holding a token and keys currently throttled. A throttled key is the **last** thing eviction spends, which is what stops a client being rate limited from losing its bucket when unrelated traffic arrives.

  This is **not** flood resistance. The "prefer keys seen once" first pass is LRU-blind among one-shot keys, and an attacker who visits each decoy twice empties that counter of its own keys, so the pass then removes only real one-shot keys and keeps the decoys — the opposite of its intent. Measured at a cap of 5 000 with 2 500 real keys interleaved with 2 500 decoys: at one visit per decoy 250 of 2 500 real keys survive, at two visits none do, and filling the key space either way costs about 6 ms. Real resistance would need a signal the client cannot forge, such as aggregating by prefix rather than by full address.

## 6a. Authenticated Surface

Changed 2026-09-29. This reverses the decision recorded in
`docs/research/backend/observability-hardening.md` to leave `/metrics`
public, which was made to avoid breaking unauthenticated Grafana scrapes.

| Endpoint | Auth | Note |
| --- | --- | --- |
| `GET /metrics` on `core-api` | Admin only (bearer key or admin session) | Exposes the per-endpoint request summary (method, path, status, counts, bytes, latency). Any authenticated caller — including the read-only `guest` role — could otherwise fingerprint the API surface and read 401/403/429 rates as a brute-force progress signal, so `RequireAdminFunc` is required rather than `RequireAuthFunc`. |
| `POST /v1/auth/logout` | Bearer key, or admin session plus same-origin `Origin`/`Referer` | Revokes the persisted session row, so it is a state-changing cookie route and now runs the CSRF gate. **Breaking change:** an anonymous POST now returns 401 instead of 200. |
| `/v1/telemetry/recent` | Any authenticated role | Per-client `client_ip` and `client_id` are returned to administrators only; every other role receives those fields omitted, and `redacted` reports the policy applied (`true` for non-admin, including on an empty page). |
| `admin_session` cookie | `Secure` from configuration | `X-Forwarded-Proto` is only honoured from a peer inside `SAFE_ZONE_TRUSTED_PROXIES`; otherwise the `Secure` attribute follows `SAFE_ZONE_FORCE_SECURE_COOKIES` (default: on in production). A client-supplied header from an untrusted peer can neither set nor clear it, and an ignored header is logged once so a deployment that forgets to declare its TLS terminator is diagnosable. |
| `dns-resolver` `/` and `/metrics` | none | The resolver has no auth surface; it is loopback-only in production. It shares `ratelimit.ClientIP` for DoH limiter keys, so it inherits that decision. |

### Known exceptions to the outbound address guard

`netguard` covers every outbound fetch: threat feeds, OSINT, WHOIS and TLS
enrichment, alert webhooks, whitelist imports, and the DoH upstream client.
Two paths are deliberately outside it, and the reason is recorded so a later
change does not "fix" them by accident:

- **AI provider clients** (`internal/ai`). The Gemini base URL is operator
  configuration rather than anything derived from user input, and the connection
  is TLS with a pinned minimum version to a named public host, so a substituted
  endpoint fails the handshake instead of receiving the API key. Wrapping it
  would mean a second policy switch for operators who front Gemini with a
  private proxy. The Ollama client targets a loopback daemon by design — it is
  the reason local inference works — and posts no secret.
- **RFC 5737 documentation ranges** (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`) are not blocked. They are not routable, so a fetch to one
  fails on its own, and blocking them breaks test fixtures. What the omission
  does add is refusing to use a documentation address as an SSRF target inside a
  test harness.

Two behaviours worth stating because they are deliberate rather than
accidental:

- A **cancelled request context makes `Whitelist.IsAllowed` report "not
  whitelisted"**. The result is discarded by the request that cancelled, and the
  direction is the safe one: the domain is evaluated normally (and can be
  blocked) rather than short-circuited to `SAFE`.
- A **custom `http.RoundTripper` passed to `netguard.NewHTTPClient` is refused**
  (`ErrUnguardableTransport`) rather than wrapped. The address check works by
  rewriting `DialContext`; a custom base controls its own connections, including
  whether it proxies, so wrapping it would look protected while not being so.
  Every caller in the tree passes `nil` or an `*http.Transport`.

### Whitelist reads on the DNS hot path

The whitelist is consulted for every analysis. It is now held entirely in RAM: a
Bloom filter answers negatives in constant time, and a sorted, deduplicated slice
of every whitelisted domain answers positives exactly, by binary search. **Lookups
never touch the database.**

They used to. A positive — a domain genuinely on the list, plus the 1% false
positives — was verified against SQLite on every request. The store is a single
connection, so an operator-triggered reload of a large whitelist held it for
seconds. Measured against a 400k-row reload:

| | worst lookup | verdict flipped to "not whitelisted" |
|---|---|---|
| Verifying each hit in SQLite | **3s** (the whole DoT budget) | 1 of 751 |
| Bounding each read to 250ms | 251ms | 16 of 751 |
| RAM index | **553µs** | **0 of 974** |

A flipped verdict is not cosmetic: the domain then went through the rest of the
pipeline, where any layer can block it. It was also unobservable — no counter,
no log, nothing in the status output.

Bounding the read was tried and rejected as the fix: it capped the worst case but
raised the flipped count sevenfold, trading an unbounded stall for more silent
wrong answers. The RAM index removes the failure mode instead of bounding it.

Two consequences to know:

- **Lookups survive a store outage.** With the database closed, a whitelisted
  domain still resolves as whitelisted. That is the property that makes the
  allow list dependable rather than best-effort.
- **Memory scales with the list.** Measured on this build: **65 bytes per entry**,
  about 62 MiB for a million domains, of which the Bloom filter is only 1.1 MiB
  and the rest is the domain text plus its slice. `whitelist.exact_index_entries`
  in the agent metrics is the number to watch when choosing a source. A cheaper
  option was considered and rejected: a sorted array of 64-bit hashes is about 8
  bytes per entry, but a collision silently reports "not whitelisted",
  reintroducing exactly the failure this change removed.

### Rate-limiter key cap

`SAFE_ZONE_RATELIMIT_MAX_KEYS` (default 50 000) bounds how many distinct keys
each limiter tracks. It is a **memory ceiling, not a brute-force defence**:

- The key is the full client IP. A client arriving from a routed IPv6 prefix can
  present 2^64 distinct addresses, so reaching the cap is easy for an
  IPv6-only client. What stops login brute force is the login limiter's rate
  (8 rpm) and credential policy, not the cap.
- Measured cost: ~179 bytes per tracked key against ~83 for a plain map entry,
  so at full capacity the 11 configured limiters hold roughly 94 MiB of key
  state. Lowering the cap lowers that proportionally.
- The trim is 90% of the cap. A very small cap therefore rewrites nearly the
  whole map on every new key, which resets rate limits for live clients; keep it
  in the thousands unless measuring.

Eviction splits keys into two intrusive LRU lists: those holding a token, and
those currently throttled. A throttled key is the last thing spent, so a client
being rate limited does not lose its bucket when unrelated traffic arrives. This
depends on the invariant that a key is filed as blocked exactly when its next
request would be denied; a key that has just spent its last token must be
protected too, or it is the cheapest thing for the eviction sweep to take.

### Forwarded-header trust

`SAFE_ZONE_TRUSTED_PROXIES` is a trust boundary and is sized deliberately:

- Default (binary): loopback only.
- Compose: loopback plus `172.16.0.0/12`, which contains every default
  Docker address pool. `10/8` and `192.168/16` are deliberately **not** listed:
  they are not used by default, and listing them let any host in those ranges
  choose its own rate-limit key.
- A malformed entry fails closed to loopback with a warning. A prefix at or
  wider than a `/8` (IPv4) or `/16` (IPv6) is accepted but warned about,
  because it effectively disables the filtering.

**Accepted residual:** a client whose own source address falls *inside* a
trusted range is indistinguishable from a proxy hop, so the walk skips it and
accepts whatever the client placed to its left. No header heuristic can
separate the two cases. The mitigation is the trust list: prefer a `/32` for
the proxy over a subnet. The behaviour is pinned by
`TestClientInsideTrustedRangeCanStillForge` in `internal/ratelimit` so the
property cannot change silently.

`Authorization: Bearer ` with an empty token, against an empty configured
`SAFE_ZONE_ADMIN_API_KEY`, is rejected. Both auth paths share one credential
comparison so they cannot disagree; `internal/api/handlers/auth_middleware_test.go`
pins the behaviour.

## 7. Release-Blocking Risks

These items block a public production release until they are closed or explicitly downgraded by an informed review.

| ID | Risk | Why it blocks release | Closure needed |
| --- | --- | --- | --- |
| RB-1 | Public-edge exposure is not yet verified on the target VPS. | A misconfigured firewall, security group, or Compose binding could expose internal admin or service ports, or publish DoH/DoT incorrectly. | Capture and retain real execution records for port checks, firewall validation, DoH through Caddy, and DoT on `853`. Evidence collected 2026-09-20 (`docs/deployment/edge-verification-2026-09-20.md` + `scripts/ops/check-production-ports.sh`); closure still needs Azure NSG audit + informed owner review. |
| RB-2 | Backup confidentiality and recoverability are not yet proven. | Current backup flow snapshots sensitive config and can copy it offsite. SHA-256 manifests and GPG bundles are implemented (`scripts/ops/safe-zone.sh`) and a restore drill is documented (`docs/runbooks/restore-drill.md`); a clean-machine drill with RTO/RPO evidence is still missing. | Complete a clean-machine restore drill with RTO/RPO evidence. |
| RB-3 | ~~Production currently continues when SQLite persistence initialization fails.~~ **CLOSED 2026-09-18 (PR #65):** production now fails startup when SQLite init fails (`internal/risk/env.go`); non-prod keeps warn-and-continue for local dev. | SQLite stores overrides, groups, mappings, and telemetry. Starting in a degraded mode can silently remove security control-plane state and auditability. | Done — fail startup in production. |
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
| Repudiation | Telemetry and override history improve traceability. | Startup fails fast in production if SQLite initialization fails (RB-3 closed 2026-09-18); non-prod keeps warn-and-continue. | Closed (`RB-3`) |
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
| SQLite corruption or deletion | Host compromise, disk failure, unsafe restore, file tampering | Loss of overrides, groups, mappings, telemetry, and admin intent | WAL mode, foreign keys, backups, store APIs | Production refuses to start without the DB (RB-3 closed); non-prod still tolerates init failure |
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
