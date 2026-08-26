# Safe Zone Production Completion Checklist

Date: 2026-08-08

This file is the single operational/release checklist for moving Safe Zone from the current repository state to production-ready, and then to "perfect production". For AI Engine, the only detailed technical source is `docs/specs/safe-zone-ai-plan.md`; all AI release evidence and completion status are tracked here.

> **Project status:** Safe Zone remains an actively developed open-source, nonprofit project. This checklist tracks repository capabilities and release-readiness work; it is not a claim that the overall system is complete or production-ready for every environment.

## Status Legend

- `[x]` Done in the current repo.
- `[~]` Partly done; usable foundation exists, but production requirements are not fully closed.
- `[ ]` Not done yet.
- `[!]` Needs real environment verification.

## 0. Current Baseline

These are already present and should be treated as the project foundation.

- `[x]` Go services exist: `core-api`, `dns-resolver`, `feed-sync`, and `feed-syncd`.
- `[x]` Local dashboard exists and is embedded in `core-api`.
- `[x]` Redis cache is optional and risk analysis is designed to fail open when Redis is unavailable.
- `[x]` SQLite telemetry, overrides, client groups, and group overrides exist.
- `[x]` Domain analysis includes lexical heuristics, whitelist checks, threat-feed checks, TLS inspection, WHOIS enrichment, and optional AI refinement.
- `[x]` DoH endpoint exists at `/dns-query`.
- `[x]` DoT support exists and can run on host port `853` through Compose mapping.
- `[x]` Rate limiting exists for API, DoH, DoT, telemetry, overrides, and default routes.
- `[x]` Panic recovery exists for HTTP handlers and DoT handler.
- `[x]` Dockerfile and Docker Compose exist.
- `[x]` Production edge foundation exists: Caddy, `production-edge` Compose profile, production Compose override, DuckDNS update script, production cron example.
- `[x]` OpenAPI file exists at `docs/openapi/safe-zone.yaml`.
- `[x]` Runbooks exist for production edge, Redis outage, feed staleness, and certificate renewal; AI/ML/Agent incident response is consolidated in `docs/specs/safe-zone-ai-plan.md`.
- `[x]` Local benchmarks exist for core analysis paths.
- `[x]` CI/build validation exists through GitHub Actions.

## 1. Documentation Source Of Truth

Goal: one operator-facing checklist and one canonical AI Engine technical document, without parallel plans that drift.

- `[x]` Use this file as the main production completion/release checklist.
- `[x]` Use `docs/specs/safe-zone-ai-plan.md` as the only AI Engine architecture, implementation and deployment guide.
- `[x]` Consolidate the former Custom ML plan, local provider spec, Agent workflow spec, provider ADR and provider-outage runbook into those two files.
- `[x]` Keep historical non-AI SRS/general specs as references only when they still add distinct context.
- `[x]` Keep non-AI operational decisions in `docs/adr/` when they affect future maintainers or production risk.

Rules:

1. Use this file for status, release gates, environment evidence and completion tracking.
2. Use `docs/specs/safe-zone-ai-plan.md` for every AI/ML/LLM/Agent contract and procedure.
3. General README/deployment/privacy/threat-model/OPEX docs may summarize AI, but must link to the canonical AI plan and must not define conflicting defaults.
4. Do not create another AI plan, AI task checklist, provider ADR or AI outage runbook; edit the canonical pair instead.

## 2. Public Edge And Network Safety

Goal: expose only the intended production surface to the internet.

- `[x]` Caddy reverse proxy exists.
- `[x]` HTTPS/Let's Encrypt path exists through Caddy.
- `[x]` DuckDNS update script and cron example exist.
- `[x]` DoH can be served publicly on `443` through Caddy at `/dns-query`.
- `[x]` DoT can be published on `853`.
- `[x]` Repeatable public-edge checks exist through audited `scripts/check-production-ports.sh` and `scripts/public-edge-smoke.sh`.
- `[x]` Lock down host exposure of internal ports `8080` and `8081` in production. Production Compose binds both to `127.0.0.1` only.
- `[~]` Firewall/security-group validation is scripted for SSH, `80`, `443`, and `853`; each real environment still needs its execution record captured.
- `[x]` Decide how DoT receives a trusted certificate in production. Production Compose mounts a dedicated certificate directory and the renewal runbook documents the export process.

Steps:

1. Add a production override file that keeps `8080` and `8081` loopback-only instead of publicly reachable.
2. Keep Caddy as the only public HTTP/HTTPS entrypoint.
3. Configure DoT certificate files or document a repeatable cert export/mount process.
4. Deploy to a staging VPS and run `scripts/check-production-ports.sh` plus `scripts/public-edge-smoke.sh` from outside the server.

## 3. Admin Security And Secrets

Goal: no production deployment should depend on generated secrets printed into logs.

- `[x]` Explicit admin password and API key configuration paths exist through env vars or `*_FILE` secrets.
- `[x]` Weak or missing admin password is warned about at startup in non-production mode.
- `[x]` In production mode, fail startup if `SAFE_ZONE_ADMIN_PASSWORD` is missing or weak.
- `[x]` In production mode, fail startup if `SAFE_ZONE_ADMIN_API_KEY` is missing.
- `[x]` Stop printing generated admin secrets in logs for production.
- `[x]` Add file-based or Docker secret support for admin password, API key, DuckDNS token, AI keys, and webhook URLs.
- `[x]` Add credential rotation procedure to the runbooks.

Steps:

1. Define `SAFE_ZONE_ENV=production` behavior.
2. Make missing/weak production secrets a hard startup error.
3. Support loading sensitive values from files or Docker secrets via `*_FILE`.
4. Keep a short rotation checklist for admin credentials and third-party tokens.

## 4. Threat Intelligence Pipeline

Goal: make free feed ingestion repeatable, observable, and safe when sources fail or drift.

- `[x]` Generic `feed-sync` supports local files, HTTP(S), CSV/TXT, and gzip.
- `[x]` `feed-syncd` exists for scheduled sync.
- `[x]` Agent multi-source additive feed sync exists.
- `[x]` A first-class `production-free` preset exists in code and ops helpers. It currently resolves to URLhaus plus OpenPhish community feed.
- `[x]` Feed staleness runbook exists, and stale-feed policy is enforced by code through `feed_sync` status metadata.
- `[x]` Add official production preset for free threat feeds. `REScure` is intentionally excluded because `https://rescure.me/` shows a temporary-closure page as of 2026-05-21.
- `[x]` Add feed freshness metadata and stale-feed warning status.
- `[x]` Add parser drift alert when invalid counts spike.
- `[x]` Add cache invalidation strategy after feed updates by bumping a feed revision marker in Redis.

Steps:

1. Keep the built-in `production-free` preset current when external free feeds retire or change format.
2. Prefer the preset in `.env.example` and ops helpers, but allow explicit source overrides.
3. Store last-success timestamps and parser stats per source.
4. Surface stale status in `/metrics`, `/status`, or agent events.
5. Run a manual feed sync drill and record expected output from the real deployment environment.

## 5. Block Page And User Experience

Goal: blocked users see a clear page instead of only receiving a block IP.

- `[x]` Resolver can return `SAFE_ZONE_BLOCK_PAGE_IP` for blocked A/AAAA answers.
- `[x]` Add production static block page HTML.
- `[x]` Serve block page through Caddy and embedded Go.
- `[!]` Set `SAFE_ZONE_BLOCK_PAGE_IP` to the real public block-page IP in the target production environment. The repo default stays loopback for local development.
- `[x]` Include enough context on the page: blocked domain, requested path, category/reason when available, and report path.
- `[x]` Add false-positive reporting flow and operator review path.
- `[x]` Add configurable DNS blocking strategies: `sinkhole`, `nxdomain`, `refused`, and `nullip`, so operators can choose block-page behavior or avoid HTTPS certificate mismatch warnings.

Steps:

1. Add lightweight static block page assets.
2. Add Caddy route or `core-api` route for the block page.
3. Update DNS blocking config to resolve blocked domains to that page when using `sinkhole`.
4. Select the production DNS blocking strategy. Use `sinkhole` for HTTP block-page UX, or `nxdomain`, `refused`, or `nullip` when avoiding arbitrary-domain HTTPS certificate mismatch warnings is more important.
5. Add a false-positive workflow for admins.

## 6. Observability, Logging, And Alerting

Goal: operators can understand incidents without reading raw container logs by hand.

- `[x]` `/metrics` exists on `core-api` and `dns-resolver`.
- `[x]` In-memory request counts, bytes, duration, and status summaries exist.
- `[x]` Metrics intentionally stay JSON-only for the single-VPS MVP; the alert baseline consumes JSON snapshots.
- `[x]` Webhook/Slack/Telegram/email alerting exists through agent tasks, and baseline production alert rules are documented.
- `[x]` Structured JSON logging exists across HTTP request logs, panic recovery, agent runtime events, and lower-level cache/store/risk helpers.
- `[x]` HTTP responses and request logs carry `X-Request-ID`, and scheduled/background jobs emit shared `run_id` values for correlation.
- `[x]` Explicitly stay JSON-only for metrics in MVP instead of adding Prometheus right now.
- `[x]` Add alert rules for service down, Redis unavailable, feed stale, high 5xx rate, DoH upstream failure, and high latency.
- `[x]` Add log retention policy for Docker JSON logs, not only files under `/opt/safe-zone/logs/*.log`.

Steps:

1. Keep new runtime logs on the same JSON schema and preserve `request_id` / `run_id` fields in future handlers and jobs.
2. Reuse the shared `run_id` pattern for any new scheduled or asynchronous production task.
3. Revisit Prometheus only if the single-VPS JSON metrics path stops being sufficient.
4. Keep the alert rules file aligned with `/metrics` and `/` response contracts.
5. Verify Docker log rotation and alert checks in the real production environment.

## 7. Backup, Restore, And Disaster Recovery

Goal: prove data can be restored, not just backed up.

- `[x]` Redis backup and restore scripts exist.
- `[x]` Linux cron examples exist.
- `[x]` Logrotate config exists.
- `[x]` Offsite backup via `rclone` is mentioned in SRS/OPEX docs and implemented in both Linux and PowerShell helper scripts.
- `[x]` Add `rclone` offsite backup for Redis dump, `.env` snapshot, SQLite DB, and critical config including Caddy config.
- `[x]` Add encrypted backup option or document secrets handling.
- `[x]` Add scheduled restore drill.
- `[x]` Define Recovery Time Objective and Recovery Point Objective.

Steps:

1. Extend backup script to include Redis, SQLite, `.env` snapshot, and Caddy/DuckDNS config.
2. Add optional `rclone` destination.
3. Add backup verification: file exists, size nonzero, checksum recorded.
4. Run restore on a clean VM or local staging directory.
5. Document restore time and data loss window.

## 8. Performance Proof

Goal: prove the system meets the target environment, not only local benchmarks.

- `[x]` Local Go benchmarks exist.
- `[~]` Local benchmark file explicitly says it does not prove 500 qps cache-hit / 50 qps miss on target VPS.
- `[x]` Add HTTP/DoH load test script for cache hit and cache miss paths. Implemented as `cmd/load-test`.
- `[x]` Add a reproducible performance-proof wrapper. Implemented as `scripts/qa/performance-proof.sh`.
- `[ ]` Run benchmark on the chosen VPS class.
- `[ ]` Benchmark with Redis enabled, DoH through Caddy, TLS/WHOIS enrichment enabled, and AI mode explicitly selected.
- `[x]` Record CPU, memory, latency percentiles, error rate, and cache hit rate in the benchmark tooling.
- `[x]` Define pass/fail thresholds for production release.

Benchmark procedure:

1. Deploy the exact release candidate to the target VPS class with Redis enabled, SQLite persistence enabled, TLS/WHOIS enrichment enabled, and the intended profiles explicitly configured: LLM provider (`none`, `gemini`, `ollama`, or `hybrid`), Custom ML mode (`disabled`, `shadow`, or `enforce` when implemented), and Agent Engine on/off.
2. Run the formal API benchmark from the same network segment as the production edge:

   ```sh
   SAFE_ZONE_BENCH_API_URL=https://safe.example.com/v1/analyze \
   SAFE_ZONE_BENCH_DOCKER_CONTAINERS="safe-zone-core-api safe-zone-redis" \
   scripts/qa/performance-proof.sh
   ```

3. Archive the generated `tmp/performance-proof/<timestamp>/` directory in the release evidence bundle.
4. If the release exposes DoH through Caddy, run an additional DoH path smoke load with `cmd/load-test`:

   ```sh
   go run ./cmd/load-test \
     -type doh \
     -url https://dns.example.com/dns-query \
     -scenario cache-hit \
     -duration 60s \
     -rate 500 \
     -concurrency 64 \
     -max-error-rate 1 \
     -max-p95 150ms \
     -max-p99 300ms
   ```

Required recorded metrics:

- API cache-hit run: throughput, p50/p95/p99 latency, error rate, cache hit rate, load-generator memory, target container CPU/memory samples.
- API cache-miss run: throughput, p50/p95/p99 latency, error rate, load-generator memory, target container CPU/memory samples.
- DoH edge run, when applicable: throughput, p50/p95/p99 latency, error rate, and target container CPU/memory samples.

Production release pass/fail thresholds:

| Scenario | Minimum load | Required cache hit rate | p95 latency | p99 latency | Error rate | Target resource ceiling |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| API cache-hit | 500 req/s for 60s | >= 95% | <= 150 ms | <= 300 ms | <= 1.0% | Core API avg CPU <= 75%, max memory <= 70% container limit |
| API cache-miss | 50 req/s for 60s | n/a | <= 750 ms | <= 1500 ms | <= 1.0% | Core API avg CPU <= 85%, max memory <= 75% container limit |
| DoH cache-hit edge, if exposed | 500 req/s for 60s | not directly measurable from DoH | <= 150 ms | <= 300 ms | <= 1.0% | DNS resolver + edge avg CPU <= 75%, max memory <= 70% container limit |

Any threshold failure blocks production release unless the release owner records an explicit exception with the measured impact, rollback plan, and expiry date.

Steps:

1. Build the release candidate and start the production-like stack.
2. Run `scripts/qa/performance-proof.sh` and archive its evidence directory.
3. Run the optional DoH edge command if DoH is part of the release surface.
4. Compare the JSON summaries and Docker stats summary against the pass/fail table.
5. Tune rate limits, cache TTL, Redis memory, and upstream timeouts based on results.

## 9. Threat Model And Security Review

Goal: document what Safe Zone protects, what it does not protect, and how it can be attacked.

- `[x]` Write a threat model using STRIDE or a similarly simple structure in `docs/security/threat-model.md`.
- `[x]` Cover public edge, DoH/DoT, admin dashboard, auth/session, Redis, SQLite, feed ingestion, AI providers, backup storage, and deployment secrets.
- `[x]` Add abuse cases: malicious feed input, admin key leakage, upstream DoH failure, DNS amplification attempts, stale feeds, false positives, and SSRF-like enrichment risks.
- `[x]` Add mitigations and explicit accepted risks.
- `[ ]` Review the model before production release.

Steps:

1. Define assets and trust boundaries.
2. List threats per component.
3. Map each threat to current mitigation or missing work.
4. Decide which risks block production and which are accepted for MVP.
5. Revisit after each major architecture change.

## 10. Product Completeness

Goal: make the product operationally useful, not just technically deployable.

- `[x]` Admin dashboard exists with analysis, telemetry, overrides, system status, agent panel, and client/group controls.
- `[x]` Agent workflow exists for audit, feed sync, OSINT audit, alerting, and whitelist update.
- `[x]` Agent architecture/tasks/config are consolidated in `docs/specs/safe-zone-ai-plan.md`; no separate Agent task checklist remains.
- `[x]` Add manual QA checklist for dashboard workflows on desktop and mobile.
- `[ ]` Add release notes or changelog process.
- `[x]` Add operator onboarding guide: first login, first feed sync, first override, first backup, first restore.
- `[x]` Add false-positive and incident review workflow.
- `[x]` Add a simple operator review flow in `core-api` to move false positives from blocked to allow override with a documented review reason.
- `[ ]` Add URL/path analysis if project scope expands beyond domain-level analysis.

Steps:

1. Reconcile stale dashboard and agent checklist files against current code.
2. Run manual UI tests for dashboard tabs, auth, overrides, group policy, telemetry, and agent trigger.
3. Document the first-day operator workflow.
4. Decide whether URL/path analysis belongs in v1 production or a later release.

## 10A. AI Engine Completion And Release Gates

Goal: release only the explicitly selected AI profile, while preserving deterministic fail-open behavior.

### Release profile declaration

Every staging/production evidence bundle must declare one profile:

| Profile | Required configuration | Scope |
|---|---|---|
| Deterministic | `SAFE_ZONE_AI_PROVIDER=none`, `SAFE_ZONE_ML_MODE=disabled`, Agent optional/off | Base production MVP; no LLM/Custom ML dependency. |
| LLM-assisted | Provider `gemini`, `ollama`, or `hybrid`; ML disabled unless separately declared | Optional ambiguous-domain refinement. |
| Agent-assisted | `SAFE_ZONE_AGENT_ENABLED=true` plus explicit per-task settings | Background audit/feed/OSINT/alert/whitelist automation. |
| Custom ML shadow | `SAFE_ZONE_ML_MODE=shadow` with approved bundle | Prediction/evidence only; no verdict change. |
| Custom ML enforce | `SAFE_ZONE_ML_MODE=enforce` with approved bundle | Malicious-only promotion at calibrated policy threshold. |
| URL ML shadow | `SAFE_ZONE_URL_ML_MODE=shadow` on `core-api` with URL bundle | Caller-supplied URL observation only; no DNS use, server fetch or verdict change. |

Profiles can be combined, but every enabled component adds its corresponding gates below.

### Existing LLM provider gates

- `[x]` Gemini/Ollama unified provider manager and `none|gemini|ollama|hybrid` routing exist.
- `[x]` Provider timeout/error/invalid JSON paths preserve deterministic result.
- `[x]` Hybrid tests prove Ollama-first and Gemini fallback behavior.
- `[x]` Risk merge only promotes malicious and does not downgrade suspicious to safe.
- `[!]` Record a real-environment provider smoke for the selected release mode.
- `[!]` Record quota/terms/privacy approval for Gemini or local model/RAM/source approval for Ollama.
- `[!]` Run AI outage drill and prove switching to `none`/approved fallback keeps analysis available.
- `[x]` Reconcile README/index AI summary with all four provider modes, Custom ML modes, and the canonical plan link.

### Agent Engine gates

- `[x]` Engine implements timeout, per-task single flight, panic recovery, status and admin trigger.
- `[x]` Current task catalog is documented: `audit`, `feedsync`, `osint-audit`, `alert`, `whitelist_update`.
- `[!]` Set `SAFE_ZONE_AGENT_WHITELIST_ENABLED=false` in first production environment until controlled import/backup/rollback drill passes.
- `[x]` Admin manual trigger áp dụng cùng enablement policy với scheduler: task disabled trả `409 Conflict`; unknown task trả `404`, queue đầy trả `429`, và các nhánh API được kiểm thử tự động.
- `[!]` Run live Agent audit smoke and record resulting reviewed/auto-block event and cache invalidation.
- `[!]` Run controlled feed partial-failure/parser-drift drill.
- `[!]` Run alert test for every enabled channel without leaking secrets.
- `[!]` Run whitelist update on controlled fixture, measure memory/time, verify Bloom reload and restore prior DB.
- `[!]` Verify Agent initial due-run behavior is safe for all tasks enabled in production.

### Custom ML development gates

- `[x]` Local dataset snapshot and revised end-to-end plan are documented.
- `[x]` Phase 0: canonicalization/feature contract and exact `leaves` compatibility spike pass.
- `[~]` Phase 1: candidate cohort, conflict quarantine and group-disjoint split artifacts pass; source/legal approval and any additional holdout evidence remain release gates.
- `[x]` Phase 2: sparse training, LightGBM, Platt calibration and candidate-cohort evaluation artifacts are present; product/security approval of the selected threshold remains open.
- `[x]` Phase 3: immutable model bundle, checksums and Python–Go feature/probability parity pass.
- `[x]` Phase 4: Go integration, disabled/shadow/enforce behavior, model-aware cache, telemetry, tests, race and static verification pass.
- `[~]` Phase 5: provisioning/validation tooling, validated private artifact activation, read-only mounts, shadow evidence plumbing, bounded selector, representative replay and rollback mechanics are complete. V4 đã freeze PhishTank adaptation/development cùng OpenPhish source-disjoint holdout trước train, pass `36/36` artifact checks cho cả data-only và ternary-TLD family, rồi chọn trong sáu tổ hợp mà không dùng final inputs. Final evaluation giữ representative `22/34` và SAFE VN runtime-candidate phát sinh `1/1.400` FP. Checksum-pinned production-free threat-context evaluation phục hồi `0/12` model false-negative nhưng tạo `1/25` representative benign collision do URL indicator được collapse xuống hostname. Candidate v4 là private `NO-GO`; không export/provision/restart staging. Production canary tiếp tục bị chặn chờ source-aware feed policy, model remediation mới và owner approval.
- `[ ]` Product owner approves threshold/trade-off; security owner approves data/model storage, terms, retention and rollout scope.

Phase 0–4 evidence from the current repository includes `go test ./...`, `go test -race ./internal/analysis ./internal/risk`, CGO-disabled tests, `go vet ./...`, artifact validation `49/49`, provenance hash validation `15/15`, and matching model-bundle `SHA256SUMS`. Candidate v2 artifacts additionally pass `33/33` matrix/provenance/leakage checks and a local Go core/DNS replay with zero parity mismatch. Leakage-free v2/v3 pass their artifact checks; v4 data-only and ternary-TLD families each pass `36/36`, but v4 fails two final gates and has not been exported or provisioned. Phase 5 has a checksum-gated versioned provisioner, validated private artifact activation, read-only Compose mounts, shadow evidence status fields, a clean staging golden-vector observation window, and a policy-only rollback mechanics drill. The default release profile remains Deterministic (`SAFE_ZONE_ML_MODE=disabled`) until model-quality, canary, and approval gates are complete.

### URL-aware ML shadow gates

- `[x]` Fresh group/source-disjoint V10 evidence excludes baseline, frozen packet and prior experiment groups; final đạt `+33 TP / +0 FP`.
- `[x]` Native Go bundle, checksum, `12/12` golden parity, no server-side fetch and privacy-safe query shaping pass.
- `[x]` URL route is core-API POST-only; DNS, GET, domain probability/verdict and parse-failure behavior remain unchanged.
- `[x]` Stable `1–100%` domain sampling, aggregate histograms, error classes, latency and non-blocking proxy PSI are exposed on status/metrics.
- `[x]` Local and Compose staging full-shadow replay completed `679/679` rows with zero HTTP failure, valid prediction error, response mismatch or raw-context leak; labelled Brier/ECE-10 are `0.125928/0.011386`.
- `[x]` Restart rollback to `disabled` passes `5/5` gates on Compose staging runtime; URL `enforce` is rejected by configuration and runtime contract.
- `[x]` Product owner approved the expanded shadow scope on 2026-08-26.
- `[x]` Staging operational monitoring baseline frozen at `ml/experiments/v10-url-shadow-operational-baseline.json` with SHA-256; current PSI reference remains a balanced offline proxy (`proxy_shift`, non-blocking) until live external traffic baseline is captured.
- `[!]` Record reviewed live benign promotions, coverage, invalid-context rate and target-host p95/p99 on external traffic cohort before any enforce design is considered.

URL shadow staging artifacts are `ml/experiments/v10-url-shadow-staging.json`, `ml/experiments/v10-url-shadow-rollback.json`, and `ml/experiments/v10-url-shadow-operational-baseline.json`. The operational procedure is `docs/runbooks/url-ml-shadow-rollout.md`. This route is `BOUNDED_CANARY_OBSERVATION_READY` for external observation; it does not make the domain-only `22/34` representative result pass and does not authorize enforce.

### AI/ML release evidence

Archive with the release:

- selected provider/ML/Agent modes with secrets redacted;
- code/image Git SHA;
- provider smoke/outage results when LLM enabled;
- Agent status/task/drill results when Agent enabled;
- model bundle revision/checksum/policy/report when Custom ML enabled;
- artifact validation result, data-manifest linkage and raw/processed provenance checksum result;
- Python–Go parity report and candidate-cohort metrics for ML release;
- URL shadow staging/rollback reports, sampling policy revision and aggregate drift/calibration evidence when URL ML is enabled;
- target VPS latency/RSS/load results for every selected profile;
- rollback commands and last-known-good provider/model revision.

### Current Phase 5 staging evidence

The reviewed representative replay packet is archived at
`ml/evidence/representative-replay/run-20260808/`. It contains 137 human-label
rows, the referenced evidence files, the generated metrics/approval packet, and
`checksums.sha256`. Its `FPR=0.0000` is a zero-event sample result (0/25
benign), not a production guarantee; the archive records the IDN and
single-reviewer governance waivers. This evidence is sufficient for owner
review, but not by itself for `enforce`.

The targeted whitelist-proxy addendum at
`ml/evidence/whitelist-proxy-review/run-20260823-owner-reviewed-addendum/`
contains three additional owner-reviewed benign domains. All three are model
would-block cases, so both offline and runtime-candidate FPR on this deliberately
selected supplement are `3/3 = 100%`. Probability and response parity remain
clean, but this model-quality result blocks canary activation until remediation
passes the supplement and the representative regression suite.

The 2026-08-08 staging smoke used the validated private bundle outside the repository:

- both `core-api` and `dns-resolver` were healthy with `SAFE_ZONE_ML_MODE=shadow` and `ml_state=ready`;
- both services reported model version `1.0.0`, block threshold `0.85`, and the same immutable revision `4632f9ea69124591db89dfb176aacf46323c18043c7b8c8d0972c3b2f92c3bca`;
- the active bundle mount was read-only in both containers and the canonical SHA-256 validation passed for all five hashed runtime files;
- three rounds of the 29-case golden fixture were replayed through each service (87 requests per service); all responses were HTTP 200 with zero parity failures, zero ML errors, and zero enforce promotions;
- the replay ran with external provider/enrichment/OSINT calls disabled to isolate the ML shadow path; both services remained `shadow`/`ready` on model `1.0.0`, threshold `0.85`, with the same immutable revision and non-zero `would_block`/`would_pass` telemetry;
- the `v2-policy-drill` release was activated and rolled back to v1; both services returned to the v1 revision/threshold and the post-rollback cache check observed a revision-invalidated miss. This validates rollback mechanics only, not a new model quality release;
- this is golden-vector/synthetic evidence, not representative production traffic or a human-labelled false-positive review. Canary enforce and product/security approval remain open, and the default production profile remains `disabled`.

An optional component that is disabled does not block base deterministic MVP. A component that is enabled without its gates/evidence blocks that release profile.

## 11. Production Release Process

Goal: make deployments repeatable and reversible.

- `[x]` Compose deploy helper exists.
- `[x]` Health checks exist.
- `[x]` Production deploy and release-gate runbooks exist for both supported edge modes.
- `[x]` Production ports validation check exists through `scripts/check-production-ports.sh`.
- `[x]` Public edge smoke check exists through `scripts/public-edge-smoke.sh`.
- `[x]` Add staging environment procedure.
- `[x]` Add pre-release checklist.
- `[x]` Add rollback procedure.
- `[x]` Pin image tags or define build provenance for releases.
- `[x]` Add version endpoint/build metadata.
- `[x]` Add production smoke test script.

Steps:

1. Define staging and production `.env` requirements.
2. Build images and record version/SHA.
3. Run tests, security scan, and load smoke before release.
4. Deploy staging first.
5. Run public endpoint smoke tests.
6. Deploy production.
7. Keep a rollback command and last-known-good config ready.

## 12. Perfect Production

Goal: go beyond single-node MVP into a polished, resilient service.

- `[ ]` Multi-node architecture decision: stay single VPS, split DNS/core/Redis, or add HA.
- `[x]` External uptime monitoring.
- `[x]` Dedicated dashboards for latency, error rate, cache hit rate, feed freshness, and block events.
- `[x]` Automated certificate monitoring for both HTTPS and DoT.
- `[x]` Regular disaster recovery drills.
- `[x]` Security review before major releases.
- `[x]` Capacity plan for 10x current traffic.
- `[x]` Data retention and privacy policy for telemetry.
- `[x]` Operator handover docs.

Steps:

1. Stabilize MVP production first.
2. Add external monitoring and alerting.
3. Practice restore and rollback.
4. Document privacy/data retention.
5. Decide whether HA is worth the cost and complexity.

## Recommended Execution Order

1. Fix production exposure and secrets: ports, firewall, admin credentials, DoT certificate path.
2. Finish user-facing protection: production block page and false-positive workflow.
3. Make operations real: structured logs, request IDs, alerts, offsite backup, restore drill.
4. Prove performance: run cache-hit and cache-miss benchmarks on target VPS.
5. Write threat model and close release blockers.
6. Declare the AI/ML/Agent release profile and close every enabled-component gate in section 10A.
7. Run staging deployment and smoke tests.
8. Release production MVP.
9. Iterate toward perfect production: Custom ML phases, monitoring dashboards, DR drills, privacy docs, and HA decision.

## Production MVP Exit Criteria

Safe Zone can be called production MVP when all of these are true:

- `[~]` Public traffic only enters through intended ports. Compose bindings and validation scripts are complete; a real environment execution record is still needed.
- `[x]` Production secrets are explicit, strong, and not printed in logs.
- `[~]` DoH over HTTPS works through the Caddy production edge; public-internet execution still needs to be recorded per deployment.
- `[x]` DoT uses a trusted certificate path or documented client trust model, and configured TLS key failures now fail fast.
- `[x]` Block page and configurable DNS blocking strategies work for blocked DNS answers.
- `[x]` Threat feeds sync from the official preset and stale status is visible.
- `[~]` Backups can be copied offsite and restored by scripts; a scheduled restore drill still needs to be recorded.
- `[x]` Structured logs and request IDs exist.
- `[x]` Alerts exist for the main failure modes.
- `[ ]` Performance target is proven on the target VPS.
- `[~]` Threat model draft exists and release-blocking risks are identified; blocker closure is still required.
- `[~]` Staging deploy and production smoke tests are scripted; pass records from the target environment are still needed.
- `[~]` AI release profile is explicit. Deterministic/LLM/Agent/Custom ML components are enabled only when their section 10A gates and evidence are complete.
