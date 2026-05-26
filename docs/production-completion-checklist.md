# Safe Zone Production Completion Checklist

Date: 2026-05-21

This file is the single operational checklist for moving Safe Zone from the current repository state to production-ready, and then to "perfect production". It intentionally does not merge detailed design/spec documents. Those remain in `docs/specs/` as technical references.

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
- `[x]` Runbooks exist for production edge, Redis outage, AI provider outage, feed staleness, and certificate renewal.
- `[x]` Local benchmarks exist for core analysis paths.
- `[x]` CI/build validation exists through GitHub Actions.

## 1. Documentation Source Of Truth

Goal: one operator-facing checklist, with detailed design documents kept separate.

- `[x]` Create this consolidated checklist as the main production completion file.
- `[x]` Keep historical SRS documents as references only.
- `[x]` Keep detailed design/spec docs in `docs/specs/`.
- `[x]` Reconcile stale task files where checkboxes are still open even though code appears implemented.
- `[x]` Add short Architecture Decision Records for important decisions: fail-open behavior, single-VPS baseline, Redis vs embedded DB, Caddy edge, AI provider strategy.

Steps:

1. Use this file for roadmap tracking.
2. Keep `docs/specs/` for technical implementation details.
3. Mark old checklists as superseded or sync their checkboxes with code reality.
4. Keep operational decisions in `docs/adr/` when they affect future maintainers or production risk.

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
- `[ ]` Add encrypted backup option or document secrets handling.
- `[ ]` Add scheduled restore drill.
- `[ ]` Define Recovery Time Objective and Recovery Point Objective.

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
- `[ ]` Run benchmark on the chosen VPS class.
- `[ ]` Benchmark with Redis enabled, DoH through Caddy, TLS/WHOIS enrichment enabled, and AI mode explicitly selected.
- `[ ]` Record CPU, memory, latency percentiles, error rate, and cache hit rate.
- `[ ]` Define pass/fail thresholds for production release.

Steps:

1. Add reproducible load test commands.
2. Seed Redis with cache-hit domains and choose cache-miss test domains.
3. Test direct service path and public Caddy/DoH path.
4. Capture p50/p95/p99 latency and throughput.
5. Tune rate limits, cache TTL, Redis memory, and upstream timeouts based on results.

## 9. Threat Model And Security Review

Goal: document what Safe Zone protects, what it does not protect, and how it can be attacked.

- `[ ]` Write a threat model using STRIDE or a similarly simple structure.
- `[ ]` Cover public edge, DoH/DoT, admin dashboard, auth/session, Redis, SQLite, feed ingestion, AI providers, backup storage, and deployment secrets.
- `[ ]` Add abuse cases: malicious feed input, admin key leakage, upstream DoH failure, DNS amplification attempts, stale feeds, false positives, and SSRF-like enrichment risks.
- `[ ]` Add mitigations and explicit accepted risks.
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
- `[x]` Agent workflow exists for audit, feed sync, alerting, and whitelist update.
- `[x]` Dashboard and agent task checklists in `docs/specs/` were reviewed; remaining open items are manual QA or environment smoke checks, not stale implementation tasks.
- `[ ]` Add manual QA checklist for dashboard workflows on desktop and mobile.
- `[ ]` Add release notes or changelog process.
- `[ ]` Add operator onboarding guide: first login, first feed sync, first override, first backup, first restore.
- `[ ]` Add false-positive and incident review workflow.
- `[ ]` Add URL/path analysis if project scope expands beyond domain-level analysis.

Steps:

1. Reconcile stale dashboard and agent checklist files against current code.
2. Run manual UI tests for dashboard tabs, auth, overrides, group policy, telemetry, and agent trigger.
3. Document the first-day operator workflow.
4. Decide whether URL/path analysis belongs in v1 production or a later release.

## 11. Production Release Process

Goal: make deployments repeatable and reversible.

- `[x]` Compose deploy helper exists.
- `[x]` Health checks exist.
- `[~]` Production deploy runbook exists, but release gating is not formalized.
- `[x]` Production ports validation check exists through `scripts/check-production-ports.sh`.
- `[x]` Public edge smoke check exists through `scripts/public-edge-smoke.sh`.
- `[ ]` Add staging environment procedure.
- `[ ]` Add pre-release checklist.
- `[ ]` Add rollback procedure.
- `[ ]` Pin image tags or define build provenance for releases.
- `[ ]` Add version endpoint/build metadata.
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
- `[ ]` External uptime monitoring.
- `[ ]` Dedicated dashboards for latency, error rate, cache hit rate, feed freshness, and block events.
- `[ ]` Automated certificate monitoring for both HTTPS and DoT.
- `[ ]` Regular disaster recovery drills.
- `[ ]` Security review before major releases.
- `[ ]` Capacity plan for 10x current traffic.
- `[ ]` Data retention and privacy policy for telemetry.
- `[ ]` Operator handover docs.

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
6. Reconcile stale task files so docs match code.
7. Run staging deployment and smoke tests.
8. Release production MVP.
9. Iterate toward perfect production: monitoring dashboards, DR drills, privacy docs, and HA decision.

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
- `[ ]` Threat model is written and release-blocking risks are addressed.
- `[~]` Staging deploy and production smoke tests are scripted; pass records from the target environment are still needed.
