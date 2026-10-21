# Changelog

Notable changes to Safe Zone. Dates are UTC. Entries land here when their
PR merges to `main`, oldest batch first.

## [Unreleased]

### Security
- The allow list no longer fails silently. A load failure is recorded,
  logged with its consequence, reported in `/v1/status` as
  `whitelist.loaded` / `whitelist.error`, and stops `core-api` and
  `dns-resolver` from starting in production. A configured allow-list file
  that cannot be read is an error, not an empty allow list. Unset or empty
  `SAFE_ZONE_WHITELIST_PATH` now means DB-only; the service no longer invents
  `./data/whitelist.txt` and refuses to start on a stock install.
- A blocked domain can no longer be silently unblocked. An unparsable
  `SAFE_ZONE_BLOCK_PAGE_IP` falls back to the null IP instead of producing
  an empty answer, and the resolver refuses to start in production with a
  malformed value.
- `SAFE_ZONE_AGENT_WHITELIST_ENABLED` now defaults to `false`. Enabling the
  agent engine previously replaced the whole operator-curated allow list
  with a downloaded file on the first run.
- The agent's whitelist import is verifiable and undoable: an optional
  `SAFE_ZONE_AGENT_WHITELIST_SHA256` rejects a download that is not the
  expected file, a rollback snapshot is taken before every import, and
  `GET /v1/whitelist/snapshots` plus `POST /v1/whitelist/rollback` restore a
  previous allow list.
- `core-api` refuses to start in production when no threat feed source is
  configured, and the canonical production stack now includes the
  `feed-syncd` daemon with a real default source. The base Compose file keeps
  the daemon behind the `feed-sync` profile for the developer stack; the
  production override resets that profile so the deploy cannot quietly omit
  it. `SAFE_ZONE_SCRIPT_FEED_SYNC=0` stops the daemon after a deploy that
  goes through the helper script. A direct `docker compose ... up` recreates
  and starts it because it is in the production stack, so the opt-out holds
  only while every deploy goes through the helper. The start-up guard does
  not see the stopped daemon either: it reads `SAFE_ZONE_THREAT_FEED_SOURCE`
  and `SAFE_ZONE_AGENT_ENABLED`, so an opted-out deployment with no other
  writer passes the guard while nothing syncs the feed. Feed state is
  observable only through `/v1/status` -> `feed_sync`; alerting on it is not
  part of this change. A stock production install previously had no feed at
  all and no alert that could have said so.
- The production Compose override pins `SAFE_ZONE_ENV=production` for
  `core-api` and `dns-resolver`. The shared `.env` in `.env.example` ships
  `SAFE_ZONE_ENV=local`, and Compose passed it straight into production,
  disabling the guards that key off the environment.
- DoT now requires a trusted certificate in production. A missing key pair
  stops the resolver instead of serving a self-signed certificate that every
  client rejects.
- The container healthcheck probes `/readyz` instead of `/healthz`, so a
  service that is running but cannot do its job is reported as unhealthy.

### Changed
- `/readyz` is a real readiness probe: SQLite is mandatory, Redis is
  optional (a Redis outage degrades coverage but the resolver still
  answers), and the allow list state is reported. `ok` and `degraded` answer
  200; `not_ready` answers 503. Per-check values are only `ok` or
  `unavailable`; the raw error stays in the log, and each check increments a
  `readiness_check_<name>_<outcome>_total` counter.
- `feed-syncd` accepts several comma-separated sources, matching the agent
  task and the alert rules. One failing source no longer takes the others
  down.
- Every `SAFE_ZONE_*` setting the code reads is now documented in
  `.env.example`; a new CI gate (`tools/env-docs-check`) keeps it that way.
  21 settings were previously invisible to an operator, including
  `SAFE_ZONE_AGENT_AUDIT_AUTO_ENFORCE`, `SAFE_ZONE_FEED_ADMISSION_MODE` and
  the four rate-limit tiers that had no documented value.

### Added
- `/v1/whitelist/snapshots` and `/v1/whitelist/rollback` for the allow-list
  rollback copies.
- `whitelist` block in `/v1/status` reporting whether the allow list is in
  effect.
- End-to-end coverage for the report-resolution path and for the read-only
  role, neither of which had any test before.

### Fixed
- The report-review dialog no longer says "Resolve report without
  override". Resolving a report creates a global allow override, exactly
  like the allow path; the dialog now says so and warns about the side
  effect for both actions.
- The read-only role now disables the mutation controls it should: the
  allow/block buttons on the analysis result, adding and deleting an
  override, flushing the cache, downloading the logs, adding a policy
  group, adding a client mapping, deleting either, and triggering an agent
  task. A guest used to see enabled controls that answered 403.
- The operator UI no longer loads a webfont it could not load. The Google
  Fonts import was blocked by the production Content-Security-Policy, so
  the declared family never applied; the page falls back to a system font
  stack now, with no third-party request.
- The Content-Security-Policy allows inline styles. The operator UI sets
  element styles through React style attributes, so the policy was blocking
  the layout of the logo, the score bars and the threat-pressure bars in
  production. `script-src` is unchanged and still refuses inline scripts.
- The domain dataset build no longer labels ad and tracker hosts as
  malicious. The label policy now comes from the trust tier the data
  manifest records, so `stevenblack_hosts.txt` (tier `unwanted-ad-tracker`)
  is excluded from the positive class instead of inflating the measured
  recall and hiding the real false-positive risk. The policy tests call the
  shipped `resolve_source_tiers`/`split_sources_by_tier` functions, so a
  name special case cannot re-add the source without turning CI red.
  `label_policy_version` is now 2 in the manifest and both producers. The
  artifact is not re-exported by this change; the new numbers come with the
  next evaluation.
- A whitelist rollback now reaches `dns-resolver` without a restart. The
  durable `whitelist_revision` is bumped in the same transaction as the
  rows, the API publishes `whitelist_updated`, and the resolver also
  reconciles every 30 seconds, so a missed message or a Redis outage still
  converges. The rollback response reports `revision` and `published`, and
  status endpoints expose `whitelist.revision`.
- A whitelist rollback now requires a reason and writes an
  `agent_audit_log` event with the snapshot, entry count, actor, reason,
  revision and correlation id. The snapshots listing exposes
  `last_rollback`.
- Whitelist snapshot restores verify the stored SHA-256 and entry count,
  refuse an empty snapshot, and log prune failures. `GET
  /v1/whitelist/snapshots` lists the retained snapshots instead of only the
  latest.
- The read-only role now also disables the group Edit button; the
  `GroupModal` submit path receives `canMutate` as a second line of defence.
  The guest Playwright test now covers group edit/delete, mapping
  create/delete, Analysis Allow/Block and the `/reports` redirect.

## [1.10.16] - 2026-10-16

### Security
- Production startup now rejects `saferoad`-prefixed admin secrets: the dev
  defaults once shipped in `start.bat` are public in git history and cleared
  the length checks, so the placeholder gate is what stops a dev `.env`
  from being promoted (#171).
- `start.bat` no longer hardcodes or overwrites admin secrets; it generates
  crypto-random dev-only values when missing and prints the effective
  password once (#171).
- `-redis-password` flag default is empty and resolved from the environment
  after parsing, so parse-error usage text no longer prints the real
  password (#171).
- SQLite database file is created owner-only and re-restricted on every
  startup; serving policy from a world-readable database is a startup
  error. The two swallowed `analysis_log` migrations now fail closed (#173).
- CIDR policy mappings sort by (address bits, prefix length) and normalize
  4-in-6 input to IPv4 before persisting, closing a wrong-group assignment
  via v4-mapped typos (#173).
- URL model bundles now validate handcrafted feature names and order, not
  just counts, catching train/serve skew at load (#174).
- `.env.example` no longer pins `SAFE_ZONE_TRUSTED_PROXIES`, so Compose
  bridge-inclusive defaults apply. Existing deployments whose `.env` still
  pins loopback-only are unaffected by this change — see the upgrade notes
  in `docs/runbooks/pre-release-checklist.md` (#174).
- All GitHub Actions steps pinned to commit SHAs (#172).
- UI source maps off by default (they shipped original TypeScript on a
  public immutable route); `SAFE_ZONE_UI_SOURCEMAPS=true` restores hidden
  maps for release debugging (#172).

### Changed
- CI runs the Go, UI end-to-end and ML gates on dedicated runners instead of
  one saturated job, and shards the Playwright suite three ways (16/16/15
  tests, still serial inside each shard). Same gate coverage: the closure of
  the `ci` task graph is unchanged. The longest gate job went 12m44s -> 7m1s
  measured cold-to-cold (#185).
- CI restores the Go build/module and golangci-lint caches on the quality job.
  Same gate coverage; the task graph measured 656s -> 351s and the job
  12m44s -> 8m18s on an identical commit (#184).
- Go toolchain unified on 1.26.9 across `mise.toml`, `go.mod` and the
  Docker build image (#163).
- Research CLIs moved `cmd/ml-*` → `tools/` with dedicated
  `research:build` / `research:test` tasks; the production `./cmd/...`
  gate no longer compiles them (#163).
- `internal/store/sqlite.go` (3000 lines) split into `groups`,
  `telemetry`, `whitelist`, `reports`, `retention` and `overrides`
  (largest file now ~850 lines; same package, no API change) (#165, #167–#170).
- UI data access unified behind `apiFetch`/`apiJSON`; `SettingsPage` and
  `AnalysisPage` keep their operator-facing message prefixes
  (`Analysis failed:`, `Failed to load settings (HTTP …)`) (#166).
- Go coverage gate at 65% (CI measures ~68%) evaluated from the profile
  `go:test` writes; no second suite run (#164, #167).
- `golangci-lint` timeout 5m → 10m after parallel-load timeouts (#165).
- `deploy.ps1` default remote dir generalized from a personal home path to
  `/home/safe-zone/safe-zone` (override with `-RemoteDir`).

### Added
- AI code review process (`docs/security/ai-code-review.md`): high-risk path
  classes, a security review checklist, a no-self-merge rule, and a reviewer
  self-check for evidence quality. Advisory — nothing is blocked
  automatically (#187).
- Release versioning and tagging runbook (`docs/runbooks/release-tagging.md`)
  with the `v1.<MM>.<DD>` policy, a no-environment tagging checklist and the
  four-part waiver rule, plus a GitHub release-notes template. Recorded in
  DECISION.md (#186).
- Threat-feed Redis failures counted (total/consecutive/last) and exposed
  in `/v1/status` `decision_pipeline`, which is now built by
  `Service.DecisionPipelineStatus()` instead of a partial literal (#174).
- Secret rotation runbook (`docs/runbooks/secret-rotation.md`) and
  `rotate-admin-secrets` helpers (`sh` + `ps1`, `mise run ops:rotate-secrets`)
  with backup, verify (new-key-200/old-key-401) and automatic rollback (#175).
- Parser fuzz targets for feed, WHOIS and TLS hostname matching (#164).
- Oxlint (raw-`fetch` ban, `exhaustive-deps`) and Prettier gates inside
  `npm run check` (#166, #178).
- Pre-release checklist upgrade section: SQLite backup, migration notes,
  `.env` trusted-proxy pin check (#179).
