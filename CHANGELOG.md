# Changelog

Notable changes to Safe Zone. Dates are UTC. Entries land here when their
PR merges to `main`, oldest batch first.

## Unreleased

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
