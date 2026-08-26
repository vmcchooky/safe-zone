# Release gate runbook

## Goal

Make Safe Zone releases repeatable, reviewable, and reversible across both supported edge modes:

- `production-edge`: bundled Caddy with public HTTPS/DoH and optional public DoT
- `shared-host-edge`: Safe Zone stays loopback-only and relies on the host-level Caddy edge

This is a manual release process. No production release should skip the gate.

## Release flow

Follow this exact order:

1. Prepare the release inputs.
2. Run local preflight and archive the evidence.
3. Deploy staging.
4. Verify staging.
5. Approve production with the completed checklist.
6. Deploy production.
7. Run post-release verification and archive the final evidence.

## 1. Prepare

Before running the gate:

- Choose the target edge mode: `production-edge` or `shared-host-edge`.
- Choose the release version string.
- Identify the commit SHA that will be released.
- Confirm the last-known-good image tags and config snapshot for rollback.
- Confirm whether the release exposes public DoT.
- Confirm whether the release uses `sinkhole` block-page mode.

Use the staging and production env examples under `ops/vps-edge/`:

- `env.production-edge.staging.example`
- `env.production-edge.production.example`
- `env.shared-host-edge.staging.example`
- `env.shared-host-edge.production.example`

Staging should use production behavior with staging-only hostnames and secrets. Safe Zone currently distinguishes `local` and `production`, so staging should run with `SAFE_ZONE_ENV=production`.

## 2. Local preflight

Run the helper that collects all local evidence:

Linux/macOS:

```sh
scripts/ops/release-preflight.sh --edge-mode production-edge --version 0.1.0
```

Windows:

```powershell
pwsh ./scripts/ops/release-preflight.ps1 -EdgeMode production-edge -Version 0.1.0
```

For `shared-host-edge`, replace `production-edge` with `shared-host-edge`.

The helper must complete successfully and produce:

- `metadata.env`
- `metadata.json`
- `go-test.txt`
- `go-build.txt`
- `gosec.txt`
- `govulncheck.txt`
- binary build logs for `core-api` and `dns-resolver`
- Docker build logs and image inspect output for `core-api`, `dns-resolver`, `feed-sync`, and `feed-syncd`

Do not continue if preflight fails.

## 3. Staging deploy

### Production-edge staging

1. Copy `ops/vps-edge/env.production-edge.staging.example` to `.env` on the staging host.
2. Fill staging secrets and hostname values.
3. Deploy with:

```sh
scripts/ops/safe-zone.sh deploy
```

### Shared-host-edge staging

1. Copy `ops/vps-edge/env.shared-host-edge.staging.example` to `.env` on the staging host.
2. Fill staging secrets and hostname values.
3. Deploy with:

```sh
docker compose \
  -f docker-compose.yml \
  -f ops/vps-edge/docker-compose.host-edge.yml \
  up -d --build redis core-api dns-resolver
```

Use the image tags and commit from the preflight evidence for the final release record.

## 4. Staging verification

Staging approval requires all of the following:

- `core-api` version endpoint returns the expected metadata.
- `dns-resolver` version endpoint returns the expected metadata.
- `/healthz`, `/readyz`, and `/metrics` return success where applicable.
- `/v1/analyze` works.
- Dashboard login works with staging credentials.
- DoH smoke succeeds.
- DoT smoke succeeds if the release exposes public DoT.
- Block-page smoke succeeds if `SAFE_ZONE_DNS_BLOCK_STRATEGY=sinkhole`.

### Production-edge verification

Run:

```sh
scripts/ops/check-production-ports.sh
scripts/ops/public-edge-smoke.sh "$SAFE_ZONE_PUBLIC_HOST"
scripts/ops/check-block-page.sh "$SAFE_ZONE_PUBLIC_HOST" "$SAFE_ZONE_BLOCK_PAGE_IP" blocked.example.test
curl -fsS "https://$SAFE_ZONE_PUBLIC_HOST/v1/version"
```

### Shared-host-edge verification

Run:

```sh
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8081/healthz
curl -fsS http://127.0.0.1:8080/v1/version
curl -fsS http://127.0.0.1:8081/v1/version
curl -fsS "https://$SAFE_ZONE_PUBLIC_HOST/v1/analyze?domain=example.com"
```

If shared host-edge staging is publicly routed, also record host-level Caddy verification and the external smoke output.

## 5. Production approval

Do not deploy production until `docs/runbooks/pre-release-checklist.md` is fully completed and the threat-model blockers are either closed or explicitly approved as exceptions.

Public production approval must include attached evidence for:

- firewall or security-group validation
- public-edge smoke checks or host-edge routing proof
- backup/restore status
- performance status
- threat-model blocker review

## 6. Production deploy

Production deploy should reuse the same edge mode and same release metadata already proven in staging.

### Production-edge

1. Copy `ops/vps-edge/env.production-edge.production.example` to `.env`.
2. Fill production secrets and hostname values.
3. Deploy with:

```sh
scripts/ops/safe-zone.sh deploy
```

### Shared-host-edge

1. Copy `ops/vps-edge/env.shared-host-edge.production.example` to `.env`.
2. Fill production secrets and hostname values.
3. Deploy with:

```sh
docker compose \
  -f docker-compose.yml \
  -f ops/vps-edge/docker-compose.host-edge.yml \
  up -d --build redis core-api dns-resolver
```

## 7. Post-release verification

Always record:

- `core-api /v1/version`
- `dns-resolver /v1/version`
- health and metrics checks
- public or host-edge smoke output for the selected edge mode
- any exception or deviation from the pre-release checklist

If any production verification step fails, use `docs/runbooks/release-rollback.md`.

## 8. Two independent release gates (Round 5)

Safe Zone separates product readiness from URL ML readiness. The URL ML
specialist is an observer-only shadow route; its promotion status can never
block or gate the deterministic/domain product release, and conversely a
product release never implies URL ML enforce approval.

### Gate A — Product Release Gate (deterministic/domain engine)

Evaluates whether Safe-Zone core is releasable. URL ML state is irrelevant to
this gate except for the safety profile checks below.

| # | Criterion | Evidence source |
|---|---|---|
| A1 | Deterministic analysis path passes full `go test ./...`, race and vet on the release SHA | release preflight |
| A2 | Production config fails startup on missing/weak admin secrets (`SAFE_ZONE_ENV=production`) | startup check |
| A3 | TLS/reverse proxy: only Caddy public; internal ports loopback-only | `check-production-ports.sh` |
| A4 | Health/readiness endpoints and Compose startup ordering verified after restart | `/healthz`, `/readyz` |
| A5 | Image tags pinned / build provenance recorded; rollback target known | preflight metadata |
| A6 | Load test within thresholds on target VPS class (`performance-proof.sh`) | benchmark archive |
| A7 | Restart, rollback, backup/restore drills pass; dependency failure (Redis down) degrades without verdict impact | drill records |
| A8 | Minimal operational telemetry/alerts configured from existing JSON metrics | alert rules file |
| A9 | Installation/upgrade/rollback/privacy docs current | runbooks index |
| A10 | UI/API compatibility: dashboard works against the release API; degraded mode (no Redis/OSINT/AI) shows usable UX | manual QA checklist |
| A11 | Safe URL ML profile holds (see below) even while URL ML stays shadow | `/v1/status → ml.url` |

### Gate B — URL ML Promotion Gate (shadow → enforce consideration)

Evaluates only whether the URL specialist may be *considered* for enforcement
in a later, separately approved round. Failure of Gate B never blocks Gate A.

| # | Criterion | Threshold |
|---|---|---|
| B1 | Shadow parity: zero response parity mismatch over the observation window | 0 mismatches |
| B2 | Raw-context leak (response, log, telemetry, reports) | 0 leaks |
| B3 | Valid prediction errors during window | 0 errors |
| B4 | Invalid-context rate | < 5% after ≥ 100 attempts |
| B5 | URL inference latency p95 | < 2.000 µs |
| B6 | External URL-context volume from real callers (`ui/sdk/extension`), not `.example`/replay probes | ≥ 1.000 evaluated or a representative external window with stated sample count and confidence |
| B7 | Reviewed benign would-promotions on external traffic | 0 confirmed false promotions |
| B8 | External operational baseline frozen from that window (sample count + observation time stated); staging baseline explicitly non-production | artifact with provenance |
| B9 | Rollback/disable drill passes on the deployed runtime | all gates PASS |
| B10 | Product owner approval for any scope/enforce change | recorded approval |

### Safe release profile (URL ML)

A release satisfies the safe profile when ALL of these hold regardless of
Gate B progress:

- `SAFE_ZONE_URL_ML_MODE` defaults to `disabled`; only `disabled`/`shadow`
  parse — `enforce` is rejected at startup by both env loader and runtime.
- No configuration surface (compose defaults, examples, overrides) enables
  enforce implicitly.
- Disabling URL ML requires only a `core-api` restart (DNS never loads the
  bundle). No hot-reload machinery is required or provided.
- Model bundle load failure, operational-baseline load failure and telemetry
  failures are fail-open: they degrade monitoring only and never alter a
  verdict.
- Feedback persistence failures fail closed for feedback alone (HTTP 503)
  while analysis continues unaffected.

Record the outcome of each gate separately in the release manifest:

```text
Gate A (Product Release):    READY | HOLD_WITH_SPECIFIC_BLOCKER | NO_GO
Gate B (URL ML Promotion):   SHADOW_OBSERVER_ONLY | PROMOTION_REVIEW_READY | ENFORCE_APPROVED
```

The overall round status is derived from Gate A; Gate B is reported as its own
line so shadow evidence work is visible without being able to block release.
