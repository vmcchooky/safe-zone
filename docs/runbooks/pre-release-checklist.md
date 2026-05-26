# Pre-release checklist

Complete this checklist before every Safe Zone production release.

## Release identity

- [ ] Release version is chosen and recorded.
- [ ] Git commit SHA is chosen and recorded.
- [ ] Target edge mode is recorded as `production-edge` or `shared-host-edge`.
- [ ] Last-known-good image tags are recorded for rollback.
- [ ] Last-known-good config snapshot location is recorded.

## Local preflight evidence

- [ ] `scripts/release-preflight.sh` or `scripts/release-preflight.ps1` completed successfully.
- [ ] `go test ./...` passed.
- [ ] `go build ./...` passed.
- [ ] `gosec ./...` passed.
- [ ] `govulncheck ./...` passed.
- [ ] Docker builds succeeded for `core-api`, `dns-resolver`, `feed-sync`, and `feed-syncd`.
- [ ] Preflight evidence directory is attached to the release record.

## Build metadata and provenance

- [ ] `core-api /v1/version` reports the expected `version`, `git_commit`, `build_time`, `image_tag`, `source_repo`, and `deployment_tier`.
- [ ] `dns-resolver /v1/version` reports the expected `version`, `git_commit`, `build_time`, `image_tag`, `source_repo`, and `deployment_tier`.
- [ ] Docker image inspect output is archived for all release images.

## Staging

- [ ] Staging uses a staging-only hostname and staging-only secrets.
- [ ] Staging deploy completed with the same edge mode intended for production.
- [ ] `/healthz` and `/metrics` checks passed.
- [ ] Dashboard auth works in staging.
- [ ] `/v1/analyze` works in staging.
- [ ] DoH smoke passed in staging.
- [ ] DoT smoke passed in staging if the release exposes public DoT.
- [ ] Block-page smoke passed in staging if `SAFE_ZONE_DNS_BLOCK_STRATEGY=sinkhole`.

## Release blockers and evidence

- [ ] Threat-model blockers are closed, or each open blocker has an explicit written exception.
- [ ] Firewall or security-group validation evidence is attached for public production releases.
- [ ] Public-edge smoke evidence is attached for `production-edge`, or host-edge routing evidence is attached for `shared-host-edge`.
- [ ] Restore-drill status is attached.
- [ ] Performance proof status is attached.
- [ ] If public DoT is enabled, certificate readiness and handshake evidence are attached.
- [ ] If SQLite remains fail-open in production, the release record explicitly notes the approved degraded-mode decision.

## Go/no-go

- [ ] Rollback commands and rollback inputs are ready before production deploy.
- [ ] Production deploy approver is recorded.
- [ ] Post-release verification owner is recorded.
