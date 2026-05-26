# Pre-release security checklist

Run this checklist before every major Safe Zone release.

## Goal

Catch obvious security regressions before deployment, not after exposure.

## 1. Static analysis and vulnerability review

- [ ] `gosec ./...` passes with no unreviewed findings.
- [ ] `govulncheck ./...` passes with no unresolved vulnerable dependency paths.
- [ ] `go test ./...` passes after the final security-relevant changes.
- [ ] `go build ./...` passes for the release candidate.

## 2. Secret and credential hygiene

- [ ] Confirm `.env`, `ops/secrets/`, backups, and screenshots are not being prepared for publication or commit.
- [ ] Run a secret scan against the repo and release bundle. At minimum, search for obvious tokens, passwords, and private keys with `rg`.
- [ ] Verify production uses explicit strong secrets or `*_FILE` secret paths.
- [ ] Verify generated local-only secrets are not reused in staging or production.

Recommended quick secret scan examples:

```sh
rg -n "BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|API[_-]?KEY|TOKEN|SECRET|PASSWORD" .
rg -n "SAFE_ZONE_ADMIN_|SAFE_ZONE_GEMINI_|SAFE_ZONE_DUCKDNS_|SAFE_ZONE_AGENT_" .env ops
```

## 3. Dependency and supply-chain review

- [ ] Review `go.mod` and `go.sum` changes in the release diff.
- [ ] Confirm any newly added third-party dependency has a clear purpose and maintained upstream.
- [ ] Re-check feed sources, OSINT sources, AI endpoints, and webhook destinations for unexpected changes.
- [ ] If release images changed, record the image tags and build provenance in the release evidence.

## 4. File permissions and local artifact review

- [ ] Confirm scripts under `scripts/` that are intended for Linux execution still have the executable bit where needed.
- [ ] Confirm secret files under `ops/secrets/` are not world-readable on the target host.
- [ ] Confirm backup outputs are encrypted when production backup handling requires it.
- [ ] Confirm no debug dumps or temporary logs containing sensitive data are being retained unintentionally.

## 5. Runtime and surface-area checks

- [ ] Review `docs/security/threat-model.md` for any new component or exposure introduced by the release.
- [ ] Confirm only intended public ports are exposed for the target edge mode.
- [ ] Confirm `/healthz`, `/readyz`, `/metrics`, dashboard auth, DoH, and DoT behavior match the expected release surface.
- [ ] Confirm certificate status and expiry monitoring are working for HTTPS and DoT if those paths are public.

## 6. Release gate alignment

- [ ] Complete [pre-release-checklist.md](D:/Quorix/services/safe-zone/docs/runbooks/pre-release-checklist.md).
- [ ] Confirm rollback inputs are available and current.
- [ ] Confirm the latest restore-drill evidence is attached.
- [ ] Record any accepted security exceptions explicitly with owner and expiry date.

## Minimum rule

If any item above fails and there is no explicit written exception, the release should not be treated as security-reviewed.
