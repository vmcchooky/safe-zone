# Safe Zone analysis remediation checklist

Date: 2026-05-21

Source reviewed:
- `docs/analysis/safe-zone-deep-analysis.md`
- The generated PDF copy was removed during the Safe Zone rename; the Markdown file is the authoritative source.

## Verdict on Kimi 2.6 analysis

The analysis is useful as a broad architecture review, but it is partly outdated against the current repository. I treated each claim as a hypothesis and verified it against code before fixing anything.

For the current operator-facing checklist from repo status to production, see [../production-completion-checklist.md](../production-completion-checklist.md).

## Claim-by-claim assessment

| Area | Assessment | Evidence | Action |
| --- | --- | --- | --- |
| Fail-open Redis/AI/feed design | Correct | `internal/risk/service.go`, `internal/cache`, optional AI client and feed sync paths | No code change needed |
| Missing tests / no visible `*_test.go` | Incorrect | Many tests exist under `cmd/*` and `internal/*` | Documented as outdated |
| No rate limiting on API/DoH | Incorrect | `internal/ratelimit`, `cmd/core-api/main.go`, `cmd/dns-resolver/main.go` | Documented as outdated |
| No body size limits | Incorrect | `http.MaxBytesReader` is present on POST/PUT handlers and DoH body read | Documented as outdated |
| No TLS/WHOIS enrichment | Incorrect | `internal/tlsinspect`, `internal/whois`, enrichment path in `internal/risk/service.go` | Documented as outdated |
| No DoT support | Incorrect | `cmd/dns-resolver/main.go` starts DNS-over-TLS server when enabled | Documented as outdated |
| Cache TTL unclear | Incorrect | `SAFE_ZONE_CACHE_TTL_*` envs and `internal/risk/env.go` | Documented as outdated |
| No GitHub Actions CI | Correct | `.github` had no `workflows` directory | Fixed in this pass |
| Dockerfile build/runtime concerns | Partly correct | Dockerfile was multi-stage already, but Go base image lagged behind `go.mod` and copied whole source before module download | Fixed in this pass |
| Production TLS via reverse proxy not fully packaged | Mostly correct | Docs mention Caddy, but repo has no Caddyfile/workflow gate | Kept as future task |
| Structured logging / correlation IDs missing | Mostly correct | Standard `log` is still used | Future task; not fixed in this pass due wider behavior/design impact |
| OpenAPI/runbooks/threat model missing | Mostly correct | No OpenAPI spec found; some operational docs exist | Future task |

## Fix plan

- [x] Add GitHub Actions CI that runs `go test ./...`, `gosec ./...`, and `govulncheck ./...`.
- [x] Add Docker image build validation for `core-api`, `dns-resolver`, `feed-sync`, and `feed-syncd`.
- [x] Update Dockerfile builder image to Go `1.26.3` to match the vulnerability-free local toolchain.
- [x] Improve Dockerfile layer caching by copying `go.mod`/`go.sum` and downloading modules before copying the full source tree.
- [x] Re-run local verification after changes.

## Deferred follow-up items

- [ ] Add production reverse-proxy assets such as a Caddyfile and deployment notes for public HTTPS/DoH.
- [ ] Add OpenAPI documentation for public HTTP endpoints.
- [ ] Add structured logging and request correlation IDs.
- [ ] Add focused runbooks for Redis outage, AI provider outage, feed staleness, and certificate rotation.
- [ ] Consider Prometheus exposition format or document that `/metrics` is JSON-only.

## Final verification

- [x] `go test ./...` — pass
- [x] `gosec ./...` — pass, 0 issues
- [x] `govulncheck ./...` — pass, no vulnerabilities found
- [x] `docker build --build-arg SERVICE=core-api .` — pass
- [x] `docker build --build-arg SERVICE=dns-resolver .` — pass
- [x] `docker build --build-arg SERVICE=feed-sync .` — pass
- [x] `docker build --build-arg SERVICE=feed-syncd .` — pass
