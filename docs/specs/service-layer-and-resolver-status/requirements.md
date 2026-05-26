# Requirements: Shared Risk Service and Resolver Status

## Goal

Reduce duplicated risk-analysis/cache behavior between `core-api` and `dns-resolver`, and make the resolver root URL return an explicit machine-readable status instead of an ambiguous 404.

## Functional Requirements

- `core-api` and `dns-resolver` must use one shared internal service for domain analysis, Redis cache lookup, cache writes, TTL selection, and recent-analysis history.
- Existing API response shapes for `/v1/analyze`, `/v1/analysis/recent`, and `/v1/policy` must stay compatible.
- Redis must remain optional. If `SAFE_ZONE_REDIS_ADDR` is empty, services continue to work without cache.
- Redis failures must remain fail-open. Domain analysis must continue when cache reads/writes fail.
- `dns-resolver` root path `/` must return HTTP 200 JSON status describing service, status, mode, upstream DoH URL, Redis cache state, and supported endpoints.
- Existing `/healthz`, `/v1/policy`, and `/dns-query` behavior must keep working.

## Non-Functional Requirements

- Do not introduce a database, worker queue, or external paid service.
- Keep the implementation local-first and simple enough to run with `go run`.
- Do not add user-facing secrets or hard-coded credentials.
- Keep changes small and focused on service-layer extraction plus status discoverability.

## Acceptance Criteria

- `go test ./...` passes.
- `go build ./...` passes.
- `GET http://localhost:8081/` returns JSON instead of 404.
- `GET http://localhost:8081/healthz` returns ok.
- `GET http://localhost:8080/v1/analyze?domain=secure-login-wallet-example.com` still returns a malicious verdict.
- `GET http://localhost:8081/v1/policy?domain=secure-login-wallet-example.com` still returns `policy: block`.
- DoH POST to `/dns-query` still returns a DNS message for malicious A queries pointing at the configured block IP.
