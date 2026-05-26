# Tasks: Rate Limiting & Request Protection

Synced with repository state on 2026-05-21. Code-backed items are checked; verification items stay open until rerun is recorded.

## Phase 1: Core Rate Limiter

- [x] Create `internal/ratelimit/limiter.go`:
  - Token bucket struct with `sync.Mutex`.
  - `New(ratePerMinute, burst)` constructor.
  - `Allow(key string) bool` method with lazy token refill.
  - `Close()` to stop cleanup goroutine.
  - Background cleanup goroutine (every 5 min, removes idle > 10 min).
- [x] Create `internal/ratelimit/limiter_test.go`:
  - Test basic allow/deny.
  - Test burst capacity.
  - Test token refill after waiting.
  - Test concurrent access (race detector).
  - Test auto-cleanup.
  - Test disabled limiter (nil-safe).

## Phase 2: HTTP Middleware

- [x] Create `internal/ratelimit/middleware.go`:
  - `Middleware(limiter, next)` single-tier middleware.
  - `TieredMiddleware` with path-prefix → limiter mapping.
  - Client IP extraction (X-Forwarded-For → X-Real-IP → RemoteAddr).
  - 429 response with `Retry-After` header.
- [x] Add middleware tests:
  - Test 429 response format.
  - Test `Retry-After` header.
  - Test IP extraction from various headers.
  - Test tiered routing (different limits per path).

## Phase 3: Service Integration

- [x] Modify `cmd/core-api/main.go`:
  - Add tiered rate limiter (analyze, overrides, telemetry, default).
  - Wrap mux: `logRequests(tiered.Wrap(mux), metrics)`.
  - Add `defer` close for all limiters.
- [x] Modify `cmd/dns-resolver/main.go`:
  - Add tiered rate limiter (dns-query, default).
  - Wrap mux similarly.

## Phase 4: Configuration & Documentation

- [x] Update `.env.example` with rate limit env vars.
- [x] Update `docker-compose.yml` with rate limit env vars.
- [ ] Update `/` status endpoint to include rate limit info.

## Phase 5: Verification

- [x] `go test ./internal/ratelimit/...` — all pass.
- [x] `go test ./...` — full suite passes, no regression.
- [x] `go build ./...` — compiles clean.
- [ ] Manual test: rapid `curl` loop triggers 429 correctly.
