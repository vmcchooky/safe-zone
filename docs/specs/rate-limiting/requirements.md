# Requirements: Rate Limiting & Request Protection

## Goal

Protect Safe Zone services (core-api, dns-resolver) against abuse, DDoS, and resource exhaustion from a single source. Must work on a single budget VPS ($0/mo external cost) without external dependencies.

## Problem Statement

Currently, both `core-api` and `dns-resolver` accept unlimited requests from any source. On a budget VPS with limited CPU/RAM, a single abusive client can:
- Exhaust Gemini API quota (free tier).
- Overload Redis with cache operations.
- Saturate SQLite write channel with telemetry.
- Cause latency spikes for legitimate users.

## Milestones

### Milestone 1: In-Memory Rate Limiter Package

- A new `internal/ratelimit` package providing a reusable, in-memory rate limiter.
- **Algorithm**: Token Bucket — simple, well-understood, allows bursts.
- **Key**: Client IP address (from `X-Forwarded-For`, `X-Real-IP`, or `RemoteAddr`).
- **Zero external dependency**: No Redis, no external service. Pure Go + `sync.Mutex`.
- **Auto-cleanup**: Expired buckets removed periodically to prevent memory leak.

### Milestone 2: HTTP Middleware

- A reusable `http.Handler` middleware wrapping the rate limiter.
- Returns `429 Too Many Requests` with `Retry-After` header when rate exceeded.
- Configurable per-service (different limits for core-api vs dns-resolver).
- Applied at the mux level, before any handler logic.

### Milestone 3: Per-Endpoint Tiers

| Endpoint Group | Rate Limit | Burst | Rationale |
|---|---|---|---|
| `/v1/analyze` (POST) | 10 req/min | 5 | Most expensive (triggers Gemini AI) |
| `/dns-query` (DoH) | 100 req/min | 20 | DNS must be fast, but bounded |
| `/v1/overrides` (POST/DELETE) | 20 req/min | 5 | Admin mutations, moderate |
| `/v1/telemetry/*` | 30 req/min | 10 | Read-only queries |
| `/*` (default) | 60 req/min | 15 | Health, status, metrics |

### Milestone 4: Configuration & Observability

- All rate limit values configurable via environment variables.
- Rate limit events recorded in metrics (observability.Registry).
- Rate limit status visible in `/metrics` endpoint.

## Non-Functional Requirements

- Rate limiting must add < 1ms overhead per request.
- Memory usage must be bounded (auto-cleanup of idle client entries).
- Must not block or slow down allowed requests.
- Must work correctly with reverse proxies (proper client IP extraction).
- No new external dependencies introduced.

## Acceptance Criteria

- Rate limiter correctly limits per-IP requests.
- Burst allowance works (e.g., 5 rapid requests allowed, then throttled).
- `429` responses include valid `Retry-After` header.
- Expired rate limit entries are cleaned up automatically.
- All existing tests continue to pass.
- Service operates normally when rate limiter is disabled (via env var).

## What This Does NOT Include

- Distributed rate limiting (across multiple instances).
- API key-based rate limiting.
- IP blocklist/allowlist (handled by Local Overrides).
- WAF or Layer-7 DDoS protection (use Cloudflare for that).
