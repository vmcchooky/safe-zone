# Design: Rate Limiting & Request Protection

## Architecture Decision

**In-memory Token Bucket**, not Redis-based or external. Rationale:
- Safe Zone targets a single VPS. No need for distributed coordination.
- Zero additional cost (no Redis memory, no external API).
- Minimal latency overhead (< 1ms per check).
- Simpler failure mode (if process restarts, limits reset — acceptable trade-off).

## Token Bucket Algorithm

Each client IP gets a bucket with:
- **Capacity** (max burst size): allows short bursts of traffic.
- **Rate** (tokens per second): steady-state refill rate.
- Tokens are consumed on each request. If no tokens available → `429`.

```
Example: rate=10/min, burst=5
- Bucket starts with 5 tokens.
- Client sends 5 rapid requests → all pass (burst consumed).
- 6th request → 429 (must wait ~6 seconds for next token).
- After waiting, tokens refill at 1 every 6 seconds.
```

## Package Design: `internal/ratelimit`

### Core Types

```go
// Limiter manages per-key token buckets with auto-cleanup.
type Limiter struct {
    mu       sync.Mutex
    buckets  map[string]*bucket
    rate     float64       // tokens per second
    burst    int           // max tokens (burst capacity)
    done     chan struct{}
}

type bucket struct {
    tokens    float64
    lastCheck time.Time
}
```

### Key Functions

```go
// New creates a rate limiter. rate = requests/minute, burst = max burst.
func New(ratePerMinute float64, burst int) *Limiter

// Allow checks if the given key (IP) has tokens available.
// Returns true if allowed, false if rate limited.
func (l *Limiter) Allow(key string) bool

// Close stops the cleanup goroutine.
func (l *Limiter) Close()
```

### Auto-Cleanup

- Background goroutine runs every 5 minutes.
- Removes buckets where `time.Since(lastCheck) > 10 minutes`.
- Prevents memory leak from abandoned client IPs.

## HTTP Middleware: `internal/ratelimit.Middleware`

```go
// Middleware returns an http.Handler that rate-limits by client IP.
func Middleware(limiter *Limiter, next http.Handler) http.Handler
```

### Client IP Extraction Priority
1. `X-Forwarded-For` header (first IP) — for reverse proxy setups.
2. `X-Real-IP` header — alternative proxy header.
3. `r.RemoteAddr` — direct connection fallback.

### 429 Response Format
```json
{
  "error": "rate limit exceeded",
  "retry_after_seconds": 6
}
```
Headers: `Retry-After: 6`, `Content-Type: application/json`.

## Integration Points

### core-api (`cmd/core-api/main.go`)

```
Current:  logRequests(mux)
After:    logRequests(ratelimit.Middleware(limiter, mux))
```

Rate limiter wraps the mux, so all routes are protected. Different tiers are handled by using multiple limiters:

```go
analyzeLimiter   := ratelimit.New(10, 5)    // /v1/analyze
overrideLimiter  := ratelimit.New(20, 5)    // /v1/overrides
telemetryLimiter := ratelimit.New(30, 10)   // /v1/telemetry/*
defaultLimiter   := ratelimit.New(60, 15)   // everything else
```

### dns-resolver (`cmd/dns-resolver/main.go`)

```go
dohLimiter     := ratelimit.New(100, 20)   // /dns-query
defaultLimiter := ratelimit.New(60, 15)     // everything else
```

### Per-Route Strategy

Instead of one global middleware, use a **TieredMiddleware** that maps URL path prefixes to specific limiters:

```go
type TieredMiddleware struct {
    tiers   []Tier
    fallback *Limiter
}

type Tier struct {
    PathPrefix string
    Limiter    *Limiter
}
```

## Configuration

Environment variables (all optional, with sensible defaults):

| Variable | Default | Description |
|---|---|---|
| `SAFE_ZONE_RATELIMIT_ENABLED` | `true` | Enable/disable rate limiting |
| `SAFE_ZONE_RATELIMIT_ANALYZE_RPM` | `10` | /v1/analyze requests per minute |
| `SAFE_ZONE_RATELIMIT_ANALYZE_BURST` | `5` | /v1/analyze max burst |
| `SAFE_ZONE_RATELIMIT_DOH_RPM` | `100` | /dns-query requests per minute |
| `SAFE_ZONE_RATELIMIT_DOH_BURST` | `20` | /dns-query max burst |
| `SAFE_ZONE_RATELIMIT_DEFAULT_RPM` | `60` | Default requests per minute |
| `SAFE_ZONE_RATELIMIT_DEFAULT_BURST` | `15` | Default max burst |

## Observability

Rate limit events are counted in `observability.Registry`:
- New metric key format: `RATELIMIT {path} 429`
- Visible in `/metrics` endpoint.
- Log line: `"rate limited %s on %s"` at INFO level (not every hit, sampled).

## Files Changed

### New Files
| File | Description |
|---|---|
| `internal/ratelimit/limiter.go` | Core token bucket + auto-cleanup |
| `internal/ratelimit/middleware.go` | HTTP middleware + IP extraction |
| `internal/ratelimit/limiter_test.go` | Unit tests |

### Modified Files
| File | Change |
|---|---|
| `cmd/core-api/main.go` | Add tiered rate limit middleware |
| `cmd/dns-resolver/main.go` | Add tiered rate limit middleware |
| `.env.example` | Add rate limit env vars |
| `docker-compose.yml` | Add rate limit env vars |

## What This Design Excludes

- Per-API-key rate limiting (no API keys exist yet).
- Redis-backed distributed limiting.
- Adaptive rate limiting based on system load.
- Connection-level rate limiting (use iptables/nftables for that).
