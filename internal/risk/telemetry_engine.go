package risk

import (
	"time"

	"safe-zone/internal/cache"
	"safe-zone/internal/store"
)

// TelemetryEngine owns telemetry state: the recent-analysis ring buffer
// bounds plus the platform handles that persist and serve it. Service
// holds exactly one, constructed in NewService; all telemetry behavior
// lives here.
//
// redis, redisTimeout and store are shared platform handles, not owned
// state: the engine receives the same *cache.Redis / *store.DB pointers
// and the same timeout value the Service holds, all written once in
// NewService and never reassigned afterwards, so the copies cannot
// drift. They stay duplicated (rather than reached through the Service)
// so request-path recording needs no per-call plumbing; a future infra
// extraction can lift them, withRedisTimeout included, without touching
// callers.
type TelemetryEngine struct {
	recentLimit  int64
	recentTTL    time.Duration
	redis        *cache.Redis
	redisTimeout time.Duration
	store        *store.DB
}
