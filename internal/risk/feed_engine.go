package risk

import (
	"time"

	"safe-zone/internal/cache"
)

// FeedEngine owns threat-feed matching state: the Redis key of the live
// feed plus the platform handles needed to read it. Service holds exactly
// one, constructed in NewService; all feed matching behavior lives here.
//
// redis and redisTimeout are shared platform handles, not owned state:
// the engine receives the same *cache.Redis pointer and the same timeout
// value the Service holds, both written once in NewService and never
// reassigned afterwards, so the copies cannot drift. They stay duplicated
// (rather than reached through the Service) so request-path matching
// needs no per-call plumbing; a future infra extraction can lift them,
// withRedisTimeout included, without touching callers.
type FeedEngine struct {
	threatFeedKey string
	redis         *cache.Redis
	redisTimeout  time.Duration
}
