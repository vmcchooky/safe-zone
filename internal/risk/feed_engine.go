package risk

import (
	"sync/atomic"
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
	// feedLookupFailures counts threat-feed Redis reads that failed. The
	// pipeline stays fail-open so a Redis outage cannot block all traffic,
	// but every failure used to be invisible beyond a per-request log line;
	// this makes "the IOC layer is blind" a number the operator can alert
	// on. feedConsecutiveFailures distinguishes "broken right now" from
	// "failed since boot"; feedLastFailureUnix stamps the last one.
	// Disabled-feed reads (cache.ErrDisabled) are not failures and are
	// never counted.
	feedLookupFailures      atomic.Int64
	feedConsecutiveFailures atomic.Int64
	feedLastFailureUnix     atomic.Int64
}

// noteFeedLookupErr records a failed threat-feed read.
func (e *FeedEngine) noteFeedLookupErr() {
	if e == nil {
		return
	}
	e.feedLookupFailures.Add(1)
	e.feedConsecutiveFailures.Add(1)
	e.feedLastFailureUnix.Store(time.Now().Unix())
}

// noteFeedLookupSuccess resets the consecutive-failure run. The last-failure
// stamp is kept: "when did it last break" stays answerable after recovery.
func (e *FeedEngine) noteFeedLookupSuccess() {
	if e == nil {
		return
	}
	e.feedConsecutiveFailures.Store(0)
}
