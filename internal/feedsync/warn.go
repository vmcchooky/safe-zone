package feedsync

import (
	"context"

	"github.com/redis/go-redis/v9"

	"safe-zone/internal/config"
	"safe-zone/internal/logjson"
)

// defaultFeedMemberWarnThreshold bounds silent additive growth of the
// shared threat-feed ZSET. Sources grow over time; without a tripwire the
// first symptom is Redis memory pressure.
const defaultFeedMemberWarnThreshold = 2000000

// WarnIfFeedOversized reports whether the feed key holds more members than
// the configured tripwire. A read error or a non-positive threshold is not
// an oversize signal, so both report false without logging: the sync itself
// already succeeded, and this check must never fail a run.
func WarnIfFeedOversized(ctx context.Context, redisAddr, redisPassword string, redisDB int, key string) bool {
	threshold := config.Int("SAFE_ZONE_FEED_MAX_MEMBERS_WARN", defaultFeedMemberWarnThreshold)
	total, err := feedMemberCount(ctx, redisAddr, redisPassword, redisDB, key)
	if err != nil || threshold <= 0 {
		return false
	}
	if total <= int64(threshold) {
		return false
	}
	logjson.Warn("threat feed member count above threshold", map[string]any{
		"service":   "feed-sync",
		"key":       key,
		"members":   total,
		"threshold": threshold,
	})
	return true
}

func feedMemberCount(ctx context.Context, redisAddr, redisPassword string, redisDB int, key string) (int64, error) {
	client := redis.NewClient(&redis.Options{Addr: redisAddr, Password: redisPassword, DB: redisDB})
	defer func() { _ = client.Close() }()
	return client.ZCard(ctx, key).Result()
}
