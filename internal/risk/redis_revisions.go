package risk

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	"safe-zone/internal/cache"
	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
)

func (s *Service) withRedis(parent context.Context, fn func(context.Context) error) error {
	if s == nil {
		return cache.ErrDisabled
	}
	return withRedisTimeout(parent, s.redis, s.redisTimeout, fn)
}

// withRedisTimeout runs fn with a timeout-bounded context when the given
// Redis handle is usable, or reports cache.ErrDisabled otherwise. It is a
// free function (not a method) so both Service behavior and the FeedEngine
// share the single guard-and-timeout semantics instead of duplicating
// them; the two pass their own handle and timeout, both written once at
// construction and never reassigned.
func withRedisTimeout(parent context.Context, r *cache.Redis, timeout time.Duration, fn func(context.Context) error) error {
	if r == nil || !r.Enabled() {
		return cache.ErrDisabled
	}

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	return fn(ctx)
}

func (s *Service) currentFeedRevision(ctx context.Context) (string, bool) {
	if s == nil || s.feedRevisionKey == "" {
		return "", true
	}

	var revision string
	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		value, err := s.redis.GetString(redisCtx, s.feedRevisionKey)
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return nil
			}
			return err
		}
		revision = value
		return nil
	})
	if err != nil {
		return "", false
	}
	return revision, true
}

func (s *Service) currentBrandRevision(ctx context.Context) (string, bool) {
	if s == nil {
		return "", true
	}
	var revision string
	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		value, err := s.redis.GetString(redisCtx, brandRevisionKey)
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return nil
			}
			return err
		}
		revision = value
		return nil
	})
	if err != nil {
		return "", false
	}
	return revision, true
}

func (s *Service) bumpBrandRevision(ctx context.Context) {
	if s == nil {
		return
	}
	revision := time.Now().UTC().Format(time.RFC3339Nano)
	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		return s.redis.SetString(redisCtx, brandRevisionKey, revision, 0)
	})
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		logjson.Warn("brand revision cache write failed", correlation.Fields(ctx, map[string]any{
			"service": "risk",
			"error":   err.Error(),
		}))
	}
}
