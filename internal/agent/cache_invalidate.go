package agent

import (
	"context"
	"fmt"
	"strings"

	"safe-zone/internal/cache"
)

// analysisCachePrefix is the shared key layout of the risk service analysis
// cache: the base key plus optional model-revision variants
// (risk.analysisCacheKey).
const analysisCachePrefix = "safe-zone:analysis:"

// analysisCacheScanMaxKeys bounds the SCAN used to find model-revision
// variants of one domain so a pathological keyspace cannot pin a cycle.
const analysisCacheScanMaxKeys int64 = 1000

// invalidateAnalysisCache deletes every cached analysis entry for exactly one
// domain: the base key plus any model-revision variants. Neighbor domains and
// global revision/status keys are never touched. The pattern is exact-scope
// because domains never contain glob metacharacters; the guard rejects any
// input that could widen the match.
func invalidateAnalysisCache(ctx context.Context, redisCache *cache.Redis, domain string) error {
	if redisCache == nil || !redisCache.Enabled() {
		return cache.ErrDisabled
	}
	if domain == "" || strings.ContainsAny(domain, "*?[]\\ \t") {
		return fmt.Errorf("invalidate analysis cache: invalid domain %q", domain)
	}

	if err := redisCache.Delete(ctx, analysisCachePrefix+domain); err != nil {
		return err
	}
	_, err := redisCache.ScanDelete(ctx, analysisCachePrefix+domain+":model:*", analysisCacheScanMaxKeys)
	if err != nil {
		return err
	}
	return nil
}
