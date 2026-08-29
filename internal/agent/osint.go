package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
	"safe-zone/internal/osint"
	"safe-zone/internal/store"
)

// DefaultOSINTPromotionTTL mirrors the feed.Sync default and the
// SAFE_ZONE_FEED_TTL_DAYS fallback so promoted members expire on the same
// schedule as feed-synced ones.
const DefaultOSINTPromotionTTL = 14 * 24 * time.Hour

type OSINTConfig struct {
	MaxPerCycle int
	Lookback    time.Duration
	ThreatKey   string
	// TTL is the expiry window scored into every promoted member. It must
	// mirror the threat-feed TTL (SAFE_ZONE_FEED_TTL_DAYS): risk.Service
	// only matches members whose score is still in the future.
	TTL time.Duration
}

// evidenceLookup decouples the task from the concrete OSINT service so tests
// can inject deterministic reports.
type evidenceLookup interface {
	Enabled() bool
	Lookup(ctx context.Context, domain string, force bool) (osint.Report, error)
}

type OSINTTask struct {
	store  *store.DB
	osint  evidenceLookup
	redis  *cache.Redis
	config OSINTConfig
}

func NewOSINTTask(db *store.DB, evidence *osint.Service, redis *cache.Redis, cfg OSINTConfig) *OSINTTask {
	if cfg.MaxPerCycle <= 0 {
		cfg.MaxPerCycle = 50
	}
	if cfg.Lookback <= 0 {
		cfg.Lookback = 24 * time.Hour
	}
	if cfg.ThreatKey == "" {
		cfg.ThreatKey = "safe-zone:threat:feed"
	}
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultOSINTPromotionTTL
	}
	return &OSINTTask{store: db, osint: evidence, redis: redis, config: cfg}
}

func (t *OSINTTask) Name() string { return "osint-audit" }

func (t *OSINTTask) Run(ctx context.Context) error {
	if t.store == nil || !t.store.Enabled() || t.osint == nil || !t.osint.Enabled() {
		return nil
	}

	// The threat feed contract is a ZSET scored by expiry epoch. A key left
	// by an older build may be a plain SET; fail loudly instead of either
	// silently skipping promotion or corrupting feed matching.
	if t.redis != nil && t.redis.Enabled() {
		if err := t.preflightThreatKey(ctx); err != nil {
			return err
		}
	}

	candidates, err := t.store.QueryRecentAllowedOrSuspiciousDomains(ctx, time.Now().Add(-t.config.Lookback), t.config.MaxPerCycle*3)
	if err != nil {
		return err
	}

	var checked, promoted, skipped, failed int
	for _, candidate := range candidates {
		if checked >= t.config.MaxPerCycle {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if !osint.ShouldLookup(candidate.Domain, analysis.Result{Domain: candidate.Domain}) {
			skipped++
			continue
		}
		checked++
		report, err := t.osint.Lookup(ctx, candidate.Domain, false)
		if err != nil {
			logjson.Warn("agent osint lookup failed", correlation.Fields(ctx, map[string]any{
				"service": "core-api",
				"task":    "osint-audit",
				"domain":  candidate.Domain,
				"error":   err.Error(),
			}))
			continue
		}
		if !report.ShouldBlock || t.redis == nil || !t.redis.Enabled() {
			continue
		}
		if t.promote(ctx, report.Domain, len(report.Evidence)) {
			promoted++
		} else {
			failed++
		}
	}

	summary := fmt.Sprintf(`{"checked":%d,"promoted":%d,"skipped":%d,"promotion_failures":%d}`, checked, promoted, skipped, failed)
	_ = t.store.RecordAgentEvent(ctx, "osint-audit", "osint_audit_completed", "", summary)
	return nil
}

// preflightThreatKey verifies the threat key is compatible before any
// promotion. Valid types are "none" (missing) and "zset". The key is never
// deleted automatically — recovery is a manual operator action described in
// docs/runbooks/redis-outage.md.
func (t *OSINTTask) preflightThreatKey(ctx context.Context) error {
	keyType, err := t.redis.Type(ctx, t.config.ThreatKey)
	if err != nil {
		return fmt.Errorf("threat feed key type check failed: %w", err)
	}
	switch keyType {
	case "", "none", "zset":
		return nil
	default:
		_ = t.store.RecordAgentEvent(ctx, "osint-audit", "threat_feed_key_wrong_type", "",
			fmt.Sprintf(`{"key":%q,"type":%q}`, t.config.ThreatKey, keyType))
		logjson.Error("threat feed key has incompatible type; OSINT promotion disabled", correlation.Fields(ctx, map[string]any{
			"service":  "core-api",
			"task":     "osint-audit",
			"key":      t.config.ThreatKey,
			"key_type": keyType,
			"recovery": "back up or rename the key, then run a feed sync to recreate the ZSET (docs/runbooks/redis-outage.md)",
		}))
		return fmt.Errorf("threat feed key %q has incompatible type %q; expected none or zset", t.config.ThreatKey, keyType)
	}
}

// promote adds a domain to the threat feed ZSET with an expiry score and
// invalidates the cached analysis for that exact domain. It reports success
// only when both steps succeed so partial promotions are never counted.
func (t *OSINTTask) promote(ctx context.Context, domain string, evidence int) bool {
	normalized, err := analysis.NormalizeDomain(domain)
	if err != nil {
		t.logPromotionFailure(ctx, domain, "normalize", err)
		return false
	}
	expiryScore := float64(time.Now().Add(t.config.TTL).Unix())
	if _, err := t.redis.ZAdd(ctx, t.config.ThreatKey, redis.Z{Score: expiryScore, Member: normalized}); err != nil {
		t.logPromotionFailure(ctx, normalized, "zadd", err)
		return false
	}
	if err := t.redis.Delete(ctx, "safe-zone:analysis:"+normalized); err != nil {
		// The feed entry is in place, but the stale cached verdict would
		// shadow it, so this must not be reported as a clean promotion.
		t.logPromotionFailure(ctx, normalized, "cache_invalidate", err)
		return false
	}
	_ = t.store.RecordAgentEvent(ctx, "osint-audit", "threat_feed_promote", normalized,
		fmt.Sprintf(`{"evidence":%d,"ttl_seconds":%d}`, evidence, int(t.config.TTL.Seconds())))
	return true
}

func (t *OSINTTask) logPromotionFailure(ctx context.Context, domain, stage string, err error) {
	logjson.Warn("agent osint promotion failed", correlation.Fields(ctx, map[string]any{
		"service": "core-api",
		"task":    "osint-audit",
		"domain":  domain,
		"stage":   stage,
		"error":   err.Error(),
	}))
	_ = t.store.RecordAgentEvent(ctx, "osint-audit", "threat_feed_promote_failed", domain,
		fmt.Sprintf(`{"stage":%q,"error":%q}`, stage, err.Error()))
}
