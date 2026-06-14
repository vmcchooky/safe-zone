package agent

import (
	"context"
	"fmt"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
	"safe-zone/internal/osint"
	"safe-zone/internal/store"
)

type OSINTConfig struct {
	MaxPerCycle int
	Lookback    time.Duration
	ThreatKey   string
}

type OSINTTask struct {
	store  *store.DB
	osint  *osint.Service
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
	return &OSINTTask{store: db, osint: evidence, redis: redis, config: cfg}
}

func (t *OSINTTask) Name() string { return "osint-audit" }

func (t *OSINTTask) Run(ctx context.Context) error {
	if t.store == nil || !t.store.Enabled() || t.osint == nil || !t.osint.Enabled() {
		return nil
	}

	candidates, err := t.store.QueryRecentAllowedOrSuspiciousDomains(context.Background(), time.Now().Add(-t.config.Lookback), t.config.MaxPerCycle*3)
	if err != nil {
		return err
	}

	var checked, promoted, skipped int
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
		if report.ShouldBlock && t.redis != nil && t.redis.Enabled() {
			if _, err := t.redis.SetAdd(ctx, t.config.ThreatKey, candidate.Domain); err == nil {
				_ = t.redis.Delete(ctx, "safe-zone:analysis:"+candidate.Domain)
				promoted++
				_ = t.store.RecordAgentEvent(context.Background(), "osint-audit", "threat_feed_promote", candidate.Domain, fmt.Sprintf(`{"evidence":%d}`, len(report.Evidence)))
			}
		}
	}

	_ = t.store.RecordAgentEvent(context.Background(), "osint-audit", "osint_audit_completed", "", fmt.Sprintf(`{"checked":%d,"promoted":%d,"skipped":%d}`, checked, promoted, skipped))
	return nil
}
