package risk

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"safe-zone/internal/cache"
	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
	"safe-zone/internal/store"
)

func (s *Service) RecordRecent(ctx context.Context, item Analysis) {
	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		if err := s.redis.PushJSON(redisCtx, recentAnalysisKey, item, s.telemetry.recentLimit); err != nil {
			return err
		}
		if s.telemetry.recentTTL > 0 {
			return s.redis.Expire(redisCtx, recentAnalysisKey, s.telemetry.recentTTL)
		}
		return nil
	})
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		logjson.Warn("recent analysis cache write failed", correlation.Fields(ctx, map[string]any{
			"service": "risk",
			"error":   err.Error(),
		}))
	}
}

func (s *Service) Recent(ctx context.Context) []Analysis {
	recent := make([]Analysis, 0, s.telemetry.recentLimit)
	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		return s.redis.ListJSON(redisCtx, recentAnalysisKey, 0, s.telemetry.recentLimit-1, func(data []byte) error {
			var item Analysis
			if err := json.Unmarshal(data, &item); err != nil {
				return err
			}
			recent = append(recent, item)
			return nil
		})
	})
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		logjson.Warn("recent analysis cache read failed", correlation.Fields(ctx, map[string]any{
			"service": "risk",
			"error":   err.Error(),
		}))
	}

	return recent
}

func (s *Service) CacheStatus(ctx context.Context) CacheStatus {
	if s == nil || s.redis == nil || !s.redis.Enabled() {
		return CacheStatus{
			Configured: false,
			Status:     "disabled",
		}
	}

	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		return s.redis.Ping(redisCtx)
	})
	if err != nil {
		return CacheStatus{
			Configured: true,
			Status:     "unavailable",
			Error:      err.Error(),
		}
	}

	status := CacheStatus{
		Configured: true,
		Status:     "ok",
	}
	var runtimeStats cache.RedisRuntimeStats
	statsErr := s.withRedis(ctx, func(redisCtx context.Context) error {
		var err error
		runtimeStats, err = s.redis.RuntimeStats(redisCtx)
		return err
	})
	if statsErr != nil {
		status.ObservabilityError = statsErr.Error()
		return status
	}

	status.UsedMemoryBytes = runtimeStats.UsedMemoryBytes
	status.MaxMemoryBytes = runtimeStats.MaxMemoryBytes
	status.MaxMemoryPolicy = runtimeStats.MaxMemoryPolicy
	status.EvictedKeys = runtimeStats.EvictedKeys
	if safe, known := runtimeStats.ProtectsNonExpiringKeys(); known {
		status.EvictionPolicySafe = &safe
	}
	return status
}

func (s *Service) recordTelemetry(a Analysis, client ClientInfo) {
	s.recordTelemetryWithSource(a, client, "")
}

// recordTelemetryWithSource records telemetry with an explicit source,
// overriding the Reasons-based inference. Policy paths that do not inject
// their reason into Result.Reasons (e.g. the separated adblock branch) use
// this so the telemetry source stays accurate without polluting the security
// reasons.
//
// PR1 limitation: telemetry stores the security result (verdict/score/
// reasons) and the source label only. The policy action, category and
// assessment_mode carried by PolicyDecision are not persisted yet; adding
// columns would be a schema migration, deferred to a later PR.
func (s *Service) recordTelemetryWithSource(a Analysis, client ClientInfo, source string) {
	if s.store == nil {
		return
	}
	if source == "" {
		source = inferSource(a)
	}
	policyAction, policyCategory := "", ""
	if a.Decision != nil {
		policyAction, policyCategory = a.Decision.Action, a.Decision.Category
	}
	s.store.RecordAnalysis(store.TelemetryEntry{
		Domain:         a.Domain,
		Verdict:        string(a.Verdict),
		Score:          a.Score,
		Confidence:     a.Confidence,
		Reasons:        a.Reasons,
		CacheHit:       a.CacheHit,
		Source:         source,
		PolicyAction:   policyAction,
		PolicyCategory: policyCategory,
		DecisionID:     a.DecisionID,
		Trace:          encodeTrace(a.Assessment),
		AnalyzedAt:     a.AnalyzedAt,
		ClientIP:       client.IP,
		ClientID:       client.ClientID,
	})
}

func inferSource(a Analysis) string {
	if a.CacheHit {
		return "cache"
	}
	for _, r := range a.Reasons {
		if strings.HasPrefix(r, "admin override") {
			return "override"
		}
		if r == "whitelisted" {
			return "whitelist"
		}
		if r == threatFeedReason {
			return "feed"
		}
		if r == "adblock" {
			return "adblock"
		}
	}
	return "lexical"
}

// TelemetryRecentFiltered returns recent telemetry entries constrained at the store layer.
func (s *Service) TelemetryRecentFiltered(filter store.TelemetryFilter, limit, offset int) ([]store.TelemetryEntry, error) {
	if s.store == nil {
		return nil, nil
	}
	return s.store.QueryRecentFiltered(context.Background(), filter, limit, offset)
}

// TelemetryStats returns aggregate telemetry statistics.
func (s *Service) TelemetryStats(period string) (store.Stats, error) {
	if s.store == nil {
		return store.Stats{}, nil
	}
	return s.store.QueryStats(context.Background(), period)
}
