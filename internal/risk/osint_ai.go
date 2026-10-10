package risk

import (
	"context"
	"errors"
	"strings"
	"time"

	"safe-zone/internal/ai"
	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
	"safe-zone/internal/osint"
	"safe-zone/internal/store"
)

func (s *Service) syncAIClient() {
	if s == nil || s.store == nil || !s.store.Enabled() {
		return
	}

	s.aiMu.Lock()
	defer s.aiMu.Unlock()

	now := time.Now()
	if !s.lastGeminiKeySync.IsZero() && now.Sub(s.lastGeminiKeySync) < geminiKeySyncCooldown {
		return
	}
	s.lastGeminiKeySync = now

	customKey, err := s.store.GetSystemConfig(context.Background(), "gemini_api_key")
	if err != nil {
		return
	}
	customKey = strings.TrimSpace(customKey)

	if customKey == s.cachedGeminiKey {
		if customKey != "" && s.ai == nil {
			s.ai = ai.NewClient(ai.Config{Provider: "gemini"})
			s.ai.SetGeminiAPIKey(customKey)
		}
		return
	}

	if customKey == "" {
		if s.cachedGeminiKey != "" && s.ai != nil {
			s.ai.SetGeminiAPIKey("")
			if !s.ai.Enabled() && !s.aiShared {
				s.ai = nil
			}
		}
		s.cachedGeminiKey = ""
		return
	}

	if s.ai == nil {
		s.ai = ai.NewClient(ai.Config{Provider: "gemini"})
	}
	s.ai.SetGeminiAPIKey(customKey)
	s.cachedGeminiKey = customKey
}

func (s *Service) refineWithAI(ctx context.Context, current analysis.Result) analysis.Result {
	if s == nil {
		return current
	}
	if current.Verdict != analysis.VerdictSuspicious {
		return current
	}
	s.syncAIClient()

	s.aiMu.Lock()
	client := s.ai
	if client == nil || !client.Enabled() {
		s.aiMu.Unlock()
		return current
	}
	aiResult, err := client.Refine(ctx, current.Domain, current)
	s.aiMu.Unlock()

	if err != nil {
		logjson.Warn("local ai refinement failed", correlation.Fields(ctx, map[string]any{
			"service": "risk",
			"domain":  current.Domain,
			"error":   err.Error(),
		}))
		return current
	}
	if aiResult.Verdict != analysis.VerdictMalicious {
		if len(aiResult.Reasons) > 0 {
			current.Reasons = append(current.Reasons, aiResult.Reasons...)
		}
		return current
	}

	current.Verdict = analysis.VerdictMalicious
	if aiResult.Score > current.Score {
		current.Score = aiResult.Score
	}
	if aiResult.Confidence > current.Confidence {
		current.Confidence = aiResult.Confidence
	}
	current.Reasons = append(current.Reasons, aiResult.Reasons...)
	return current
}

func (s *Service) trustedBrands(ctx context.Context) []analysis.Brand {
	if s == nil || s.brandStore == nil {
		return analysis.DetectionBrands(analysis.DefaultTrustedBrands())
	}
	if ctx == nil {
		ctx = context.Background()
	}
	brands, err := s.brandStore.ListBrands(ctx)
	if err != nil || len(brands) == 0 {
		return analysis.DetectionBrands(analysis.DefaultTrustedBrands())
	}
	return analysis.DetectionBrands(brands)
}

func (s *Service) lookupOSINT(ctx context.Context, domain string, result analysis.Result, mode osintLookupMode, force bool) osint.Report {
	if s == nil || s.osint == nil || !s.osint.Enabled() || mode == osintLookupNone {
		return osint.Report{}
	}
	if !force && !osint.ShouldLookup(domain, result) {
		return osint.Report{}
	}

	switch mode {
	case osintLookupCachedOnly:
		report, ok := s.osint.Cached(ctx, domain)
		if !ok {
			return osint.Report{}
		}
		report.CacheHit = true
		return report
	case osintLookupOnDemand:
		report, err := s.osint.Lookup(ctx, domain, force)
		if err != nil {
			logjson.Warn("osint lookup failed", correlation.Fields(ctx, map[string]any{
				"service": "risk",
				"domain":  domain,
				"error":   err.Error(),
			}))
		}
		s.recordOSINTEvidence(report)
		return report
	default:
		return osint.Report{}
	}
}

func (s *Service) applyOSINT(ctx context.Context, domain string, result analysis.Result, report osint.Report, feedRevision string) analysis.Result {
	if s == nil || s.osint == nil || !report.ShouldBlock {
		return result
	}
	updated := s.osint.Apply(result, report)
	if updated.Verdict == result.Verdict && updated.Score == result.Score {
		return updated
	}

	modelRevision := s.ml.currentMLPolicyRevision()
	cacheKey := analysisCacheKey(domain, modelRevision)
	brandRevision, _ := s.currentBrandRevision(ctx)
	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		return s.redis.SetJSON(redisCtx, cacheKey, analysisCacheEntry{
			Result:           updated,
			FeedRevision:     feedRevision,
			BrandRevision:    brandRevision,
			AnalysisRevision: analysisAlgorithmRevision,
			ConfigRevision:   s.currentConfigRevision(),
			ModelRevision:    modelRevision,
			OSINTCheckedAt:   report.CheckedAt,
			AssessedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		}, s.ttlFor(updated.Verdict))
	})
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		logjson.Warn("analysis cache osint write failed", correlation.Fields(ctx, map[string]any{
			"service": "risk",
			"domain":  domain,
			"error":   err.Error(),
		}))
	}
	return updated
}

func (s *Service) recordOSINTEvidence(report osint.Report) {
	if s == nil || s.store == nil || !s.store.Enabled() || len(report.Evidence) == 0 {
		return
	}
	expiresAt := report.ExpiresAt
	if expiresAt == "" {
		expiresAt = time.Now().Add(6 * time.Hour).UTC().Format(time.RFC3339Nano)
	}
	items := make([]store.OSINTEvidence, 0, len(report.Evidence))
	for _, ev := range report.Evidence {
		items = append(items, store.OSINTEvidence{
			Domain:       ev.Domain,
			SourceURL:    ev.SourceURL,
			SourceTitle:  ev.SourceTitle,
			SourceType:   ev.SourceType,
			Confidence:   ev.Confidence,
			MatchedTerms: ev.MatchedTerms,
			RetrievedAt:  ev.RetrievedAt,
			ExpiresAt:    expiresAt,
		})
	}
	if err := s.store.ReplaceOSINTEvidence(context.Background(), report.Domain, items); err != nil {
		logjson.Warn("osint evidence store write failed", map[string]any{
			"service": "risk",
			"domain":  report.Domain,
			"error":   err.Error(),
		})
	}
}
