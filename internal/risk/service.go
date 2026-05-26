package risk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"safe-zone/internal/ai"
	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/config"
	"safe-zone/internal/correlation"
	"safe-zone/internal/feed"
	"safe-zone/internal/logjson"
	"safe-zone/internal/osint"
	"safe-zone/internal/store"
	"safe-zone/internal/tlsinspect"
	"safe-zone/internal/whois"
)

const recentAnalysisKey = "safe-zone:analysis:recent"
const defaultThreatFeedKey = "safe-zone:threat:feed"
const brandRevisionKey = "safe-zone:analysis:trusted-brands:revision"
const threatFeedReason = "matched local threat feed"
const analysisAlgorithmRevision = "2026-05-osint-v1"

type Options struct {
	Redis          *cache.Redis
	RedisTimeout   time.Duration
	TTLAllowed     time.Duration
	TTLSuspicious  time.Duration
	TTLBlocked     time.Duration
	RecentLimit    int64
	RecentTTL      time.Duration
	ThreatFeedKey  string
	AIProvider     string
	GeminiBaseURL  string
	GeminiAPIKey   string
	GeminiModel    string
	GeminiTimeout  time.Duration
	OllamaBaseURL  string
	OllamaModel    string
	OllamaTimeout  time.Duration
	WhitelistPath  string
	AnalysisConfig config.AnalysisConfig
	Store          *store.DB
	BrandCacheTTL  time.Duration
	// Enrichment (TLS + WHOIS)
	EnrichEnabled   bool
	EnrichTimeout   time.Duration
	EnrichQueueSize int
	// OSINT evidence lookup for API/dashboard paths.
	OSINT *osint.Service
}

type Service struct {
	redis            *cache.Redis
	redisTimeout     time.Duration
	ttlAllowed       time.Duration
	ttlSuspicious    time.Duration
	ttlBlocked       time.Duration
	recentLimit      int64
	recentTTL        time.Duration
	threatFeedKey    string
	feedRevisionKey  string
	ai               *ai.Client
	whitelist        *Whitelist
	analyzer         *analysis.Analyzer
	store            *store.DB
	brandStore       analysis.BrandStore
	enrichEnabled    bool
	enrichTimeout    time.Duration
	enrichQueue      chan enrichmentJob
	enrichDone       chan struct{}
	enrichWG         sync.WaitGroup
	enrichMu         sync.Mutex
	enrichInFlight   map[string]struct{}
	enrichmentLookup func(context.Context, string) enrichmentSignals
	osint            *osint.Service
}

type ClientInfo struct {
	IP       string `json:"ip"`
	ClientID string `json:"client_id"`
}

type Analysis struct {
	analysis.Result
	CacheHit   bool             `json:"cache_hit"`
	AnalyzedAt string           `json:"analyzed_at"`
	Evidence   []osint.Evidence `json:"evidence,omitempty"`
}

type Policy struct {
	Domain   string          `json:"domain"`
	Policy   string          `json:"policy"`
	Result   analysis.Result `json:"result"`
	CacheHit bool            `json:"cache_hit"`
}

type CacheStatus struct {
	Configured bool   `json:"configured"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
}

type analysisCacheEntry struct {
	Result           analysis.Result `json:"result"`
	FeedRevision     string          `json:"feed_revision,omitempty"`
	BrandRevision    string          `json:"brand_revision,omitempty"`
	AnalysisRevision string          `json:"analysis_revision,omitempty"`
	OSINTCheckedAt   string          `json:"osint_checked_at,omitempty"`
	EnrichedAt       string          `json:"enriched_at,omitempty"`
}

type enrichmentJob struct {
	Domain        string
	Result        analysis.Result
	FeedRevision  string
	BrandRevision string
}

type enrichmentSignals struct {
	DNSFailed bool
	TLS       tlsinspect.Result
	WHOIS     whois.Result
}

type AnalyzeOptions struct {
	IncludeEvidence bool
	ForceOSINT      bool
}

type osintLookupMode int

const (
	osintLookupNone osintLookupMode = iota
	osintLookupCachedOnly
	osintLookupOnDemand
)

func NewService(options Options) *Service {
	recentLimit := options.RecentLimit
	if recentLimit <= 0 {
		recentLimit = 25
	}
	threatFeedKey := options.ThreatFeedKey
	if threatFeedKey == "" {
		threatFeedKey = defaultThreatFeedKey
	}
	aiClient := ai.NewClient(ai.Config{
		Provider:      options.AIProvider,
		GeminiBaseURL: options.GeminiBaseURL,
		GeminiAPIKey:  options.GeminiAPIKey,
		GeminiModel:   options.GeminiModel,
		GeminiTimeout: options.GeminiTimeout,
		OllamaBaseURL: options.OllamaBaseURL,
		OllamaModel:   options.OllamaModel,
		OllamaTimeout: options.OllamaTimeout,
	})
	if !aiClient.Enabled() {
		aiClient = nil
	}

	wl := NewWhitelist(options.Store)
	if options.WhitelistPath != "" {
		_ = wl.LoadFromFile(options.WhitelistPath)
	} else if options.Store != nil && options.Store.Enabled() {
		_ = wl.LoadFromDB()
	}

	brandStore := analysis.BrandStore(store.NewBrandStore(
		options.Store,
		options.Redis,
		options.RedisTimeout,
		configDuration(options.BrandCacheTTL, 5*time.Minute),
	))

	enrichQueueSize := options.EnrichQueueSize
	if enrichQueueSize <= 0 {
		enrichQueueSize = 256
	}

	svc := &Service{
		redis:            options.Redis,
		redisTimeout:     options.RedisTimeout,
		ttlAllowed:       options.TTLAllowed,
		ttlSuspicious:    options.TTLSuspicious,
		ttlBlocked:       options.TTLBlocked,
		recentLimit:      recentLimit,
		recentTTL:        configDuration(options.RecentTTL, 24*time.Hour),
		threatFeedKey:    threatFeedKey,
		feedRevisionKey:  feed.RevisionKey(threatFeedKey),
		ai:               aiClient,
		whitelist:        wl,
		analyzer:         analysis.NewAnalyzerWithBrandStore(options.AnalysisConfig, brandStore),
		store:            options.Store,
		brandStore:       brandStore,
		enrichEnabled:    options.EnrichEnabled,
		enrichTimeout:    options.EnrichTimeout,
		enrichDone:       make(chan struct{}),
		enrichInFlight:   make(map[string]struct{}),
		enrichmentLookup: defaultEnrichmentLookup,
		osint:            options.OSINT,
	}
	if svc.enrichEnabled && svc.redis != nil && svc.redis.Enabled() && svc.enrichTimeout > 0 {
		svc.enrichQueue = make(chan enrichmentJob, enrichQueueSize)
		svc.enrichWG.Add(1)
		go svc.enrichmentWorker()
	}
	return svc
}

func configDuration(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}

func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	var redisErr, storeErr error
	if s.enrichDone != nil {
		close(s.enrichDone)
		s.enrichWG.Wait()
	}
	if s.redis != nil {
		redisErr = s.redis.Close()
	}
	if s.store != nil {
		storeErr = s.store.Close()
	}
	return errors.Join(redisErr, storeErr)
}

func (s *Service) Analyze(ctx context.Context, domain string, client ClientInfo) Analysis {
	return s.AnalyzeWithOptions(ctx, domain, client, AnalyzeOptions{})
}

func (s *Service) AnalyzeWithOptions(ctx context.Context, domain string, client ClientInfo, options AnalyzeOptions) Analysis {
	normalized, err := analysis.NormalizeDomain(domain)
	var result analysis.Result
	var cacheHit bool
	var evidence []osint.Evidence

	if err != nil {
		result = s.analyzer.Analyze(domain)
		cacheHit = false
	} else {
		// Get group
		var group *store.ClientGroup
		if s.store != nil && s.store.Enabled() {
			g, err := s.store.GetGroupForClient(client.IP, client.ClientID)
			if err == nil {
				group = g
			}
		}
		if group == nil {
			group = &store.ClientGroup{ID: 1, Name: "default", StrictMalware: true}
		}

		// 1. Check Overrides
		if s.store != nil && s.store.Enabled() {
			override, err := s.store.GetEffectiveOverride(group.ID, normalized)
			if err == nil && override != nil {
				verdict := analysis.VerdictSafe
				score := 0
				if override.Action == "block" {
					verdict = analysis.VerdictMalicious
					score = 100
				}
				reason := fmt.Sprintf("admin override: %s", override.Action)
				if override.Reason != "" {
					reason = fmt.Sprintf("admin override: %s (%s)", override.Action, override.Reason)
				}
				result = analysis.Result{
					Domain:     normalized,
					Verdict:    verdict,
					Confidence: 1.0,
					Score:      score,
					Reasons:    []string{reason},
					Category:   analysis.ClassifyCategory(normalized),
				}
				cacheHit = false
			}
		}

		// 2. Check Whitelist
		if result.Domain == "" && s.whitelist.IsAllowed(normalized) {
			result = analysis.Result{
				Domain:     normalized,
				Verdict:    analysis.VerdictSafe,
				Confidence: 1.0,
				Score:      0,
				Reasons:    []string{"whitelisted"},
				Category:   "uncategorized",
			}
			cacheHit = false
		}

		if result.Domain == "" {
			// 3. Fallback to threat assessment
			result, cacheHit, evidence = s.analyze(ctx, normalized, osintLookupOnDemand, options.ForceOSINT)
		}
	}

	a := Analysis{
		Result:     result,
		CacheHit:   cacheHit,
		AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if options.IncludeEvidence {
		a.Evidence = evidence
	}
	s.recordTelemetry(a, client)
	return a
}

func (s *Service) Policy(ctx context.Context, domain string, client ClientInfo) Policy {
	normalized, err := analysis.NormalizeDomain(domain)
	if err != nil {
		res := s.analyzer.Analyze(domain)
		return Policy{
			Domain:   domain,
			Policy:   "block",
			Result:   res,
			CacheHit: false,
		}
	}

	// 1. Get Group for Client
	var group *store.ClientGroup
	if s.store != nil && s.store.Enabled() {
		g, err := s.store.GetGroupForClient(client.IP, client.ClientID)
		if err == nil {
			group = g
		}
	}
	if group == nil {
		group = &store.ClientGroup{
			ID:             1,
			Name:           "default",
			StrictMalware:  true,
			StrictPhishing: false,
		}
	}

	// 2. Check Overrides
	if s.store != nil && s.store.Enabled() {
		override, err := s.store.GetEffectiveOverride(group.ID, normalized)
		if err == nil && override != nil {
			policyAction := override.Action
			verdict := analysis.VerdictSafe
			score := 0
			if policyAction == "block" {
				verdict = analysis.VerdictMalicious
				score = 100
			}
			reason := fmt.Sprintf("admin override: %s", policyAction)
			if override.Reason != "" {
				reason = fmt.Sprintf("admin override: %s (%s)", policyAction, override.Reason)
			}
			policyResult := Policy{
				Domain: normalized,
				Policy: policyAction,
				Result: analysis.Result{
					Domain:     normalized,
					Verdict:    verdict,
					Confidence: 1.0,
					Score:      score,
					Reasons:    []string{reason},
					Category:   analysis.ClassifyCategory(normalized),
				},
				CacheHit: false,
			}
			s.recordTelemetry(Analysis{
				Result:     policyResult.Result,
				CacheHit:   false,
				AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
			}, client)
			return policyResult
		}
	}

	// 3. Check Whitelist
	if s.whitelist.IsAllowed(normalized) {
		policyResult := Policy{
			Domain: normalized,
			Policy: "allow",
			Result: analysis.Result{
				Domain:     normalized,
				Verdict:    analysis.VerdictSafe,
				Confidence: 1.0,
				Score:      0,
				Reasons:    []string{"whitelisted"},
				Category:   "uncategorized",
			},
			CacheHit: false,
		}
		s.recordTelemetry(Analysis{
			Result:     policyResult.Result,
			CacheHit:   false,
			AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
		}, client)
		return policyResult
	}

	// 4. Get Threat Assessment
	result, cacheHit, _ := s.analyze(ctx, normalized, osintLookupCachedOnly, false)

	// 5. Dynamic enforcement
	policy := "allow"
	if result.Verdict == analysis.VerdictMalicious && group.StrictMalware {
		policy = "block"
	}

	if group.StrictPhishing {
		isPhishing := false
		for _, r := range result.Reasons {
			if strings.Contains(strings.ToLower(r), "phishing") {
				isPhishing = true
				break
			}
		}
		if result.Score >= 40 && (isPhishing || result.Category == "phishing") {
			policy = "block"
		}
	}

	if len(group.BlockCategories) > 0 && result.Category != "" && result.Category != "uncategorized" {
		for _, blockedCat := range group.BlockCategories {
			if strings.ToLower(strings.TrimSpace(blockedCat)) == strings.ToLower(result.Category) {
				policy = "block"
				break
			}
		}
	}

	policyResult := Policy{
		Domain:   result.Domain,
		Policy:   policy,
		Result:   result,
		CacheHit: cacheHit,
	}

	s.recordTelemetry(Analysis{
		Result:     result,
		CacheHit:   cacheHit,
		AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}, client)

	return policyResult
}

func (s *Service) RecordRecent(ctx context.Context, item Analysis) {
	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		if err := s.redis.PushJSON(redisCtx, recentAnalysisKey, item, s.recentLimit); err != nil {
			return err
		}
		if s.recentTTL > 0 {
			return s.redis.Expire(redisCtx, recentAnalysisKey, s.recentTTL)
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
	recent := make([]Analysis, 0, s.recentLimit)
	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		return s.redis.ListJSON(redisCtx, recentAnalysisKey, 0, s.recentLimit-1, func(data []byte) error {
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

	return CacheStatus{
		Configured: true,
		Status:     "ok",
	}
}

func (s *Service) analyze(ctx context.Context, domain string, lookupMode osintLookupMode, forceOSINT bool) (analysis.Result, bool, []osint.Evidence) {
	normalized, err := analysis.NormalizeDomain(domain)
	if err != nil {
		return s.analyzer.Analyze(domain), false, nil
	}

	// 1. Check Cache
	cacheKey := fmt.Sprintf("safe-zone:analysis:%s", normalized)
	currentRevision := s.currentFeedRevision(ctx)
	currentBrandRevision := s.currentBrandRevision(ctx)
	var cached analysis.Result
	var cachedEntry analysisCacheEntry
	err = s.withRedis(ctx, func(redisCtx context.Context) error {
		var entry analysisCacheEntry
		found, err := s.redis.GetJSON(redisCtx, cacheKey, &entry)
		if err == nil && found && entry.Result.Domain != "" {
			if entry.AnalysisRevision == analysisAlgorithmRevision &&
				(currentRevision == "" || entry.FeedRevision == currentRevision) &&
				(currentBrandRevision == "" || entry.BrandRevision == currentBrandRevision) {
				cached = entry.Result
				cachedEntry = entry
				return nil
			}
			return nil
		}

		var legacy analysis.Result
		found, err = s.redis.GetJSON(redisCtx, cacheKey, &legacy)
		if err != nil || !found {
			return err
		}
		return nil
	})
	if err == nil && cached.Domain != "" {
		if shouldEnqueueEnrichment(cached) && cachedEntryNeedsEnrichment(cachedEntry) {
			s.enqueueEnrichment(ctx, enrichmentJob{
				Domain:        normalized,
				Result:        cached,
				FeedRevision:  cachedEntry.FeedRevision,
				BrandRevision: cachedEntry.BrandRevision,
			})
		}
		report := s.lookupOSINT(ctx, normalized, cached, lookupMode, forceOSINT)
		updated := s.applyOSINT(ctx, normalized, cached, report, currentRevision)
		return updated, true, report.Evidence
	}
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		logjson.Warn("analysis cache read failed", correlation.Fields(ctx, map[string]any{
			"service": "risk",
			"domain":  normalized,
			"error":   err.Error(),
		}))
	}

	// 2. Check Threat Feed
	result := s.feedResult(ctx, normalized)
	if result.Domain == "" {
		// 3. Lexical Analysis
		result = s.analyzer.Analyze(normalized)
	}
	// 4. AI Refinement
	result = s.refineWithAI(ctx, result)
	if shouldEnqueueEnrichment(result) {
		s.enqueueEnrichment(ctx, enrichmentJob{
			Domain:        normalized,
			Result:        result,
			FeedRevision:  currentRevision,
			BrandRevision: currentBrandRevision,
		})
	}
	// 5. OSINT public-warning evidence. API/dashboard can fetch on demand;
	// resolver policy uses cached evidence only via lookupMode.
	report := s.lookupOSINT(ctx, normalized, result, lookupMode, forceOSINT)
	result = s.applyOSINT(ctx, normalized, result, report, currentRevision)

	// Cache the final result
	err = s.withRedis(ctx, func(redisCtx context.Context) error {
		return s.redis.SetJSON(redisCtx, cacheKey, analysisCacheEntry{
			Result:           result,
			FeedRevision:     currentRevision,
			BrandRevision:    currentBrandRevision,
			AnalysisRevision: analysisAlgorithmRevision,
		}, s.ttlFor(result.Verdict))
	})
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		logjson.Warn("analysis cache write failed", correlation.Fields(ctx, map[string]any{
			"service": "risk",
			"domain":  normalized,
			"error":   err.Error(),
		}))
	}

	return result, false, report.Evidence
}

func (s *Service) feedResult(ctx context.Context, domain string) analysis.Result {
	matched, err := s.matchThreatFeed(ctx, domain)
	if err != nil {
		if !errors.Is(err, cache.ErrDisabled) {
			logjson.Warn("threat feed lookup failed", correlation.Fields(ctx, map[string]any{
				"service": "risk",
				"domain":  domain,
				"error":   err.Error(),
			}))
		}
		return analysis.Result{}
	}
	if !matched {
		return analysis.Result{}
	}

	return analysis.Result{
		Domain:     domain,
		Verdict:    analysis.VerdictMalicious,
		Confidence: 1,
		Score:      100,
		Reasons:    []string{threatFeedReason},
	}
}

func (s *Service) refineWithAI(ctx context.Context, current analysis.Result) analysis.Result {
	if s == nil || s.ai == nil {
		return current
	}
	if current.Verdict != analysis.VerdictSuspicious {
		return current
	}

	aiResult, err := s.ai.Refine(ctx, current.Domain, current)
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

	cacheKey := fmt.Sprintf("safe-zone:analysis:%s", domain)
	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		return s.redis.SetJSON(redisCtx, cacheKey, analysisCacheEntry{
			Result:           updated,
			FeedRevision:     feedRevision,
			BrandRevision:    s.currentBrandRevision(ctx),
			AnalysisRevision: analysisAlgorithmRevision,
			OSINTCheckedAt:   report.CheckedAt,
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
	if err := s.store.ReplaceOSINTEvidence(report.Domain, items); err != nil {
		logjson.Warn("osint evidence store write failed", map[string]any{
			"service": "risk",
			"domain":  report.Domain,
			"error":   err.Error(),
		})
	}
}

func shouldEnqueueEnrichment(result analysis.Result) bool {
	return result.Domain != "" && result.Score >= 20 && result.Score < 70
}

func cachedEntryNeedsEnrichment(entry analysisCacheEntry) bool {
	return entry.EnrichedAt == ""
}

func (s *Service) enqueueEnrichment(ctx context.Context, job enrichmentJob) {
	if s == nil || !s.enrichEnabled || s.enrichQueue == nil || s.enrichTimeout <= 0 {
		return
	}
	s.enrichMu.Lock()
	if _, ok := s.enrichInFlight[job.Domain]; ok {
		s.enrichMu.Unlock()
		return
	}
	s.enrichInFlight[job.Domain] = struct{}{}
	s.enrichMu.Unlock()

	select {
	case s.enrichQueue <- job:
	case <-ctx.Done():
		s.clearEnrichmentInFlight(job.Domain)
	default:
		s.clearEnrichmentInFlight(job.Domain)
		logjson.Warn("enrichment queue full; skipping background job", correlation.Fields(ctx, map[string]any{
			"service": "risk",
			"domain":  job.Domain,
		}))
	}
}

func (s *Service) clearEnrichmentInFlight(domain string) {
	s.enrichMu.Lock()
	delete(s.enrichInFlight, domain)
	s.enrichMu.Unlock()
}

func (s *Service) enrichmentWorker() {
	defer s.enrichWG.Done()
	for {
		select {
		case <-s.enrichDone:
			return
		case job := <-s.enrichQueue:
			s.processEnrichmentJob(job)
			s.clearEnrichmentInFlight(job.Domain)
		}
	}
}

func (s *Service) processEnrichmentJob(job enrichmentJob) {
	if s == nil || s.redis == nil || !s.redis.Enabled() {
		return
	}
	if current := s.currentFeedRevision(context.Background()); current != "" && job.FeedRevision != "" && current != job.FeedRevision {
		return
	}
	if current := s.currentBrandRevision(context.Background()); current != "" && job.BrandRevision != "" && current != job.BrandRevision {
		return
	}

	enrichCtx, cancel := context.WithTimeout(context.Background(), s.enrichTimeout)
	defer cancel()

	signals := s.enrichmentLookup(enrichCtx, job.Domain)
	enriched := job.Result
	applyEnrichmentSignals(&enriched, signals)

	cacheKey := fmt.Sprintf("safe-zone:analysis:%s", job.Domain)
	err := s.withRedis(context.Background(), func(redisCtx context.Context) error {
		return s.redis.SetJSON(redisCtx, cacheKey, analysisCacheEntry{
			Result:           enriched,
			FeedRevision:     job.FeedRevision,
			BrandRevision:    job.BrandRevision,
			AnalysisRevision: analysisAlgorithmRevision,
			EnrichedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		}, s.ttlFor(enriched.Verdict))
	})
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		logjson.Warn("background enrichment cache write failed", map[string]any{
			"service": "risk",
			"domain":  job.Domain,
			"error":   err.Error(),
		})
	}
}

func defaultEnrichmentLookup(ctx context.Context, domain string) enrichmentSignals {
	var (
		dnsFailed   bool
		tlsResult   tlsinspect.Result
		whoisResult whois.Result
		wg          sync.WaitGroup
	)
	wg.Add(3)
	go func() {
		defer wg.Done()
		apex := whois.RegisteredDomain(domain)
		if apex == "" {
			return
		}
		nsCtx, cancel := context.WithTimeout(ctx, minDuration(2*time.Second, enrichContextTimeout(ctx, 2*time.Second)))
		defer cancel()
		if _, err := net.DefaultResolver.LookupNS(nsCtx, apex); err != nil {
			dnsFailed = true
		}
	}()
	go func() {
		defer wg.Done()
		tlsResult = tlsinspect.Inspect(ctx, domain)
	}()
	go func() {
		defer wg.Done()
		whoisResult = whois.Lookup(ctx, domain)
	}()
	wg.Wait()
	return enrichmentSignals{
		DNSFailed: dnsFailed,
		TLS:       tlsResult,
		WHOIS:     whoisResult,
	}
}

func applyEnrichmentSignals(result *analysis.Result, signals enrichmentSignals) {
	if result == nil {
		return
	}
	if signals.DNSFailed {
		if result.Score < 75 {
			result.Score = 75
		}
		result.Reasons = append(result.Reasons, "domain is not registered or resolving (NXDOMAIN)")
	}
	result.Score += signals.TLS.Score + signals.WHOIS.Score
	result.Reasons = append(result.Reasons, signals.TLS.Reasons...)
	result.Reasons = append(result.Reasons, signals.WHOIS.Reasons...)
	if result.Score > 100 {
		result.Score = 100
	}
	switch {
	case result.Score >= 70:
		result.Verdict = analysis.VerdictMalicious
	case result.Score >= 40:
		result.Verdict = analysis.VerdictSuspicious
	default:
		result.Verdict = analysis.VerdictSafe
	}
	result.Confidence = math.Min(1, 0.45+float64(result.Score)/120)
}

func enrichContextTimeout(ctx context.Context, fallback time.Duration) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return fallback
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return fallback
	}
	return remaining
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func (s *Service) matchThreatFeed(parent context.Context, domain string) (bool, error) {
	candidates := threatFeedCandidates(domain)
	return s.matchAnyThreatFeedCandidate(parent, candidates)
}

func (s *Service) matchAnyThreatFeedCandidate(parent context.Context, candidates []string) (bool, error) {
	var matched bool
	err := s.withRedis(parent, func(ctx context.Context) error {
		for _, candidate := range candidates {
			exists, err := s.redis.SetIsMember(ctx, s.threatFeedKey, candidate)
			if err != nil {
				return err
			}
			if exists {
				matched = true
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return false, err
	}

	return matched, nil
}

func threatFeedCandidates(domain string) []string {
	parts := strings.Split(domain, ".")
	candidates := make([]string, 0, len(parts))
	for i := 0; i < len(parts); i++ {
		candidate := strings.Join(parts[i:], ".")
		if candidate != "" {
			candidates = append(candidates, candidate)
		}
	}

	return candidates
}

func (s *Service) ttlFor(verdict analysis.Verdict) time.Duration {
	switch verdict {
	case analysis.VerdictMalicious:
		return s.ttlBlocked
	case analysis.VerdictSuspicious:
		return s.ttlSuspicious
	default:
		return s.ttlAllowed
	}
}

func (s *Service) withRedis(parent context.Context, fn func(context.Context) error) error {
	if s == nil || s.redis == nil || !s.redis.Enabled() {
		return cache.ErrDisabled
	}

	ctx, cancel := context.WithTimeout(parent, s.redisTimeout)
	defer cancel()
	return fn(ctx)
}

func (s *Service) currentFeedRevision(ctx context.Context) string {
	if s == nil || s.feedRevisionKey == "" {
		return ""
	}

	var revision string
	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		value, err := s.redis.GetString(redisCtx, s.feedRevisionKey)
		if err != nil {
			return err
		}
		revision = value
		return nil
	})
	if err != nil {
		return ""
	}
	return revision
}

func (s *Service) currentBrandRevision(ctx context.Context) string {
	if s == nil {
		return ""
	}
	var revision string
	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		value, err := s.redis.GetString(redisCtx, brandRevisionKey)
		if err != nil {
			return err
		}
		revision = value
		return nil
	})
	if err != nil {
		return ""
	}
	return revision
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

// --- Local Overrides ---

func (s *Service) checkOverride(domain string) *analysis.Result {
	if s.store == nil {
		return nil
	}
	override, err := s.store.GetOverride(domain)
	if err != nil {
		logjson.Warn("override check failed", map[string]any{
			"service": "risk",
			"domain":  domain,
			"error":   err.Error(),
		})
		return nil // fail-open
	}
	if override == nil {
		return nil
	}

	switch override.Action {
	case "block":
		reason := "admin override: block"
		if override.Reason != "" {
			reason = fmt.Sprintf("admin override: block (%s)", override.Reason)
		}
		return &analysis.Result{
			Domain:     domain,
			Verdict:    analysis.VerdictMalicious,
			Confidence: 1.0,
			Score:      100,
			Reasons:    []string{reason},
		}
	case "allow":
		reason := "admin override: allow"
		if override.Reason != "" {
			reason = fmt.Sprintf("admin override: allow (%s)", override.Reason)
		}
		return &analysis.Result{
			Domain:     domain,
			Verdict:    analysis.VerdictSafe,
			Confidence: 1.0,
			Score:      0,
			Reasons:    []string{reason},
		}
	}
	return nil
}

// --- Telemetry ---

func (s *Service) recordTelemetry(a Analysis, client ClientInfo) {
	if s.store == nil {
		return
	}
	s.store.RecordAnalysis(store.TelemetryEntry{
		Domain:     a.Result.Domain,
		Verdict:    string(a.Result.Verdict),
		Score:      a.Result.Score,
		Confidence: a.Result.Confidence,
		Reasons:    a.Result.Reasons,
		CacheHit:   a.CacheHit,
		Source:     inferSource(a),
		AnalyzedAt: a.AnalyzedAt,
		ClientIP:   client.IP,
		ClientID:   client.ClientID,
	})
}

func inferSource(a Analysis) string {
	if a.CacheHit {
		return "cache"
	}
	for _, r := range a.Result.Reasons {
		if strings.HasPrefix(r, "admin override") {
			return "override"
		}
		if r == "whitelisted" {
			return "whitelist"
		}
		if r == threatFeedReason {
			return "feed"
		}
	}
	return "lexical"
}

// --- Store API wrappers ---

// ListOverrides returns all local overrides, optionally filtered by action.
func (s *Service) ListOverrides(action string) ([]store.Override, error) {
	if s.store == nil {
		return nil, nil
	}
	return s.store.ListOverrides(action)
}

// UpsertOverride creates or updates a local override for a domain.
func (s *Service) UpsertOverride(domain, action, reason string) error {
	if s.store == nil {
		return fmt.Errorf("store not configured")
	}
	normalized, err := analysis.NormalizeDomain(domain)
	if err != nil {
		return fmt.Errorf("invalid domain: %w", err)
	}
	return s.store.UpsertOverride(normalized, action, reason)
}

// DeleteOverride removes a local override for a domain.
func (s *Service) DeleteOverride(domain string) error {
	if s.store == nil {
		return fmt.Errorf("store not configured")
	}
	normalized, err := analysis.NormalizeDomain(domain)
	if err != nil {
		return fmt.Errorf("invalid domain: %w", err)
	}
	return s.store.DeleteOverride(normalized)
}

func (s *Service) ListBrands(ctx context.Context) ([]analysis.Brand, error) {
	if s == nil || s.brandStore == nil {
		return nil, fmt.Errorf("brand store not configured")
	}
	return s.brandStore.ListBrands(ctx)
}

func (s *Service) GetBrand(ctx context.Context, id int64) (analysis.Brand, error) {
	if s == nil || s.brandStore == nil {
		return analysis.Brand{}, fmt.Errorf("brand store not configured")
	}
	return s.brandStore.GetBrand(ctx, id)
}

func (s *Service) CreateBrand(ctx context.Context, brand analysis.Brand) (analysis.Brand, error) {
	if s == nil || s.brandStore == nil {
		return analysis.Brand{}, fmt.Errorf("brand store not configured")
	}
	created, err := s.brandStore.CreateBrand(ctx, brand)
	if err != nil {
		return analysis.Brand{}, err
	}
	s.bumpBrandRevision(ctx)
	return created, nil
}

func (s *Service) UpdateBrand(ctx context.Context, id int64, brand analysis.Brand) (analysis.Brand, error) {
	if s == nil || s.brandStore == nil {
		return analysis.Brand{}, fmt.Errorf("brand store not configured")
	}
	updated, err := s.brandStore.UpdateBrand(ctx, id, brand)
	if err != nil {
		return analysis.Brand{}, err
	}
	s.bumpBrandRevision(ctx)
	return updated, nil
}

func (s *Service) DeleteBrand(ctx context.Context, id int64) error {
	if s == nil || s.brandStore == nil {
		return fmt.Errorf("brand store not configured")
	}
	if err := s.brandStore.DeleteBrand(ctx, id); err != nil {
		return err
	}
	s.bumpBrandRevision(ctx)
	return nil
}

// TelemetryRecent returns recent telemetry entries.
func (s *Service) TelemetryRecent(limit, offset int) ([]store.TelemetryEntry, error) {
	if s.store == nil {
		return nil, nil
	}
	return s.store.QueryRecent(limit, offset)
}

// TelemetryStats returns aggregate telemetry statistics.
func (s *Service) TelemetryStats(since time.Time) (store.Stats, error) {
	if s.store == nil {
		return store.Stats{}, nil
	}
	return s.store.QueryStats(since)
}

// --- Accessors for Agent Engine ---

// StoreDB returns the underlying SQLite store, or nil if not configured.
func (s *Service) StoreDB() *store.DB {
	if s == nil {
		return nil
	}
	return s.store
}

// AIClient returns the Gemini AI client, or nil if not configured.
func (s *Service) AIClient() *ai.Client {
	if s == nil {
		return nil
	}
	return s.ai
}

// RedisCache returns the Redis cache client, or nil if not configured.
func (s *Service) RedisCache() *cache.Redis {
	if s == nil {
		return nil
	}
	return s.redis
}

// OSINT returns the public-evidence lookup service, or nil when disabled.
func (s *Service) OSINT() *osint.Service {
	if s == nil {
		return nil
	}
	return s.osint
}

func (s *Service) OSINTEvidence(ctx context.Context, domain string, force bool) (osint.Report, error) {
	if s == nil || s.osint == nil || !s.osint.Enabled() {
		return osint.Report{Domain: domain, Enabled: false}, nil
	}
	if !force {
		if report, ok := s.osint.Cached(ctx, domain); ok {
			report.CacheHit = true
			return report, nil
		}
		if report, ok := s.storedOSINTEvidence(domain); ok {
			return report, nil
		}
	}
	return s.osint.Lookup(ctx, domain, force)
}

func (s *Service) storedOSINTEvidence(domain string) (osint.Report, bool) {
	if s == nil || s.store == nil || !s.store.Enabled() {
		return osint.Report{}, false
	}
	normalized, err := analysis.NormalizeDomain(domain)
	if err != nil {
		return osint.Report{}, false
	}
	items, err := s.store.ListOSINTEvidence(normalized, time.Now())
	if err != nil || len(items) == 0 {
		return osint.Report{}, false
	}
	evidence := make([]osint.Evidence, 0, len(items))
	for _, item := range items {
		evidence = append(evidence, osint.Evidence{
			Domain:       item.Domain,
			SourceURL:    item.SourceURL,
			SourceTitle:  item.SourceTitle,
			SourceType:   item.SourceType,
			Confidence:   item.Confidence,
			MatchedTerms: item.MatchedTerms,
			RetrievedAt:  item.RetrievedAt,
		})
	}
	return osint.Report{
		Domain:      normalized,
		Enabled:     true,
		CacheHit:    true,
		ShouldBlock: osint.HasStrongWarning(evidence),
		Evidence:    evidence,
		CheckedAt:   evidence[0].RetrievedAt,
		ExpiresAt:   items[0].ExpiresAt,
		VerdictImpact: func() string {
			if osint.HasStrongWarning(evidence) {
				return "escalate_malicious"
			}
			return ""
		}(),
	}, true
}

// Whitelist returns the whitelist client.
func (s *Service) Whitelist() *Whitelist {
	if s == nil {
		return nil
	}
	return s.whitelist
}
