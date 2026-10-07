package risk

import (
	"context"
	"errors"
	"fmt"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
	"safe-zone/internal/osint"
	"safe-zone/internal/store"
)

// resolvedLayer is the outcome of one of the administrative layers that both
// decision paths consult: an admin override or a whitelist match.
//
// The two paths build identical Results and identical Decisions from these
// layers, and each had grown its own copy of the construction. The Assessment
// bookkeeping stays with the caller on purpose: Analyze appends its layer list
// eagerly before consulting anything, while Policy appends per branch as it
// returns, and Assessment is serialized into API responses and telemetry. Sharing
// that would change output, so only the computation is shared here.
type resolvedLayer struct {
	result   analysis.Result
	cacheHit bool
	decision *PolicyDecision
}

// resolveClientGroup returns the policy group for a client, defaulting when the
// store is unavailable or the lookup fails.
//
// Client-supplied identifiers (DoH client_id) are unauthenticated, so policy is
// derived from the trusted client IP only. The request context bounds this lookup
// so a disconnected caller stops consuming database work.
func (s *Service) resolveClientGroup(ctx context.Context, client ClientInfo, t *layerTimer) *store.ClientGroup {
	var group *store.ClientGroup
	if s.store != nil && s.store.Enabled() {
		var g *store.ClientGroup
		var groupErr error
		t.measure(LayerClientGroup, func() {
			g, groupErr = s.store.GetGroupForClient(ctx, client.IP, client.ClientID, false)
		})
		if groupErr == nil {
			group = g
		}
	}
	if group == nil {
		group = &store.ClientGroup{ID: 1, Name: "default", StrictMalware: true}
	}
	return group
}

// resolveOverride consults the administrative override chain. It returns nil when
// no override applies.
//
// A lookup error resolves to "no override" rather than propagating: the layer is
// fail-open by design so a transient store failure cannot block every domain for
// every client. lookupEffectiveOverride counts and publishes those failures.
func (s *Service) resolveOverride(ctx context.Context, group *store.ClientGroup, normalized string, t *layerTimer) *resolvedLayer {
	if s.store == nil || !s.store.Enabled() {
		return nil
	}
	var override *store.Override
	t.measure(LayerOverride, func() {
		var overrideErr error
		override, overrideErr = s.lookupEffectiveOverride(ctx, group.ID, normalized)
		if overrideErr != nil {
			override = nil
		}
	})
	if override == nil {
		return nil
	}

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
	return &resolvedLayer{
		result: analysis.Result{
			Domain:     normalized,
			Verdict:    verdict,
			Confidence: 1.0,
			Score:      score,
			Reasons:    []string{reason},
			Category:   analysis.ClassifyCategory(normalized),
		},
		cacheHit: false,
		decision: adminPolicyDecision(override.Action),
	}
}

// resolveWhitelist consults the allowlist. It returns nil when the domain is not
// allowlisted.
func (s *Service) resolveWhitelist(ctx context.Context, normalized string, t *layerTimer) *resolvedLayer {
	whitelisted := false
	t.measure(LayerWhitelist, func() {
		whitelisted = s.whitelist.IsAllowed(ctx, normalized)
	})
	if !whitelisted {
		return nil
	}
	return &resolvedLayer{
		result: analysis.Result{
			Domain:     normalized,
			Verdict:    analysis.VerdictSafe,
			Confidence: 1.0,
			Score:      0,
			Reasons:    []string{"whitelisted"},
			Category:   "uncategorized",
		},
		cacheHit: false,
		decision: allowlistPolicyDecision(),
	}
}

func (s *Service) Analyze(ctx context.Context, domain string, client ClientInfo) Analysis {
	return s.AnalyzeWithOptions(ctx, domain, client, AnalyzeOptions{})
}

func (s *Service) AnalyzeWithOptions(ctx context.Context, domain string, client ClientInfo, options AnalyzeOptions) Analysis {
	s.urlMLTelemetry.analyzeRequests.Add(1)
	if options.URLContext == nil {
		s.urlMLTelemetry.noteMissingContext(options.MissingContextReason)
	}
	normalized, err := analysis.NormalizeDomain(domain)
	var result analysis.Result
	var cacheHit bool
	var evidence []osint.Evidence
	var decision *PolicyDecision
	assess := newDomainAssessment()
	decisionID := decisionIDFor(ctx)
	var preTimer layerTimer

	if err != nil {
		result = s.analyzeLexical(domain)
		cacheHit = false
		assess.Evaluated = append(assess.Evaluated, LayerIdentity)
		assess.Skipped = append(assess.Skipped, LayerOverride, LayerWhitelist,
			LayerAdblock, LayerGroupPolicy)
		assess.Skipped = append(assess.Skipped, engineSkippedLayers()...)
		assess.Timings = preTimer.timings
	} else {
		group := s.resolveClientGroup(ctx, client, &preTimer)

		assess.Evaluated = append(assess.Evaluated, LayerIdentity, LayerOverride)
		// 1. Check Overrides
		if override := s.resolveOverride(ctx, group, normalized, &preTimer); override != nil {
			result = override.result
			cacheHit = override.cacheHit
			decision = override.decision
			assess.Skipped = append(assess.Skipped, LayerWhitelist, LayerAdblock)
			assess.Skipped = append(assess.Skipped, engineSkippedLayers()...)
		}

		// 2. Check Whitelist
		if result.Domain == "" {
			if allow := s.resolveWhitelist(ctx, normalized, &preTimer); allow != nil {
				result = allow.result
				cacheHit = allow.cacheHit
				decision = allow.decision
				assess.Evaluated = append(assess.Evaluated, LayerWhitelist)
				assess.Skipped = append(assess.Skipped, LayerAdblock)
				assess.Skipped = append(assess.Skipped, engineSkippedLayers()...)
			}
		}

		if result.Domain == "" {
			// 2.5 Check Adblock Trie
			adTrie := s.adblockTrie.Load()
			assess.Evaluated = append(assess.Evaluated, LayerWhitelist, LayerAdblock)
			if s.isAdblockEnabled() && adTrie != nil && adTrie.Match(normalized) {
				if s.policySemantics == PolicySemanticsLegacy {
					result = analysis.Result{
						Domain:     normalized,
						Verdict:    analysis.VerdictMalicious,
						Confidence: 1.0,
						Score:      100,
						Reasons:    []string{"adblock"},
						Category:   "adware",
					}
					cacheHit = false
					decision = legacyPolicyDecision()
					assess.Skipped = append(assess.Skipped, engineSkippedLayers()...)
					assess.Skipped = append(assess.Skipped, skippedLayer("security_assessment", SkipLegacyFused))
				}
				// Separated semantics: an adblock match is content-policy
				// evidence, not security evidence. The security pipeline below
				// still runs so the verdict only reflects independent signals.
			}
		}

		if result.Domain == "" {
			// 3. Fallback to threat assessment
			var engineAssess Assessment
			result, cacheHit, evidence, engineAssess = s.analyze(ctx, normalized, osintLookupOnDemand, options.ForceOSINT)
			assess.Evaluated = prependLayers(engineAssess.Evaluated,
				[]string{LayerIdentity, LayerOverride, LayerWhitelist, LayerAdblock})
			assess.Skipped = engineAssess.Skipped
			assess.Timings = engineAssess.Timings
			assess.Feed = engineAssess.Feed
		}
	}

	a := Analysis{
		Result:     result,
		CacheHit:   cacheHit,
		AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Decision:   decision,
		DecisionID: decisionID,
		Assessment: assess,
	}
	a.Assessment.Timings = mergeTimings(preTimer.timings, assess.Timings)
	if options.IncludeEvidence {
		a.Evidence = evidence
	}
	if options.URLContext != nil {
		a.URLML = s.observeURLML(ctx, normalized, result.Verdict, *options.URLContext)
		a.Assessment.Evaluated = append(a.Assessment.Evaluated, LayerURLML)
	} else {
		a.Assessment.Skipped = append(a.Assessment.Skipped, skippedLayer(LayerURLML, SkipNoURLContext))
	}
	s.recordTelemetry(a, client)
	return a
}

func analysisCacheKey(domain, modelRevision string) string {
	base := fmt.Sprintf("safe-zone:analysis:%s", domain)
	if modelRevision == "" {
		return base
	}
	return base + ":model:" + modelRevision
}

func (s *Service) analyze(ctx context.Context, domain string, lookupMode osintLookupMode, forceOSINT bool) (analysis.Result, bool, []osint.Evidence, Assessment) {
	normalized, err := analysis.NormalizeDomain(domain)
	if err != nil {
		return s.analyzeLexical(domain), false, nil, newDomainAssessment()
	}

	// 1. Check Cache
	var timer layerTimer
	modelRevision := s.currentMLPolicyRevision()
	cacheKey := analysisCacheKey(normalized, modelRevision)
	currentRevision, feedKnown := s.currentFeedRevision(ctx)
	currentBrandRevision, brandKnown := s.currentBrandRevision(ctx)
	currentConfigRevision := s.currentConfigRevision()
	epoch := cacheEpoch{
		AnalysisRevision: analysisAlgorithmRevision,
		ConfigRevision:   currentConfigRevision,
		ModelRevision:    modelRevision,
		FeedRevision:     currentRevision,
		FeedKnown:        feedKnown,
		BrandRevision:    currentBrandRevision,
		BrandKnown:       brandKnown,
	}
	var cached analysis.Result
	var cachedEntry analysisCacheEntry
	timer.measure(LayerResultCache, func() {
		err = s.withRedis(ctx, func(redisCtx context.Context) error {
			var entry analysisCacheEntry
			found, err := s.redis.GetJSON(redisCtx, cacheKey, &entry)
			if err == nil && found && entryMatchesRevision(entry, epoch) {
				cached = entry.Result
				cachedEntry = entry
				return nil
			}

			var legacy analysis.Result
			found, err = s.redis.GetJSON(redisCtx, cacheKey, &legacy)
			if err != nil || !found {
				return err
			}
			return nil
		})
	})
	if err == nil && cached.Domain != "" {
		assess := newDomainAssessment()
		assess.Evaluated = append(assess.Evaluated, LayerResultCache)
		assess.Skipped = append(assess.Skipped,
			LayerThreatFeed, LayerLexical, LayerDomainML, LayerAIRefine)
		if lookupMode == osintLookupOnDemand {
			assess.Evaluated = append(assess.Evaluated, LayerOSINT)
		} else {
			assess.Skipped = append(assess.Skipped, skippedLayer(LayerOSINT, SkipCacheOnly))
		}
		var report osint.Report
		var updated analysis.Result
		timer.measure(LayerOSINT, func() {
			report = s.lookupOSINT(ctx, normalized, cached, lookupMode, forceOSINT)
			updated = s.applyOSINT(ctx, normalized, cached, report, currentRevision)
		})
		// Enqueue after the OSINT section so the worker snapshot is the
		// latest evaluation, and after a cache entry is known to exist:
		// the worker must never read an entry older than its own
		// snapshot's prerequisites. QueuedAt ordering plus the in-flight
		// guard gives exactly one lookup per episode.
		if shouldEnqueueEnrichment(updated) && cachedEntryNeedsEnrichment(cachedEntry) {
			s.enqueueEnrichment(ctx, enrichmentJob{
				Domain:         normalized,
				Result:         updated,
				FeedRevision:   cachedEntry.FeedRevision,
				BrandRevision:  cachedEntry.BrandRevision,
				ConfigRevision: cachedEntry.ConfigRevision,
				ModelRevision:  cachedEntry.ModelRevision,
				QueuedAt:       time.Now().UTC().Format(time.RFC3339Nano),
			})
		}
		assess.Timings = timer.timings
		return updated, true, report.Evidence, assess
	}
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		logjson.Warn("analysis cache read failed", correlation.Fields(ctx, map[string]any{
			"service": "risk",
			"domain":  normalized,
			"error":   err.Error(),
		}))
	}

	// 2. Check Threat Feed
	assess := newDomainAssessment()
	assess.Evaluated = append(assess.Evaluated, LayerThreatFeed)
	var result analysis.Result
	var feedScope FeedScope
	timer.measure(LayerThreatFeed, func() {
		result, feedScope = s.feedResult(ctx, normalized)
	})
	// Shadow scope trace (PR-08b/M7): record hits and trust bypasses in
	// telemetry. Misses stay nil (miss-vs-skip already in the layer lists).
	if feedHit := result.Domain != ""; feedHit || feedScope.TrustBypassed {
		assess.Feed = &feedScope
	}
	feedHit := result.Domain != ""
	if !feedHit {
		// 3. Lexical Analysis
		timer.measure(LayerLexical, func() {
			result = s.analyzeLexical(normalized)
		})
		assess.Evaluated = append(assess.Evaluated, LayerLexical)
	} else {
		assess.Skipped = append(assess.Skipped, LayerLexical)
	}
	// 4. ML refinement/promotion, followed by the existing AI refinement unless
	// ML enforce mode already promoted this suspicious result.
	aiContributed := false
	mlPromoted := false
	if result.Verdict == analysis.VerdictSuspicious {
		assess.Evaluated = append(assess.Evaluated, LayerDomainML)
		timer.measure(LayerDomainML, func() {
			result, mlPromoted = s.classifyML(ctx, result)
		})
		if !mlPromoted {
			assess.Evaluated = append(assess.Evaluated, LayerAIRefine)
			var refined analysis.Result
			timer.measure(LayerAIRefine, func() {
				refined = s.refineWithAI(ctx, result)
			})
			if refined.Verdict != result.Verdict || len(refined.Reasons) > len(result.Reasons) {
				aiContributed = true
			}
			result = refined
			if s.mlMode != analysis.MLModeDisabled && s.mlClassifier != nil && s.mlClassifier.Enabled() {
				s.mlTelemetry.fallbacks.Add(1)
			}
		}
	}
	if !assessedLayer(assess.Evaluated, LayerDomainML) {
		assess.Skipped = append(assess.Skipped, LayerDomainML, LayerAIRefine)
	}
	// 5. OSINT public-warning evidence. API/dashboard can fetch on demand;
	// resolver policy uses cached evidence only via lookupMode.
	if lookupMode == osintLookupOnDemand {
		assess.Evaluated = append(assess.Evaluated, LayerOSINT)
	} else {
		assess.Skipped = append(assess.Skipped, skippedLayer(LayerOSINT, SkipCacheOnly))
	}
	var report osint.Report
	timer.measure(LayerOSINT, func() {
		report = s.lookupOSINT(ctx, normalized, result, lookupMode, forceOSINT)
		result = s.applyOSINT(ctx, normalized, result, report, currentRevision)
	})

	// Cache the final result
	err = nil
	timer.measure(LayerResultCache, func() {
		err = s.withRedis(ctx, func(redisCtx context.Context) error {
			ttl := s.ttlFor(result.Verdict)
			// Nếu AI không contribute (timeout/lỗi), dùng TTL ngắn để retry sớm
			if !aiContributed && result.Verdict == analysis.VerdictSuspicious {
				ttl = negativeCacheTTL
			}
			return s.redis.SetJSON(redisCtx, cacheKey, analysisCacheEntry{
				Result:           result,
				FeedRevision:     currentRevision,
				BrandRevision:    currentBrandRevision,
				AnalysisRevision: analysisAlgorithmRevision,
				ConfigRevision:   currentConfigRevision,
				ModelRevision:    modelRevision,
				// NOTE: no AssessedAt here on purpose. The enrichment job for
				// this evaluation is enqueued below with a later QueuedAt; a
				// stamp here is unnecessary and would only confuse recency
				// comparisons. AssessedAt is set by writers that add new
				// evidence after the snapshot: worker enrichment and OSINT.
			}, ttl)
		})
	})
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		logjson.Warn("analysis cache write failed", correlation.Fields(ctx, map[string]any{
			"service": "risk",
			"domain":  normalized,
			"error":   err.Error(),
		}))
	}

	// Enqueue after the cache write (and after OSINT, whose output is now
	// part of result): the worker must always find a cache entry, and its
	// snapshot must include every synchronous signal, so a worker write
	// can never clobber a same-request OSINT upgrade it never saw.
	if shouldEnqueueEnrichment(result) {
		assess.Skipped = append(assess.Skipped, skippedLayer(LayerEnrichment, SkipAsync))
		s.enqueueEnrichment(ctx, enrichmentJob{
			Domain:         normalized,
			Result:         result,
			FeedRevision:   currentRevision,
			BrandRevision:  currentBrandRevision,
			ConfigRevision: currentConfigRevision,
			ModelRevision:  modelRevision,
			QueuedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		})
	} else {
		assess.Skipped = append(assess.Skipped, skippedLayer(LayerEnrichment, SkipOutOfRange))
	}

	assess.Timings = timer.timings
	return result, false, report.Evidence, assess
}

type AnalyzeOptions struct {
	IncludeEvidence bool
	ForceOSINT      bool
	URLContext      *URLAnalysisContext
	// MissingContextReason classifies analysis requests that carry no URL
	// context (bounded set: get_domain_only|post_not_provided). It feeds the
	// aggregate coverage breakdown only; it never stores caller data.
	MissingContextReason string
}

type osintLookupMode int

const (
	osintLookupNone osintLookupMode = iota
	osintLookupCachedOnly
	osintLookupOnDemand
)

const negativeCacheTTL = 2 * time.Minute
