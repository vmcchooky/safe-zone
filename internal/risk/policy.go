package risk

import (
	"context"
	"strings"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/domaintrie"
)

func (s *Service) Policy(ctx context.Context, domain string, client ClientInfo) Policy {
	normalized, err := analysis.NormalizeDomain(domain)
	assess := newDomainAssessment()
	decisionID := decisionIDFor(ctx)
	var preTimer layerTimer
	if err != nil {
		res := s.analyzeLexical(domain)
		assess.Evaluated = append(assess.Evaluated, LayerIdentity)
		assess.Skipped = append(assess.Skipped, LayerOverride, LayerWhitelist,
			LayerAdblock, LayerGroupPolicy)
		assess.Skipped = append(assess.Skipped, engineSkippedLayers()...)
		assess.Timings = preTimer.timings
		return Policy{
			Domain:     domain,
			Policy:     "block",
			Result:     res,
			CacheHit:   false,
			DecisionID: decisionID,
			Assessment: assess,
		}
	}

	// 1. Get Group for Client
	group := s.resolveClientGroup(ctx, client, &preTimer)

	// 2. Check Overrides
	if override := s.resolveOverride(ctx, group, normalized, &preTimer); override != nil {
		decision := override.decision
		policyResult := Policy{
			Domain:     normalized,
			Policy:     override.decision.Action,
			Result:     override.result,
			Decision:   decision,
			CacheHit:   override.cacheHit,
			Assessment: assess,
		}
		policyResult.Assessment.Evaluated = append(policyResult.Assessment.Evaluated,
			LayerIdentity, LayerOverride)
		policyResult.Assessment.Skipped = append(policyResult.Assessment.Skipped,
			LayerWhitelist, LayerAdblock, LayerGroupPolicy)
		policyResult.Assessment.Skipped = append(policyResult.Assessment.Skipped, engineSkippedLayers()...)
		policyResult.Assessment.Timings = preTimer.timings
		policyResult.DecisionID = decisionID
		s.recordTelemetry(Analysis{
			Result:     policyResult.Result,
			CacheHit:   policyResult.CacheHit,
			AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Decision:   decision,
			DecisionID: decisionID,
			Assessment: policyResult.Assessment,
		}, client)
		return policyResult
	}

	// 3. Check Whitelist
	if allow := s.resolveWhitelist(ctx, normalized, &preTimer); allow != nil {
		decision := allow.decision
		policyResult := Policy{
			Domain:     normalized,
			Policy:     "allow",
			Result:     allow.result,
			Decision:   decision,
			CacheHit:   allow.cacheHit,
			Assessment: assess,
		}
		policyResult.Assessment.Evaluated = append(policyResult.Assessment.Evaluated,
			LayerIdentity, LayerOverride, LayerWhitelist)
		policyResult.Assessment.Skipped = append(policyResult.Assessment.Skipped,
			LayerAdblock, LayerGroupPolicy)
		policyResult.Assessment.Skipped = append(policyResult.Assessment.Skipped, engineSkippedLayers()...)
		policyResult.Assessment.Timings = preTimer.timings
		policyResult.DecisionID = decisionID
		s.recordTelemetry(Analysis{
			Result:     policyResult.Result,
			CacheHit:   policyResult.CacheHit,
			AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Decision:   decision,
			DecisionID: decisionID,
			Assessment: policyResult.Assessment,
		}, client)
		return policyResult
	}

	// 3.5 Check Adblock Trie. Group/override lookups above may already have
	// touched the store; only the post-match lexical assessment below is
	// backend-free. Check enabled and trie presence before MatchRule so a
	// nil trie never dereferences and the hot path stays lock/allocation/
	// I/O-free after the match.
	var adDetail domaintrie.MatchDetail
	if s.isAdblockEnabled() {
		if adTrie := s.adblock.adblockTrie.Load(); adTrie != nil {
			adDetail = adTrie.MatchRuleDetail(normalized)
		}
	}
	adMatched := adDetail.Matched
	// 3.6 Scoped content exception (separated mode only). It suppresses
	// exactly this adblock match — no early return — so the request falls
	// through to the full security pipeline below. The legacy branch above
	// runs unchanged before any exception is consulted.
	var excRule *domaintrie.Rule
	excID := ""
	if adMatched {
		if s.policySemantics == PolicySemanticsLegacy {
			// Pinned rollback shape: Result stays fused MALICIOUS and no
			// separated Decision is attached. Provenance flows to telemetry
			// only, via the Analysis decision below.
			legacyDecision := legacyPolicyDecision()
			policyResult := Policy{
				Domain: normalized,
				Policy: "block",
				Result: analysis.Result{
					Domain:     normalized,
					Verdict:    analysis.VerdictMalicious,
					Confidence: 1.0,
					Score:      100,
					Reasons:    []string{"adblock"},
					Category:   "adware",
				},
				CacheHit: false,
			}
			policyResult.Assessment = assess
			policyResult.Assessment.Evaluated = append(policyResult.Assessment.Evaluated,
				LayerIdentity, LayerOverride, LayerWhitelist, LayerAdblock)
			policyResult.Assessment.Skipped = append(policyResult.Assessment.Skipped, LayerGroupPolicy)
			policyResult.Assessment.Skipped = append(policyResult.Assessment.Skipped, engineSkippedLayers()...)
			policyResult.Assessment.Skipped = append(policyResult.Assessment.Skipped,
				skippedLayer("security_assessment", SkipLegacyFused))
			policyResult.Assessment.Timings = preTimer.timings
			policyResult.DecisionID = decisionID
			s.recordTelemetry(Analysis{
				Result:     policyResult.Result,
				CacheHit:   false,
				AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
				Decision:   legacyDecision,
				DecisionID: decisionID,
				Assessment: policyResult.Assessment,
			}, client)
			return policyResult
		}

		excMatched := false
		if id, ok := s.matchAdblockException(normalized, &adDetail.Rule); ok {
			excRule = &adDetail.Rule
			excID = id
			excMatched = true
			s.adblock.adblockExcMatches.Add(1)
		}
		// 3.7 Shadow exact/suffix observation (PR3B-lite). Records what a
		// prospective global suffix→exact flip would do to this hit. Pure
		// observation: it never influences Policy, Result or telemetry.
		s.observeShadowExact(adDetail, excMatched)
		if !excMatched {
			// Separated semantics: after the match above, adblock stays a fast
			// content-policy block on a strict post-match local-only path — no
			// s.analyze(), no BrandStore.ListBrands, no Redis, no SQLite, no
			// HTTP, no AI/OSINT, no enrichment enqueue.
			// The security Result is scored by the in-process lexical analyzer
			// against the built-in brand seed only (lexical_local_default_brands);
			// it is explicitly not a full security assessment. The matched rule's
			// provenance (normalized domain, scope, source, category) flows into
			// the Decision so FP triage never has to guess which rule fired.
			lexicalResult := s.analyzeLexicalLocal(normalized)
			decision := adblockDecision(adblockAssessmentLocalDefaultBrands, &adDetail.Rule)
			policyResult := Policy{
				Domain:   normalized,
				Policy:   "block",
				Result:   lexicalResult,
				Decision: &decision,
				CacheHit: false,
			}
			policyResult.Assessment = assess
			policyResult.Assessment.Evaluated = append(policyResult.Assessment.Evaluated,
				LayerIdentity, LayerOverride, LayerWhitelist, LayerAdblock,
				LayerLexicalLocal, LayerContentPolicy)
			policyResult.Assessment.Skipped = append(policyResult.Assessment.Skipped, LayerGroupPolicy)
			policyResult.Assessment.Skipped = append(policyResult.Assessment.Skipped, engineSkippedLayers()...)
			policyResult.Assessment.Timings = preTimer.timings
			policyResult.DecisionID = decisionID
			s.recordTelemetryWithSource(Analysis{
				Result:     lexicalResult,
				CacheHit:   false,
				AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
				Decision:   &decision,
				DecisionID: decisionID,
				Assessment: policyResult.Assessment,
			}, client, "adblock")
			return policyResult
		}
	}

	// 4. Get Threat Assessment
	result, cacheHit, _, engineAssess := s.analyze(ctx, normalized, osintLookupCachedOnly, false)

	// 5. Dynamic enforcement
	policy := "allow"
	preTimer.measure(LayerGroupPolicy, func() {
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
				if strings.EqualFold(strings.TrimSpace(blockedCat), result.Category) {
					policy = "block"
					break
				}
			}
		}
	})

	policyResult := Policy{
		Domain:     result.Domain,
		Policy:     policy,
		Result:     result,
		CacheHit:   cacheHit,
		DecisionID: decisionID,
	}
	policyResult.Assessment.Evaluated = prependLayers(engineAssess.Evaluated,
		[]string{LayerIdentity, LayerOverride, LayerWhitelist, LayerAdblock, LayerGroupPolicy})
	policyResult.Assessment.Coverage = engineAssess.Coverage
	policyResult.Assessment.Skipped = engineAssess.Skipped
	policyResult.Assessment.Timings = mergeTimings(preTimer.timings, engineAssess.Timings)
	policyResult.Assessment.Feed = engineAssess.Feed
	if excRule != nil {
		// Content axis only: the exception suppresses the adblock block, so
		// the decision is allow while the overall policy above still follows
		// the security Result plus dynamic enforcement. Telemetry below keeps
		// the real inferred source; the config reason is never exposed.
		decision := adblockExceptionDecision(excRule, excID)
		policyResult.Decision = &decision
	}

	s.recordTelemetry(Analysis{
		Result:     result,
		CacheHit:   cacheHit,
		AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Decision:   policyResult.Decision,
		DecisionID: decisionID,
		Assessment: policyResult.Assessment,
	}, client)

	return policyResult
}
