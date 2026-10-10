package risk

import (
	"context"
	"errors"
	"strings"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
	"safe-zone/internal/whois"
)

func assessedLayer(layers []string, layer string) bool {
	for _, l := range layers {
		if l == layer {
			return true
		}
	}
	return false
}

func (e *FeedEngine) feedResult(ctx context.Context, domain string, brands []analysis.Brand) (analysis.Result, FeedScope) {
	if e == nil {
		return analysis.Result{}, FeedScope{}
	}
	// PR-08a/H2 scope authority: a live *exact* IOC is scoped evidence for
	// this host and wins over the trusted-brand suffix bypass (a compromised
	// tenant host stays blockable). A *parent-only* match under a trusted
	// root keeps the bypass: one noisy IOC must not block a whole shared
	// root. Redis errors stay fail-open, as before.
	// PR-08b/M7 shadow: the returned scope is observability only and never
	// gates the verdict.
	exactHit, err := e.matchExactThreatFeed(ctx, domain)
	if err != nil {
		if !errors.Is(err, cache.ErrDisabled) {
			logjson.Warn("threat feed lookup failed", correlation.Fields(ctx, map[string]any{
				"service": "risk",
				"domain":  domain,
				"error":   err.Error(),
			}))
		}
		return analysis.Result{}, FeedScope{}
	}
	if exactHit {
		// FP-guard 2026-09/M7: an exact feed IOC on shared
		// infrastructure (a whole CDN apex, github.com) is contextual,
		// not authoritative. URL-only IOCs ingested as host entries must
		// not block shared apexes; tenant subdomains beneath them still
		// match exactly and keep full weight.
		if isSharedFeedApex(domain) {
			return sharedApexFeedHit(domain), FeedScope{ExactMatch: true, Candidate: domain, SharedApex: true}
		}
		return threatFeedHit(domain), FeedScope{ExactMatch: true, Candidate: domain}
	}

	if analysis.IsTrustedBrandSuffix(domain, brands) || analysis.IsTrustedInfraSuffix(domain) {
		return analysis.Result{}, FeedScope{TrustBypassed: true}
	}

	candidate, err := e.matchParentCandidate(ctx, domain)
	if err != nil {
		if !errors.Is(err, cache.ErrDisabled) {
			logjson.Warn("threat feed lookup failed", correlation.Fields(ctx, map[string]any{
				"service": "risk",
				"domain":  domain,
				"error":   err.Error(),
			}))
		}
		return analysis.Result{}, FeedScope{}
	}
	if candidate == "" {
		return analysis.Result{}, FeedScope{}
	}

	return threatFeedHit(domain), FeedScope{Candidate: candidate, Depth: feedMatchDepth(domain, candidate)}
}

// feedMatchDepth counts labels from the queried domain up to the matched
// parent candidate: 0 is the exact host.
func feedMatchDepth(domain, candidate string) int {
	depth := 0
	for d := domain; d != candidate; {
		idx := strings.IndexByte(d, '.')
		if idx < 0 {
			break
		}
		d = d[idx+1:]
		depth++
	}
	return depth
}

// threatFeedHit builds the malicious verdict for a live threat-feed match.
func threatFeedHit(domain string) analysis.Result {
	return analysis.Result{
		Domain:     domain,
		Verdict:    analysis.VerdictMalicious,
		Confidence: 1,
		Score:      100,
		Reasons:    []string{threatFeedReason},
	}
}

// sharedApexFeedHit builds the contextual verdict for a live threat-feed
// member that IS shared infrastructure. The report is preserved as
// evidence (SUSPICIOUS so policy never hard-blocks on it alone) while the
// apex keeps serving.
func sharedApexFeedHit(domain string) analysis.Result {
	return analysis.Result{
		Domain:     domain,
		Verdict:    analysis.VerdictSuspicious,
		Confidence: 0.6,
		Score:      40,
		Reasons:    []string{threatFeedReason, sharedFeedApexReason},
	}
}

// isSharedFeedApex reports whether host is shared infrastructure whose own
// feed membership (or inheritance by its children) must stay contextual:
// an explicitly listed multi-tenant serving hostname (delegated to
// analysis.IsSharedServingHost), or a known CDN/cloud root queried at the root
// itself. Tenant subdomains (evil.github.io, x.amazonaws.com) are never apexes:
// exact IOCs on them still block.
func isSharedFeedApex(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return false
	}
	if analysis.IsSharedServingHost(h) {
		return true
	}
	return h == whois.RegisteredDomain(h) && analysis.IsSharedHostingRoot(h)
}

// matchExactThreatFeed reports whether the exact domain itself is a live
// (unexpired) threat-feed member. Used by feedResult before the
// trusted-suffix bypass so scoped IOC evidence wins (PR-08a/H2).
func (e *FeedEngine) matchExactThreatFeed(parent context.Context, domain string) (bool, error) {
	if e == nil {
		return false, cache.ErrDisabled
	}
	candidates := ThreatFeedCandidates(domain)
	if len(candidates) == 0 {
		return false, nil
	}
	matched, err := e.matchAnyThreatFeedCandidate(parent, candidates[:1])
	return matched != "", err
}

// matchParentCandidate walks only the parent suffixes, skipping the exact
// domain, and returns the nearest live member ("" on miss). A parent-only
// hit is noisy evidence: under a trusted root it is bypassed by feedResult
// (PR-08a/H2). Shared-infrastructure apexes are skipped as candidates so a
// noisy apex IOC cannot block its tenants (FP-guard 2026-09, M7). The
// returned candidate feeds the shadow scope trace (PR-08b/M7).
func (e *FeedEngine) matchParentCandidate(parent context.Context, domain string) (string, error) {
	if e == nil {
		return "", cache.ErrDisabled
	}
	candidates := ThreatFeedCandidates(domain)
	if len(candidates) <= 1 {
		return "", nil
	}
	parents := candidates[1:]
	kept := parents[:0]
	for _, c := range parents {
		if isSharedFeedApex(c) {
			continue
		}
		kept = append(kept, c)
	}
	if len(kept) == 0 {
		return "", nil
	}
	return e.matchAnyThreatFeedCandidate(parent, kept)
}

func (e *FeedEngine) matchAnyThreatFeedCandidate(parent context.Context, candidates []string) (string, error) {
	if e == nil {
		return "", cache.ErrDisabled
	}
	var matched string
	currentTime := float64(time.Now().Unix())
	// Single round trip for the whole suffix walk: a 253-octet normalized
	// input fans out to at most ~127 candidates, and sequential ZSCOREs
	// would multiply Redis RTT by attacker-controlled input length
	// (PR-02/H4). Nearest-first and expiry semantics are unchanged.
	err := withRedisTimeout(parent, e.redis, e.redisTimeout, func(ctx context.Context) error {
		scores, ok, err := e.redis.ZScores(ctx, e.threatFeedKey, candidates)
		if err != nil {
			return err
		}
		for i, candidate := range candidates {
			if ok[i] && scores[i] >= currentTime {
				matched = candidate
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	return matched, nil
}

// ThreatFeedCandidates returns the exact domain followed by every parent
// suffix considered by the runtime threat-feed matcher.
//
// Unlike the whitelist and admin-override lookups, this deliberately walks all
// the way to the top-level domain. The threat feed is a list of *observed
// malicious hosts*, so blocking the namespace behind a listed host is the
// intended semantics: if "evil.example" is listed, "sub.evil.example" is
// compromised too, and a feed that lists a bare public suffix ("com") is a
// feed bug that would surface as a very broad block rather than a missed one.
//
// That is the opposite risk profile to the other two lookups, where a
// public-suffix row is an *operator* action that would silently disable
// protection (whitelist) or override the pipeline (override). Do not add a
// registrable-label floor here without re-reading those three functions.
func ThreatFeedCandidates(domain string) []string {
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

func (s *Service) analyzeLexical(domain string) analysis.Result {
	s.analyzerMu.RLock()
	analyzer := s.analyzer
	s.analyzerMu.RUnlock()
	return analyzer.Analyze(domain)
}

// analyzeLexicalLocal scores a domain with the local-only lexical path
// (Analyzer.AnalyzeLocal): it never touches BrandStore.ListBrands, Redis,
// SQLite, HTTP, AI/OSINT or enrichment, and uses no context. Brand spoofing
// is evaluated against the built-in brand seed only, not operator-managed
// brands — an accepted PR1 limitation, surfaced in the decision's
// assessment_mode.
func (s *Service) analyzeLexicalLocal(domain string) analysis.Result {
	s.analyzerMu.RLock()
	analyzer := s.analyzer
	s.analyzerMu.RUnlock()
	return analyzer.AnalyzeLocal(domain)
}
