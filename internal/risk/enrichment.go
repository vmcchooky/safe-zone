package risk

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
	"safe-zone/internal/tlsinspect"
	"safe-zone/internal/whois"
)

func shouldEnqueueEnrichment(result analysis.Result) bool {
	if result.Domain == "" || result.Score < 20 || result.Score >= 70 {
		return false
	}
	// Contextual shared-infrastructure verdicts (FP-guard 2026-09, M7)
	// never spend inspection budget: TLS/WHOIS metadata must not promote
	// them, so there is nothing for the worker to add.
	for _, reason := range result.Reasons {
		if reason == sharedFeedApexReason {
			return false
		}
	}
	return true
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
	if current, known := s.currentFeedRevision(s.lifecycleCtx); known && current != "" && job.FeedRevision != "" && current != job.FeedRevision {
		return
	}
	if current, known := s.currentBrandRevision(s.lifecycleCtx); known && current != "" && job.BrandRevision != "" && current != job.BrandRevision {
		return
	}
	if current := s.currentConfigRevision(); current != job.ConfigRevision {
		return
	}
	if current := s.ml.currentMLPolicyRevision(); current != job.ModelRevision {
		return
	}

	enrichCtx, cancel := context.WithTimeout(s.lifecycleCtx, s.enrichTimeout)
	defer cancel()

	signals := s.enrichmentLookup(enrichCtx, job.Domain)
	enriched := job.Result
	applyEnrichmentSignals(&enriched, signals)

	now := time.Now().UTC().Format(time.RFC3339Nano)
	cacheKey := analysisCacheKey(job.Domain, job.ModelRevision)
	// Recency guard (M1/PR-05): a job snapshot must not overwrite an
	// evaluation materialized after the snapshot was taken. The read and
	// the conditional write run inside one WATCH transaction, so even
	// cross-process races between two services sharing Redis converge on
	// the fresher entry instead of last-writer-wins.
	skippedStale := false
	queuedAt := jobQueuedAt(job.QueuedAt)
	err := s.withRedis(s.lifecycleCtx, func(redisCtx context.Context) error {
		swapped, err := s.redis.CompareAndSwapJSON(redisCtx, cacheKey,
			func(raw []byte, found bool) (bool, error) {
				if !found {
					return true, nil
				}
				var current analysisCacheEntry
				if err := json.Unmarshal(raw, &current); err != nil {
					return false, err
				}
				if current.Result.Domain != "" &&
					entryAssessedAt(current).After(queuedAt) {
					return false, nil
				}
				return true, nil
			}, analysisCacheEntry{
				Result:           enriched,
				FeedRevision:     job.FeedRevision,
				BrandRevision:    job.BrandRevision,
				AnalysisRevision: analysisAlgorithmRevision,
				ConfigRevision:   job.ConfigRevision,
				ModelRevision:    job.ModelRevision,
				EnrichedAt:       now,
				AssessedAt:       now,
			}, s.ttlFor(enriched.Verdict))
		if err != nil {
			if errors.Is(err, cache.ErrCASConflict) {
				skippedStale = true
				return nil
			}
			return err
		}
		if !swapped {
			skippedStale = true
		}
		return nil
	})
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		logjson.Warn("background enrichment cache write failed", map[string]any{
			"service": "risk",
			"domain":  job.Domain,
			"error":   err.Error(),
		})
	}
	if skippedStale {
		logjson.Info("background enrichment skipped stale snapshot", map[string]any{
			"service": "risk",
			"domain":  job.Domain,
		})
	}
}

func (s *Service) defaultEnrichmentLookup(ctx context.Context, domain string) enrichmentSignals {
	var (
		dnsOutcome  = DNSOutcomeOK
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
		nss, err := net.DefaultResolver.LookupNS(nsCtx, apex)
		if outcome := classifyDNSLookupErr(err); outcome != DNSOutcomeOK {
			dnsOutcome = outcome
			return
		}
		if len(nss) == 0 {
			dnsOutcome = DNSOutcomeNoData
		}
	}()
	go func() {
		defer wg.Done()
		tlsResult = tlsinspect.Inspect(ctx, domain)
	}()
	go func() {
		defer wg.Done()
		whoisResult = whois.LookupWithCache(ctx, domain, s.store, s.whoisCacheTTL)
	}()
	wg.Wait()
	return enrichmentSignals{
		DNS:   dnsOutcome,
		TLS:   tlsResult,
		WHOIS: whoisResult,
	}
}

func applyEnrichmentSignals(result *analysis.Result, signals enrichmentSignals) {
	if result == nil {
		return
	}
	// DNS outcomes are availability notes only. They never add to the
	// security score: an unreachable, slow or failing resolver says
	// nothing about malice (PR-01/H1).
	if signals.DNS != DNSOutcomeOK {
		result.Reasons = append(result.Reasons, signals.DNS.String())
	}
	tlsScore := signals.TLS.Score
	registeredDomain := whois.RegisteredDomain(result.Domain)
	isCDNOrTrustedInfra := analysis.IsCDNRoot(registeredDomain) || analysis.IsTrustedInfraSuffix(result.Domain)
	if signals.TLS.AdvisoryScore > 0 && (result.Score < minScoreForFullTLSWeight || isCDNOrTrustedInfra) {
		strong := tlsScore - signals.TLS.AdvisoryScore
		if strong < 0 {
			strong = 0
		}
		if tlsScore > strong+maxTLSAdvisoryPromotion {
			tlsScore = strong + maxTLSAdvisoryPromotion
		}
	}
	result.Score += tlsScore + signals.WHOIS.Score
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

// maxTLSAdvisoryPromotion bounds how many weak-TLS points (SAN mismatch,
// fresh certificate) can add when the pre-enrichment assessment shows no
// independent suspicion (FP-guard 2026-09, M5). CDN edges serve default
// certificates for CNAME chains and rotate constantly, so mismatch/fresh
// metadata alone must never create a MALICIOUS verdict; it can only add a
// small advisory bump or promote an already-suspicious host. Strong TLS
// signals (expired, self-signed) keep full weight.
const maxTLSAdvisoryPromotion = 10

// minScoreForFullTLSWeight is the pre-enrichment score at or above which
// weak TLS metadata applies at full weight (the host is already
// SUSPICIOUS on lexical/feed merit).
const minScoreForFullTLSWeight = 40

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

type enrichmentSignals struct {
	// DNS classifies the apex NS lookup performed during background
	// enrichment. DNS metadata is availability evidence only: no outcome
	// may promote the security score or verdict on its own (PR-01/H1).
	// The zero value means the lookup succeeded with usable NS records.
	DNS   DNSOutcome
	TLS   tlsinspect.Result
	WHOIS whois.Result
}

// DNSOutcome is the closed set of apex nameserver lookup results observed
// by background enrichment. Reason prose is derived from String, so the
// telemetry vocabulary stays bounded.
type DNSOutcome int

const (
	// DNSOutcomeOK means the apex returned usable NS records.
	DNSOutcomeOK DNSOutcome = iota
	// DNSOutcomeNXDOMAIN means the apex authoritatively does not exist.
	DNSOutcomeNXDOMAIN
	// DNSOutcomeNoData means the apex answered without usable NS records.
	DNSOutcomeNoData
	// DNSOutcomeTimeout means the lookup exceeded its deadline.
	DNSOutcomeTimeout
	// DNSOutcomeServerFailure covers SERVFAIL, refused and other
	// server-side lookup errors.
	DNSOutcomeServerFailure
	// DNSOutcomeCanceled means the lookup context was canceled.
	DNSOutcomeCanceled
	// DNSOutcomeUnknownError is the catch-all for unclassified errors.
	DNSOutcomeUnknownError
)

// String returns the bounded availability note for a non-OK outcome.
func (o DNSOutcome) String() string {
	switch o {
	case DNSOutcomeNXDOMAIN:
		return "dns: apex has no NS records (authoritative NXDOMAIN)"
	case DNSOutcomeNoData:
		return "dns: apex answered without usable NS records"
	case DNSOutcomeTimeout:
		return "dns: apex NS lookup timed out"
	case DNSOutcomeServerFailure:
		return "dns: apex NS lookup failed (server error)"
	case DNSOutcomeCanceled:
		return "dns: apex NS lookup canceled"
	case DNSOutcomeUnknownError:
		return "dns: apex NS lookup failed"
	default:
		return "dns: apex NS lookup unavailable"
	}
}

// classifyDNSLookupErr maps a LookupNS error to a DNSOutcome. A nil error
// with an empty answer set is classified by the caller as NoData.
func classifyDNSLookupErr(err error) DNSOutcome {
	if err == nil {
		return DNSOutcomeOK
	}
	if errors.Is(err, context.Canceled) {
		return DNSOutcomeCanceled
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return DNSOutcomeNXDOMAIN
		case dnsErr.IsTimeout:
			return DNSOutcomeTimeout
		default:
			return DNSOutcomeServerFailure
		}
	}
	if os.IsTimeout(err) {
		return DNSOutcomeTimeout
	}
	return DNSOutcomeUnknownError
}
