package risk

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"safe-zone/internal/analysis"
	"safe-zone/internal/tlsinspect"
	"safe-zone/internal/whois"
)

// FP-guard 2026-09 (M5): weak TLS metadata alone must not create a
// MALICIOUS verdict. It can only add a small advisory bump below the
// suspicious floor, or promote an already-suspicious host.
func TestTLSAdvisoryNeedsCorroboration(t *testing.T) {
	weak := enrichmentSignals{
		TLS: tlsinspect.Result{
			Score:         45,
			AdvisoryScore: 45,
			Reasons:       []string{"tls: certificate issued < 7 days ago", "tls: certificate name does not match domain"},
		},
	}

	low := analysis.Result{Domain: "cdn-edge-example.net", Verdict: analysis.VerdictSafe, Score: 25, Confidence: 0.65}
	applyEnrichmentSignals(&low, weak)
	if low.Score != 35 {
		t.Errorf("low-base score = %d; want 35 (25 + capped advisory 10)", low.Score)
	}
	if low.Verdict != analysis.VerdictSafe {
		t.Errorf("low-base verdict = %s; want SAFE", low.Verdict)
	}

	high := analysis.Result{Domain: "shady-example.net", Verdict: analysis.VerdictSuspicious, Score: 55, Confidence: 0.9}
	applyEnrichmentSignals(&high, weak)
	if high.Score != 100 {
		t.Errorf("suspicious-base score = %d; want 100 (55 + full 45)", high.Score)
	}
	if high.Verdict != analysis.VerdictMalicious {
		t.Errorf("suspicious-base verdict = %s; want MALICIOUS (promotion preserved)", high.Verdict)
	}

	// Fixtures produced without AdvisoryScore keep legacy full weight
	// (backward compatible: unscored signals are treated as strong).
	legacy := analysis.Result{Domain: "legacy-example.net", Verdict: analysis.VerdictSafe, Score: 25}
	applyEnrichmentSignals(&legacy, enrichmentSignals{
		TLS:   tlsinspect.Result{Score: 30, Reasons: []string{"tls: certificate name does not match domain"}},
		WHOIS: whois.Result{},
	})
	if legacy.Score != 55 {
		t.Errorf("legacy unscored TLS = %d; want 55 (full weight preserved)", legacy.Score)
	}
}

// FP-guard 2026-09 (M7): exact feed IOCs on shared serving apexes are
// contextual evidence, never a host block.
func TestSharedApexExactIsContextual(t *testing.T) {
	service, closeService := newTestServiceWithRedis(t)
	defer closeService()

	live := float64(time.Now().Add(time.Hour).Unix())
	for _, m := range []string{"cdn.jsdelivr.net", "cdn.ampproject.org", "github.com"} {
		if _, err := service.redis.ZAdd(context.Background(), defaultThreatFeedKey, redis.Z{Score: live, Member: m}); err != nil {
			t.Fatal(err)
		}
	}

	for _, domain := range []string{"cdn.jsdelivr.net", "cdn.ampproject.org"} {
		result := service.Analyze(context.Background(), domain, ClientInfo{})
		if result.Verdict == analysis.VerdictMalicious {
			t.Errorf("Analyze(%q) = MALICIOUS; want contextual SUSPICIOUS", domain)
		}
		if result.Verdict != analysis.VerdictSuspicious {
			t.Errorf("Analyze(%q) = %s; want SUSPICIOUS", domain, result.Verdict)
		}
		if !hasReasonContaining(result.Reasons, threatFeedReason) ||
			!hasReasonContaining(result.Reasons, sharedFeedApexReason) {
			t.Errorf("Analyze(%q) reasons = %v; want feed + shared-apex reasons", domain, result.Reasons)
		}
		if scope := result.Assessment.Feed; scope == nil || !scope.ExactMatch || !scope.SharedApex {
			t.Errorf("Analyze(%q) feed scope = %+v; want exact+shared-apex trace", domain, scope)
		}
	}

	// github.com as a noisy parent member must not block its tenants
	// (github is now a trusted brand AND a shared apex skip).
	result := service.Analyze(context.Background(), "api.github.com", ClientInfo{})
	if result.Verdict == analysis.VerdictMalicious {
		t.Errorf("Analyze(api.github.com) = MALICIOUS %v; want no block", result.Reasons)
	}
	if hasReasonContaining(result.Reasons, threatFeedReason) {
		t.Errorf("Analyze(api.github.com) reasons = %v; want no feed reason", result.Reasons)
	}
}

// Tenant subdomains under shared roots keep exact-IOC blocking: only the
// apex itself is contextual.
func TestTenantExactStillBlocks(t *testing.T) {
	service, closeService := newTestServiceWithRedis(t)
	defer closeService()

	exact := "evil-phish-tenant.github.io"
	if _, err := service.redis.ZAdd(context.Background(), defaultThreatFeedKey, redis.Z{
		Score:  float64(time.Now().Add(time.Hour).Unix()),
		Member: exact,
	}); err != nil {
		t.Fatal(err)
	}

	result := service.Analyze(context.Background(), exact, ClientInfo{})
	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected tenant exact IOC to block, got %s with reasons %v", result.Verdict, result.Reasons)
	}
}

// A noisy apex/root member must not block tenants via the parent walk.
func TestNoisySharedParentSkipped(t *testing.T) {
	service, closeService := newTestServiceWithRedis(t)
	defer closeService()

	if _, err := service.redis.ZAdd(context.Background(), defaultThreatFeedKey, redis.Z{
		Score:  float64(time.Now().Add(time.Hour).Unix()),
		Member: "fastly.net",
	}); err != nil {
		t.Fatal(err)
	}

	result := service.Analyze(context.Background(), "customer-a.fastly.net", ClientInfo{})
	if hasReasonContaining(result.Reasons, threatFeedReason) {
		t.Fatalf("expected noisy shared parent to be skipped, got %v", result.Reasons)
	}
	if result.Verdict == analysis.VerdictMalicious {
		t.Fatalf("expected no block from noisy shared parent, got %s", result.Verdict)
	}
}

func TestIsSharedFeedApex(t *testing.T) {
	apex := map[string]bool{
		"github.com":         true,
		"cdn.jsdelivr.net":   true,
		"cdn.ampproject.org": true,
		"fastly.net":         true,
		"jsdelivr.net":       true,
	}
	for host := range apex {
		if !isSharedFeedApex(host) {
			t.Errorf("isSharedFeedApex(%q) = false; want true", host)
		}
	}
	notApex := []string{
		"",
		"evil-phish-tenant.github.io",
		"api.github.com",
		"evil.sharepoint.com",
		"deep.feed-parent.test",
		"bad.test",
		"dualstack.video.twitter.map.fastly.net",
	}
	for _, host := range notApex {
		if isSharedFeedApex(host) {
			t.Errorf("isSharedFeedApex(%q) = true; want false", host)
		}
	}
}

// Contextual shared-apex verdicts must not spend enrichment budget: the
// worker could only promote them on metadata.
func TestSharedApexSkipsEnrichment(t *testing.T) {
	shared := analysis.Result{
		Domain: "cdn.jsdelivr.net", Verdict: analysis.VerdictSuspicious,
		Score: 40, Reasons: []string{threatFeedReason, sharedFeedApexReason},
	}
	if shouldEnqueueEnrichment(shared) {
		t.Error("shared-apex contextual result must not enqueue enrichment")
	}
	plain := analysis.Result{Domain: "suspicious-example.net", Verdict: analysis.VerdictSuspicious, Score: 40}
	if !shouldEnqueueEnrichment(plain) {
		t.Error("ordinary suspicious result must still enqueue enrichment")
	}
}
