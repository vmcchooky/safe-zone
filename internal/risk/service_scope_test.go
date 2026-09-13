package risk

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"safe-zone/internal/analysis"
)

// PR-08a/H2: an exact threat-feed IOC must win over the trusted-brand
// suffix bypass. A noisy *parent* feed member under a trusted root keeps
// the bypass (covered by TestThreatFeedTrustedBrandSuffixBypass).
func TestThreatFeedExactMatchWinsOverTrustedSuffix(t *testing.T) {
	service, closeService := newTestServiceWithRedis(t)
	defer closeService()

	exact := "evil.sharepoint.com" // sharepoint.com is a trusted microsoft alt-domain
	if _, err := service.redis.ZAdd(context.Background(), defaultThreatFeedKey, redis.Z{
		Score:  float64(time.Now().Add(time.Hour).Unix()),
		Member: exact,
	}); err != nil {
		t.Fatal(err)
	}

	result := service.Analyze(context.Background(), exact, ClientInfo{})
	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected exact feed IOC to beat trusted suffix, got %s with reasons %v", result.Verdict, result.Reasons)
	}
	if !hasReasonContaining(result.Reasons, threatFeedReason) {
		t.Fatalf("expected threat feed reason for exact IOC, got %v", result.Reasons)
	}
}

// PR-08a/H2 guardrail: a parent-only feed member under a trusted root must
// still bypass, so one noisy IOC cannot block a whole shared root.
func TestThreatFeedParentMatchStillBypassedByTrust(t *testing.T) {
	service, closeService := newTestServiceWithRedis(t)
	defer closeService()

	if _, err := service.redis.ZAdd(context.Background(), defaultThreatFeedKey, redis.Z{
		Score:  float64(time.Now().Add(time.Hour).Unix()),
		Member: "sharepoint.com",
	}); err != nil {
		t.Fatal(err)
	}

	result := service.Analyze(context.Background(), "quiet-benign-doc.sharepoint.com", ClientInfo{})
	if result.Verdict == analysis.VerdictMalicious && hasReasonContaining(result.Reasons, threatFeedReason) {
		t.Fatalf("expected noisy parent feed match under trusted suffix to keep bypass, got %s with reasons %v", result.Verdict, result.Reasons)
	}
}

// PR-08b/M7 shadow: the assessment carries the feed scope trace — exact
// hit, parent hit with depth, or trust bypass — without changing verdicts.
func TestFeedScopeTraceExactMatch(t *testing.T) {
	service, closeService := newTestServiceWithRedis(t)
	defer closeService()

	if _, err := service.redis.ZAdd(context.Background(), defaultThreatFeedKey, redis.Z{
		Score:  float64(time.Now().Add(time.Hour).Unix()),
		Member: "evil.sharepoint.com",
	}); err != nil {
		t.Fatal(err)
	}

	api := service.Analyze(context.Background(), "evil.sharepoint.com", ClientInfo{})
	scope := api.Assessment.Feed
	if scope == nil || !scope.ExactMatch || scope.Candidate != "evil.sharepoint.com" || scope.Depth != 0 {
		t.Fatalf("expected exact scope trace, got %+v", scope)
	}
}

func TestFeedScopeTraceParentDepth(t *testing.T) {
	service, closeService := newTestServiceWithRedis(t)
	defer closeService()

	if _, err := service.redis.ZAdd(context.Background(), defaultThreatFeedKey, redis.Z{
		Score:  float64(time.Now().Add(time.Hour).Unix()),
		Member: "feed-parent.test",
	}); err != nil {
		t.Fatal(err)
	}

	api := service.Analyze(context.Background(), "deep.feed-parent.test", ClientInfo{})
	scope := api.Assessment.Feed
	if scope == nil || scope.ExactMatch || scope.Candidate != "feed-parent.test" || scope.Depth != 1 {
		t.Fatalf("expected parent scope trace depth 1, got %+v", scope)
	}
}

func TestFeedScopeTraceTrustBypass(t *testing.T) {
	service, closeService := newTestServiceWithRedis(t)
	defer closeService()

	if _, err := service.redis.ZAdd(context.Background(), defaultThreatFeedKey, redis.Z{
		Score:  float64(time.Now().Add(time.Hour).Unix()),
		Member: "sharepoint.com",
	}); err != nil {
		t.Fatal(err)
	}

	api := service.Analyze(context.Background(), "quiet-benign-doc.sharepoint.com", ClientInfo{})
	scope := api.Assessment.Feed
	if scope == nil || !scope.TrustBypassed {
		t.Fatalf("expected trust-bypass scope trace, got %+v", scope)
	}
}

func TestFeedScopeTraceAbsentOnMiss(t *testing.T) {
	service, closeService := newTestServiceWithRedis(t)
	defer closeService()

	api := service.Analyze(context.Background(), "quiet-benign-hostname-example.test", ClientInfo{})
	if api.Assessment.Feed != nil {
		t.Fatalf("expected no scope trace on clean miss, got %+v", api.Assessment.Feed)
	}
}
