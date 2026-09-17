package risk

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"safe-zone/internal/analysis"
)

// PR-02/H4: pipelined fan-out must keep nearest-first and expiry
// semantics identical to the old sequential walk.
func TestThreatFeedPipelineNearestAndExpiry(t *testing.T) {
	service, closeService := newTestServiceWithRedis(t)
	defer closeService()

	now := float64(time.Now().Unix())
	live := now + 3600
	stale := now - 10
	seeds := []redis.Z{
		{Score: live, Member: "y.parent.test"},
		{Score: stale, Member: "x.y.parent.test"},
		{Score: live, Member: "parent.test"},
	}
	if _, err := service.redis.ZAdd(context.Background(), defaultThreatFeedKey, seeds...); err != nil {
		t.Fatal(err)
	}

	// Exact is stale, parent live, grandparent live: nearest live wins.
	matched, err := service.matchParentCandidate(context.Background(), "x.y.parent.test")
	if err != nil {
		t.Fatal(err)
	}
	if matched != "y.parent.test" {
		t.Fatalf("nearest live parent = %q; want %q", matched, "y.parent.test")
	}
	if depth := feedMatchDepth("x.y.parent.test", matched); depth != 1 {
		t.Fatalf("depth = %d; want 1", depth)
	}

	// All stale: miss, and the analysis falls through to lexical.
	if _, err := service.redis.ZAdd(context.Background(), defaultThreatFeedKey, redis.Z{Score: stale, Member: "lonely.test"}); err != nil {
		t.Fatal(err)
	}
	exactHit, err := service.matchExactThreatFeed(context.Background(), "lonely.test")
	if err != nil {
		t.Fatal(err)
	}
	if exactHit {
		t.Fatal("expired exact member must not match")
	}
	result := service.Analyze(context.Background(), "lonely.test", ClientInfo{})
	if result.Verdict == analysis.VerdictMalicious && hasReasonContaining(result.Reasons, threatFeedReason) {
		t.Fatalf("expired feed member must not block, got %+v", result)
	}
}
