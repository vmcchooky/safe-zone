package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
	"safe-zone/internal/feed"
	"safe-zone/internal/risk"
)

// PR-08a/M2: promoting a parent must not leave a stale cached SAFE verdict
// on its children. The task bumps the feed revision once per cycle with
// promotions, so child entries fail the epoch check and recompute against
// the fresh feed (parent-walk match).
func TestOSINTTaskPromotionInvalidatesChildCache(t *testing.T) {
	_, redisCache := newTestRedis(t)
	db := newTestStore(t)

	parent := "coherencebank.test"
	child := "cdn.coherencebank.test"

	service := risk.NewService(risk.Options{
		Redis:          redisCache,
		RedisTimeout:   time.Second,
		AnalysisConfig: config.DefaultAnalysisConfig(),
		ThreatFeedKey:  testThreatKey,
	})
	defer func() { _ = service.Close() }()

	before := service.Analyze(context.Background(), child, risk.ClientInfo{})
	if before.Verdict != analysis.VerdictSafe {
		t.Fatalf("precondition: expected child to cache SAFE, got %s (reasons %v)", before.Verdict, before.Reasons)
	}

	seedSuspiciousDomains(t, db, parent, 2)
	task := newOSINTTestTask(db, redisCache, &fakeEvidence{enabled: true, report: newBlockedReport()}, 48*time.Hour)
	if err := task.Run(context.Background()); err != nil {
		t.Fatalf("run osint task: %v", err)
	}

	rev, err := redisCache.GetString(context.Background(), feed.RevisionKey(testThreatKey))
	if err != nil || rev == "" {
		t.Fatalf("expected feed revision bump after promotion cycle, got %q (err: %v)", rev, err)
	}

	after := service.Analyze(context.Background(), child, risk.ClientInfo{})
	if after.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected child to recompute to malicious after parent promotion, got %s (reasons %v)", after.Verdict, after.Reasons)
	}
	matched := false
	for _, reason := range after.Reasons {
		if strings.Contains(reason, threatFeedMatchReason) {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("expected threat feed reason for child after parent promotion, got %v", after.Reasons)
	}
}

// A promotion-free cycle must not churn the feed revision: no feed change,
// no cache invalidation.
func TestOSINTTaskWithoutPromotionKeepsFeedRevision(t *testing.T) {
	_, redisCache := newTestRedis(t)
	db := newTestStore(t)

	before, _ := redisCache.GetString(context.Background(), feed.RevisionKey(testThreatKey))

	task := newOSINTTestTask(db, redisCache, &fakeEvidence{enabled: false}, 48*time.Hour)
	if err := task.Run(context.Background()); err != nil {
		t.Fatalf("run osint task: %v", err)
	}

	after, _ := redisCache.GetString(context.Background(), feed.RevisionKey(testThreatKey))
	if before != after {
		t.Fatalf("expected feed revision to stay %q without promotions, got %q", before, after)
	}
}
