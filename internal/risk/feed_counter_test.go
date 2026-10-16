package risk

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"safe-zone/internal/cache"
	"safe-zone/internal/config"
)

// The feed IOC layer fails open by design; these counters are the only
// signal that it is blind, so their bookkeeping gets its own test.
func TestFeedLookupFailureCounters(t *testing.T) {
	e := &FeedEngine{}
	if got := e.feedLookupFailures.Load(); got != 0 {
		t.Fatalf("initial failures = %d, want 0", got)
	}
	e.noteFeedLookupErr()
	e.noteFeedLookupErr()
	if got := e.feedLookupFailures.Load(); got != 2 {
		t.Fatalf("failures = %d, want 2", got)
	}
	if got := e.feedConsecutiveFailures.Load(); got != 2 {
		t.Fatalf("consecutive = %d, want 2", got)
	}
	if got := e.feedLastFailureUnix.Load(); got <= 0 {
		t.Fatalf("last failure unix = %d, want positive", got)
	}
	e.noteFeedLookupSuccess()
	if got := e.feedConsecutiveFailures.Load(); got != 0 {
		t.Fatalf("consecutive after success = %d, want 0", got)
	}
	// The total is monotonic: recovery must not erase history.
	if got := e.feedLookupFailures.Load(); got != 2 {
		t.Fatalf("total after success = %d, want 2", got)
	}
	var nilEngine *FeedEngine
	nilEngine.noteFeedLookupErr()
	nilEngine.noteFeedLookupSuccess()
}

// A dead Redis must surface in DecisionPipelineStatus: the /v1/status
// endpoint builds its decision_pipeline block from this constructor, so a
// field the constructor forgets stays zero on the dashboard forever.
func TestDecisionPipelineStatusReportsFeedFailures(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		Redis:              cache.NewRedis(server.Addr(), "", 0),
		DisableAdblockSync: true,
		RedisTimeout:       2 * time.Second,
	})
	t.Cleanup(func() {
		_ = service.Close()
	})
	// Kill Redis: every subsequent feed read fails fast with connection
	// refused instead of hanging to the timeout.
	server.Close()

	service.feed.feedResult(context.Background(), "unreachable.test", nil)
	service.feed.feedResult(context.Background(), "unreachable.test", nil)

	status := service.DecisionPipelineStatus()
	if status.FeedLookupFailures < 2 {
		t.Fatalf("FeedLookupFailures = %d, want >= 2", status.FeedLookupFailures)
	}
	if status.FeedConsecutiveFailures != status.FeedLookupFailures {
		t.Fatalf("consecutive = %d, total = %d: no success happened, they must match",
			status.FeedConsecutiveFailures, status.FeedLookupFailures)
	}
	if status.FeedLastFailureAt == "" {
		t.Fatal("FeedLastFailureAt must be stamped after failures")
	}
}

func TestFeedLookupFailureAccessorsNilSafe(t *testing.T) {
	var s *Service
	if got := s.FeedLookupFailures(); got != 0 {
		t.Fatalf("nil service failures = %d, want 0", got)
	}
	if got := s.FeedConsecutiveLookupFailures(); got != 0 {
		t.Fatalf("nil service consecutive = %d, want 0", got)
	}
	if got := s.FeedLastLookupFailureUnix(); got != 0 {
		t.Fatalf("nil service last failure = %d, want 0", got)
	}
	if got := (&Service{}).FeedLookupFailures(); got != 0 {
		t.Fatalf("empty service failures = %d, want 0", got)
	}
}
