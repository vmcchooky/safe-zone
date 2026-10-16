package risk

import (
	"testing"
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
