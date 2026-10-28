package risk

import (
	"context"
	"testing"

	"safe-zone/internal/config"
)

// A failed client-group lookup must stay fail-open — a store error cannot block
// every client — but it used to move that client to the built-in default group
// with no log, counter or status field anywhere. The fallback is still applied;
// the difference is that it is now observable.
func TestClientGroupLookupFailureIsCountedAndFailsOpen(t *testing.T) {
	svc := newTestServiceWithStore(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	group := svc.resolveClientGroup(ctx, ClientInfo{IP: "203.0.113.7"}, &layerTimer{})
	if group == nil || group.Name != "default" || group.ID != 1 || !group.StrictMalware {
		t.Fatalf("expected the built-in default group, got %+v", group)
	}

	status := svc.DecisionPipelineStatus()
	if status.GroupLookupFailures != 1 {
		t.Fatalf("group_lookup_failures = %d, want 1", status.GroupLookupFailures)
	}
	if status.GroupConsecutiveFailures != 1 {
		t.Fatalf("group_consecutive_failures = %d, want 1", status.GroupConsecutiveFailures)
	}
	if status.GroupLastFailureAt == "" {
		t.Fatal("group_last_failure_at must be stamped so an alert rule can compare it")
	}
	if status.GroupLastSuccessAt != "" {
		t.Fatal("group_last_success_at must stay empty until a lookup succeeds")
	}

	// The total keeps accumulating rather than saturating.
	for range 3 {
		svc.resolveClientGroup(ctx, ClientInfo{IP: "203.0.113.7"}, &layerTimer{})
	}
	status = svc.DecisionPipelineStatus()
	if status.GroupLookupFailures != 4 {
		t.Fatalf("group_lookup_failures = %d, want 4", status.GroupLookupFailures)
	}
	if status.GroupConsecutiveFailures != 4 {
		t.Fatalf("group_consecutive_failures = %d, want 4", status.GroupConsecutiveFailures)
	}
}

// The healthy path must not count anything: zero has to mean "no failures",
// not "never measured".
func TestClientGroupLookupSuccessCountsNothing(t *testing.T) {
	svc := newTestServiceWithStore(t)

	group := svc.resolveClientGroup(t.Context(), ClientInfo{IP: "203.0.113.7"}, &layerTimer{})
	if group == nil || group.Name != "default" {
		t.Fatalf("expected the store's default group, got %+v", group)
	}

	status := svc.DecisionPipelineStatus()
	if status.GroupLookupFailures != 0 || status.GroupConsecutiveFailures != 0 {
		t.Fatalf("a healthy lookup reports %+v, want all zero", status)
	}
	if status.GroupLastFailureAt != "" || status.GroupLastSuccessAt != "" {
		t.Fatalf("a healthy lookup must not stamp failure or recovery: %+v", status)
	}
}

// GroupConsecutiveFailures is what separates "broken right now" from "failed a
// few times since boot", so the first success has to clear it while leaving the
// historical total intact.
func TestClientGroupLookupSuccessResetsConsecutiveFailures(t *testing.T) {
	svc := newTestServiceWithStore(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 3 {
		svc.resolveClientGroup(ctx, ClientInfo{IP: "203.0.113.7"}, &layerTimer{})
	}
	if got := svc.DecisionPipelineStatus().GroupConsecutiveFailures; got != 3 {
		t.Fatalf("consecutive = %d, want 3", got)
	}

	svc.resolveClientGroup(t.Context(), ClientInfo{IP: "203.0.113.7"}, &layerTimer{})

	status := svc.DecisionPipelineStatus()
	if status.GroupConsecutiveFailures != 0 {
		t.Fatalf("consecutive = %d, want 0 after recovery", status.GroupConsecutiveFailures)
	}
	if status.GroupLookupFailures != 3 {
		t.Fatalf("total = %d, want the 3 historical failures preserved", status.GroupLookupFailures)
	}
	if status.GroupLastSuccessAt == "" {
		t.Fatal("group_last_success_at must be stamped on recovery")
	}
}

// A service with no store has no assignment to look up, by design; that is not
// a degraded lookup and must not inflate the failure counters.
func TestClientGroupLookupWithoutAStoreIsNotAFailure(t *testing.T) {
	svc := NewService(Options{AnalysisConfig: config.DefaultAnalysisConfig()})
	t.Cleanup(func() { _ = svc.Close() })

	group := svc.resolveClientGroup(t.Context(), ClientInfo{IP: "203.0.113.7"}, &layerTimer{})
	if group == nil || group.Name != "default" {
		t.Fatalf("expected the built-in default group, got %+v", group)
	}
	if status := svc.DecisionPipelineStatus(); status.GroupLookupFailures != 0 {
		t.Fatalf("group_lookup_failures = %d, want 0 without a store", status.GroupLookupFailures)
	}
}
