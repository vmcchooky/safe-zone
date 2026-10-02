package risk

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"safe-zone/internal/config"
	"safe-zone/internal/store"
)

func newOverrideTestService(t *testing.T) (*Service, *store.DB) {
	t.Helper()
	db, err := store.New(filepath.Join(t.TempDir(), "override.db"), 30)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	svc := NewService(Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		RedisTimeout:       10 * time.Millisecond,
		Store:              db,
		DisableAdblockSync: true,
	})
	t.Cleanup(func() { _ = svc.Close() })
	return svc, db
}

// stubOverrideLookup installs the read seam for one test.
//
// It exists because the failure branch of the hot path is otherwise
// unreachable: closing the store makes GetEffectiveOverride return (nil, nil)
// rather than an error, and a cancelled context only exercises the caller's
// own context.
//
// Storage goes through the atomic, which is the safe way to swap the seam even
// while other goroutines read it. Store(nil) is the only correct clear.
func stubOverrideLookup(t *testing.T, svc *Service, fn func() (*store.Override, error)) {
	t.Helper()
	stubOverrideLookupWith(t, svc, storeOverrideReader{fn: fn})
}

// storeOverrideReader adapts a bare function to the seam interface.
type storeOverrideReader struct {
	fn func() (*store.Override, error)
}

func (r storeOverrideReader) GetEffectiveOverride(context.Context, int64, string) (*store.Override, error) {
	return r.fn()
}

func stubOverrideLookupWith(t *testing.T, svc *Service, reader overrideReader) {
	t.Helper()
	svc.overrideLookup.Store(&reader)
	t.Cleanup(func() { svc.overrideLookup.Store(nil) })
}

// The seam must be safe to replace while the DNS hot path is reading it, which
// is the whole reason it is an atomic.
func TestOverrideLookupSeamIsSafeToReplaceConcurrently(t *testing.T) {
	svc, _ := newOverrideTestService(t)
	ctx := context.Background()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = svc.lookupEffectiveOverride(ctx, 1, "x.example")
			}
		}()
	}

	for range 200 {
		stubOverrideLookupWith(t, svc, storeOverrideReader{fn: func() (*store.Override, error) {
			return nil, errStoreUnavailable
		}})
		// Store(nil) is the only correct clear: a pointer to a nil interface
		// is representable and panics when called through.
		svc.overrideLookup.Store(nil)
	}
	close(stop)
	wg.Wait()
}

// A pointer to a nil reader must be treated as no seam and fall through to the
// store, not panic. The interface type does not remove this trap: atomic.Pointer
// can only hold *T, so *T is always a pointer to something, and that something
// can be a nil interface.
func TestOverrideLookupIgnoresAPointerToANilReader(t *testing.T) {
	svc, db := newOverrideTestService(t)
	ctx := t.Context()
	if err := db.UpsertOverride(ctx, "real.example", "block", "kept"); err != nil {
		t.Fatal(err)
	}

	var nilReader overrideReader
	svc.overrideLookup.Store(&nilReader)

	got, err := svc.lookupEffectiveOverride(ctx, 1, "real.example")
	if err != nil {
		t.Fatalf("a pointer to a nil reader must fall through to the store, not panic: %v", err)
	}
	if got == nil || got.Action != "block" {
		t.Fatalf("expected the store override, got %+v", got)
	}
}

// A nil reader must be treated as "no seam installed" and fall through to the
// store. With a bare func this state was representable as a pointer to a nil
// function, which panics when called — see the interface choice on the field.
func TestOverrideLookupFallsThroughWhenTheSeamIsCleared(t *testing.T) {
	svc, db := newOverrideTestService(t)
	ctx := t.Context()
	if err := db.UpsertOverride(ctx, "real.example", "block", "kept"); err != nil {
		t.Fatal(err)
	}

	svc.overrideLookup.Store(nil)

	got, err := svc.lookupEffectiveOverride(ctx, 1, "real.example")
	if err != nil {
		t.Fatalf("a cleared seam must fall through to the store: %v", err)
	}
	if got == nil || got.Action != "block" {
		t.Fatalf("expected the store override, got %+v", got)
	}
}

// The healthy path must not count anything: a zero counter is the signal an
// operator alerts on, so it has to mean "no failures", not "never measured".
func TestOverrideLookupSucceedsWithoutCountingAFailure(t *testing.T) {
	svc, db := newOverrideTestService(t)
	ctx := t.Context()

	if err := db.UpsertOverride(ctx, "blocked.example", "block", "INC-1"); err != nil {
		t.Fatalf("seed override: %v", err)
	}

	got, err := svc.lookupEffectiveOverride(ctx, 1, "blocked.example")
	if err != nil {
		t.Fatalf("lookup failed on a healthy store: %v", err)
	}
	if got == nil || got.Action != "block" {
		t.Fatalf("expected the block override, got %+v", got)
	}
	if failures := svc.OverrideLookupFailures(); failures != 0 {
		t.Fatalf("override_lookup_failures = %d, want 0", failures)
	}
}

// A missing override is not a failure. The store returns (nil, nil) for "no
// such override", and counting that would make the counter meaningless.
func TestOverrideLookupMissIsNotCountedAsAFailure(t *testing.T) {
	svc, _ := newOverrideTestService(t)

	got, err := svc.lookupEffectiveOverride(t.Context(), 1, "never-blocked.example")
	if err != nil {
		t.Fatalf("a miss must not be an error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected no override, got %+v", got)
	}
	if failures := svc.OverrideLookupFailures(); failures != 0 {
		t.Fatalf("override_lookup_failures = %d, want 0 for a plain miss", failures)
	}
}

var errStoreUnavailable = errors.New("simulated store failure")

// The core regression: a store read that fails must be counted and logged,
// never swallowed. The previous code assigned the error to a variable that was
// never read, so a domain the operator had blocked was evaluated normally with
// no signal anywhere.
func TestOverrideLookupFailureIsCountedAndLoud(t *testing.T) {
	svc, _ := newOverrideTestService(t)
	stubOverrideLookup(t, svc, func() (*store.Override, error) {
		return nil, errStoreUnavailable
	})

	if _, err := svc.lookupEffectiveOverride(t.Context(), 1, "blocked.example"); !errors.Is(err, errStoreUnavailable) {
		t.Fatalf("error = %v, want the store error to surface", err)
	}
	status := svc.DecisionPipelineStatus()
	if status.OverrideLookupFailures != 1 {
		t.Fatalf("override_lookup_failures = %d, want 1", status.OverrideLookupFailures)
	}
	if status.OverrideConsecutiveFailures != 1 {
		t.Fatalf("override_consecutive_failures = %d, want 1", status.OverrideConsecutiveFailures)
	}
	if status.LastFailureAt == "" {
		t.Fatal("last_failure_at must be stamped so an alert rule can compare it")
	}
	if status.LastSuccessAt != "" {
		t.Fatal("last_success_at must be empty until a read succeeds")
	}

	// The total keeps accumulating rather than saturating.
	for range 3 {
		if _, err := svc.lookupEffectiveOverride(t.Context(), 1, "blocked.example"); err == nil {
			t.Fatal("expected an error")
		}
	}
	status = svc.DecisionPipelineStatus()
	if status.OverrideLookupFailures != 4 {
		t.Fatalf("override_lookup_failures = %d, want 4", status.OverrideLookupFailures)
	}
	if status.OverrideConsecutiveFailures != 4 {
		t.Fatalf("override_consecutive_failures = %d, want 4", status.OverrideConsecutiveFailures)
	}
}

// consecutiveFailures is the number that actually separates "broken right now"
// from "failed a few times since boot". A monotonic total cannot.
func TestConsecutiveFailuresResetOnTheFirstSuccess(t *testing.T) {
	svc, _ := newOverrideTestService(t)
	failing := true
	stubOverrideLookup(t, svc, func() (*store.Override, error) {
		if failing {
			return nil, errStoreUnavailable
		}
		return &store.Override{Domain: "x.example", Action: "block"}, nil
	})

	for range 3 {
		if _, err := svc.lookupEffectiveOverride(t.Context(), 1, "x.example"); err == nil {
			t.Fatal("expected an error")
		}
	}
	if got := svc.DecisionPipelineStatus().OverrideConsecutiveFailures; got != 3 {
		t.Fatalf("consecutive = %d, want 3", got)
	}

	failing = false
	if _, err := svc.lookupEffectiveOverride(t.Context(), 1, "x.example"); err != nil {
		t.Fatal("expected the recovered read to succeed")
	}
	status := svc.DecisionPipelineStatus()
	if status.OverrideConsecutiveFailures != 0 {
		t.Fatalf("consecutive = %d, want 0 after recovery", status.OverrideConsecutiveFailures)
	}
	if status.OverrideLookupFailures != 3 {
		t.Fatalf("total = %d, want the 3 historical failures preserved", status.OverrideLookupFailures)
	}
	if status.LastSuccessAt == "" {
		t.Fatal("last_success_at must be stamped on recovery")
	}
}

// The lookup must not stall the hot path when the store is failing. An earlier
// version retried once after a 15 ms pause, which added that delay to every
// request during a sustained failure: the case where a retry helps least.
func TestOverrideLookupDoesNotDelayOnFailure(t *testing.T) {
	svc, _ := newOverrideTestService(t)

	// Counting store reads rather than timing them. The failure path logs a
	// warning per call, so a duration assertion measures stdout on a busy
	// machine and says nothing about whether a retry happens.
	calls := 0
	stubOverrideLookup(t, svc, func() (*store.Override, error) {
		calls++
		return nil, errStoreUnavailable
	})

	const attempts = 20
	for range attempts {
		if _, err := svc.lookupEffectiveOverride(t.Context(), 1, "x.example"); err == nil {
			t.Fatal("expected an error")
		}
	}
	if calls != attempts {
		t.Fatalf("%d store reads for %d attempts, want exactly one each: the failure path must not retry", calls, attempts)
	}
}

func TestDecisionPipelineStatusOnAFreshService(t *testing.T) {
	svc, _ := newOverrideTestService(t)
	status := svc.DecisionPipelineStatus()
	if status.OverrideLookupFailures != 0 || status.OverrideConsecutiveFailures != 0 {
		t.Fatalf("a fresh service reports %+v, want all zero", status)
	}
	if status.LastFailureAt != "" || status.LastSuccessAt != "" {
		t.Fatalf("a fresh service must have no stamps: %+v", status)
	}
}

func TestOverrideLookupFailuresIsNilSafe(t *testing.T) {
	var svc *Service
	if got := svc.OverrideLookupFailures(); got != 0 {
		t.Fatalf("nil service reports %d, want 0", got)
	}
	if got := svc.DecisionPipelineStatus(); got.OverrideLookupFailures != 0 {
		t.Fatalf("nil service reports %+v, want zeroed", got)
	}
}
