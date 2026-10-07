package risk

import (
	"context"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"safe-zone/internal/store"
)

func newFeedbackStoreForPruneTest(t *testing.T) (*durableURLFeedbackStore, *store.DB) {
	t.Helper()
	db, err := store.New(filepath.Join(t.TempDir(), "prune.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store := newTestDurableFeedbackStore(db, URLMLFeedbackConfig{
		KeyVersion: 1,
		Secret:     "secret-for-prune-test",
		Retention:  time.Hour,
		MaxRows:    1000,
	})
	return store, db
}

// The in-flight claim has to be taken BEFORE the schedule is advanced.
//
// An earlier version stamped startupPruned and lastPrune first and only then
// tried the claim. So a record that arrived while another prune was running
// consumed the slot, started nothing, and the next record did not consider the
// window due again for ten minutes — which is exactly the guarantee
// startupPruned exists to provide, removed by the code written to provide it.
func TestAFailedPruneClaimLeavesTheScheduleIntact(t *testing.T) {
	feedback, _ := newFeedbackStoreForPruneTest(t)

	// Pretend a prune is already running.
	feedback.pruneInflight.Store(true)
	t.Cleanup(func() { feedback.pruneInflight.Store(false) })

	before := time.Now()
	feedback.maybePrune(context.Background(), before)

	feedback.mu.Lock()
	startupPruned, lastPrune := feedback.startupPruned, feedback.lastPrune
	feedback.mu.Unlock()

	if startupPruned {
		t.Fatal("a record that could not claim the prune slot must not mark the startup prune as done")
	}
	if !lastPrune.IsZero() {
		t.Fatalf("lastPrune = %v, want it left unset so the next record retries", lastPrune)
	}

	// Once the slot frees up, the very next record must prune.
	feedback.pruneInflight.Store(false)
	feedback.maybePrune(context.Background(), before)

	feedback.mu.Lock()
	startupPruned, lastPrune = feedback.startupPruned, feedback.lastPrune
	feedback.mu.Unlock()
	if !startupPruned {
		t.Fatal("the retry after the slot freed must schedule the startup prune")
	}
	if lastPrune.IsZero() {
		t.Fatal("lastPrune must be stamped once the work is genuinely scheduled")
	}
}

// A prune must not be cancelled by an unrelated client hanging up. The
// triggering request's context is cancelled the moment a DoH client
// disconnects, and requests finish while prunes are still querying — so
// binding the prune to it meant retention housekeeping never completed under
// load. Shutdown is the thing that should stop it, and that is the store
// lifecycle.
func TestPruneSurvivesTheTriggeringRequestBeingCancelled(t *testing.T) {
	feedback, _ := newFeedbackStoreForPruneTest(t)

	ctx, cancel := context.WithCancel(context.Background())
	// The request is already gone by the time the hand-off is considered, which
	// is the case that must not start a prune.
	cancel()
	feedback.maybePrune(ctx, time.Now())

	feedback.mu.Lock()
	scheduled := feedback.startupPruned
	feedback.mu.Unlock()
	if scheduled {
		t.Fatal("a request that is already gone must not start background work")
	}

	// A live request does schedule it, and the prune must then be independent of
	// that request's context.
	live, cancelLive := context.WithCancel(context.Background())
	feedback.maybePrune(live, time.Now())
	feedback.mu.Lock()
	scheduled = feedback.startupPruned
	feedback.mu.Unlock()
	if !scheduled {
		t.Fatal("a live request must schedule the startup prune")
	}
	cancelLive()

	// The prune goroutine is detached: waiting for it must return even though the
	// triggering context is already cancelled.
	waited := make(chan struct{})
	go func() {
		defer close(waited)
		feedback.waitForPrune()
	}()
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("waitForPrune did not return: the prune is still bound to the request context")
	}
	if errors := feedback.persistenceErrors.Load(); errors != 0 {
		t.Fatalf("persistenceErrors = %d, want 0: a cancelled request must not fail the prune", errors)
	}
}

// At most one prune may be in flight, and Close must wait for it rather than
// closing the store from under a running query.
func TestCloseWaitsForAnInFlightPrune(t *testing.T) {
	feedback, db := newFeedbackStoreForPruneTest(t)
	ctx := context.Background()
	if err := db.UpsertURLFeedback(ctx, store.URLFeedbackRow{
		Fingerprint: "abc123", KeyVersion: 1, ProbabilityBucket: 5, RecordedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	feedback.maybePrune(ctx, time.Now())

	waited := make(chan struct{})
	go func() {
		defer close(waited)
		feedback.waitForPrune()
	}()
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("waitForPrune never returned")
	}
	if feedback.pruneInflight.Load() {
		t.Fatal("waitForPrune returned while a prune was still marked in flight")
	}
}

// The store lifecycle, not the request, is what stops background work.
func TestPruneIsSkippedAfterShutdown(t *testing.T) {
	db, err := store.New(filepath.Join(t.TempDir(), "shutdown.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Built with a real lifecycle so it can be cancelled, unlike the helper
	// the other tests use.
	lifecycle, cancel := context.WithCancel(context.Background())
	feedback := newDurableURLFeedbackStore(lifecycle, db, URLMLFeedbackConfig{
		KeyVersion: 1, Secret: "secret", Retention: time.Hour, MaxRows: 1000,
	})
	cancel()

	feedback.maybePrune(context.Background(), time.Now())

	feedback.mu.Lock()
	scheduled := feedback.startupPruned
	feedback.mu.Unlock()
	if scheduled {
		t.Fatal("no prune may be scheduled after the store lifecycle is cancelled")
	}
}

func TestWaitForPruneIsNilSafe(t *testing.T) {
	var feedback *durableURLFeedbackStore
	feedback.waitForPrune()
}

// Concurrent records must converge on exactly one prune, and the schedule must
// end up advanced exactly once.
func TestConcurrentRecordsScheduleOnePrune(t *testing.T) {
	feedback, _ := newFeedbackStoreForPruneTest(t)
	feedback.pruneInflight.Store(true) // hold the slot so nothing actually runs

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			feedback.maybePrune(context.Background(), time.Now())
		}()
	}
	wg.Wait()

	feedback.mu.Lock()
	startupPruned := feedback.startupPruned
	feedback.mu.Unlock()
	if startupPruned {
		t.Fatal("no concurrent record may schedule work while the slot is held")
	}

	feedback.pruneInflight.Store(false)
	feedback.maybePrune(context.Background(), time.Now())
	feedback.waitForPrune()
}

// Close must not wait out a running prune's full thirty-second budget. The
// prune is deliberately detached from the request context so an unrelated
// client disconnecting cannot cancel retention work, which means shutdown is the
// only thing that can cut a prune short.
//
// The prune is made genuinely slow with a large expired table rather than with a
// test hook: the store has a single connection and the prune is deleting every
// row, so it genuinely occupies the connection while Close runs.
func TestCloseCutsShortARunningPrune(t *testing.T) {
	db, err := store.New(filepath.Join(t.TempDir(), "prune-close.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Enough expired rows that the prune takes measurable time on the single
	// connection, with a retention that makes every row eligible for deletion.
	ctx := context.Background()
	const rows = 40_000
	for i := range rows {
		if err := db.UpsertURLFeedback(ctx, store.URLFeedbackRow{
			Fingerprint:       "row-" + strconv.Itoa(i),
			KeyVersion:        1,
			ProbabilityBucket: 5,
			RecordedAt:        time.Now().Add(-48 * time.Hour),
		}); err != nil {
			t.Fatalf("seed row %d: %v", i, err)
		}
	}

	lifecycle, cancelLifecycle := context.WithCancel(context.Background())
	feedback := newDurableURLFeedbackStore(lifecycle, db, URLMLFeedbackConfig{
		KeyVersion: 1, Secret: "secret", Retention: time.Hour, MaxRows: 1_000_000,
	})

	feedback.maybePrune(ctx, time.Now())
	// Give the goroutine time to take the connection.
	time.Sleep(50 * time.Millisecond)

	cancelLifecycle()

	start := time.Now()
	feedback.waitForPrune()
	elapsed := time.Since(start)

	// Far below the prune's own budget. Without the lifecycle wired into the
	// prune context this would block for the full timeout.
	if elapsed > 10*time.Second {
		t.Fatalf("waitForPrune took %v; shutdown does not reach a running prune", elapsed)
	}
}
