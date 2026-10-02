package risk

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"safe-zone/internal/store"
)

func newWhitelistStore(t *testing.T, name string) *store.DB {
	t.Helper()
	db, err := store.New(filepath.Join(t.TempDir(), name), 30)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// The point of the RAM index: a lookup must not depend on the database at all.
// The store is closed outright, so anything still reaching for it fails loudly
// rather than silently returning "not whitelisted".
func TestWhitelistLookupsSurviveAClosedStore(t *testing.T) {
	db := newWhitelistStore(t, "closed.db")
	if err := db.UpdateWhitelist(context.Background(), []string{"example.com", "tpb.vn"}); err != nil {
		t.Fatal(err)
	}

	w := NewWhitelist(db)
	if err := w.LoadFromDB(); err != nil {
		t.Fatal(err)
	}

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	for _, domain := range []string{"example.com", "mail.example.com", "tpb.vn", "deep.sub.tpb.vn"} {
		if !w.IsAllowed(ctx, domain) {
			t.Fatalf("%q should still be allowlisted with the store closed", domain)
		}
	}
	for _, domain := range []string{"evil.com", "sub.evil.com", "notexample.com"} {
		if w.IsAllowed(ctx, domain) {
			t.Fatalf("%q must not be allowlisted", domain)
		}
	}
}

// No read lock is held while a reload happens. A reload used to hold the single
// database connection for seconds, and a lookup waiting behind it consumed the
// caller's whole deadline; the RAM index removes the wait, and this holds the
// lookup path to the same lock the reload needs.
func TestIsAllowedDoesNotBlockAReload(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SAFE_ZONE_FEED_FILE_ROOT", dir)

	var lines []byte
	for i := range 200_000 {
		lines = append(lines, "h"+strconv.Itoa(i)+".example\n"...)
	}
	if err := os.WriteFile(filepath.Join(dir, "whitelist.txt"), lines, 0o600); err != nil {
		t.Fatal(err)
	}

	w := NewWhitelist(nil)
	if err := w.LoadFromFile("whitelist.txt"); err != nil {
		t.Fatal(err)
	}
	if w.ExactCount() != 200_000 {
		t.Fatalf("index holds %d entries, want 200000", w.ExactCount())
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := w.LoadFromFile("whitelist.txt"); err != nil {
			t.Errorf("reload: %v", err)
		}
	}()

	// Every lookup must complete promptly even mid-reload.
	worst := time.Duration(0)
	for range 500 {
		start := time.Now()
		if !w.IsAllowed(context.Background(), "h42.example") {
			t.Fatal("a known entry answered false during a reload")
		}
		if elapsed := time.Since(start); elapsed > worst {
			worst = elapsed
		}
	}
	if worst > time.Second {
		t.Fatalf("worst lookup took %v during a reload", worst)
	}
	<-done
}

// A lookup walks the published index without the lock while a reload replaces
// it, so the two must not race. Run under -race.
func TestIsAllowedIsRaceFreeAcrossAReload(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SAFE_ZONE_FEED_FILE_ROOT", dir)

	write := func(seed int) {
		t.Helper()
		var lines []byte
		for i := range 500 {
			lines = append(lines, "s"+strconv.Itoa(seed)+"-"+strconv.Itoa(i)+".example\n"...)
		}
		if err := os.WriteFile(filepath.Join(dir, "whitelist.txt"), lines, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	w := NewWhitelist(nil)
	write(0)
	if err := w.LoadFromFile("whitelist.txt"); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			for i := range 50 {
				write(i)
				if err := w.LoadFromFile("whitelist.txt"); err != nil {
					t.Error(err)
					return
				}
			}
		}
	}()

	for range 3000 {
		_ = w.IsAllowed(context.Background(), "s0-1.example")
		_ = w.IsAllowed(context.Background(), "absent.example")
	}
	close(stop)
	wg.Wait()

	if w.ExactCount() != 500 {
		t.Fatalf("index holds %d entries, want 500", w.ExactCount())
	}
}

// Metrics must read every field from its snapshot, never from the live struct.
// It used to read w.bloom.k directly, which raced a concurrent reload and
// could dereference nil after a reload emptied the table: the agent handler
// calls Metrics while the cache-flush handler calls LoadFromDB.
func TestMetricsRacesSafelyAgainstAReload(t *testing.T) {
	// The anti-poisoning floor refuses to empty a populated whitelist, which is
	// the right behaviour but blocks the case under test.
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")

	db := newWhitelistStore(t, "metrics-race.db")
	if err := db.UpdateWhitelist(context.Background(), []string{"one.example", "two.example"}); err != nil {
		t.Fatal(err)
	}

	w := NewWhitelist(db)
	if err := w.LoadFromDB(); err != nil {
		t.Fatal(err)
	}

	// Precondition: the branch that was wrong must actually be taken.
	if got := w.Metrics().BloomHashes; got == 0 {
		t.Fatal("precondition: BloomHashes should be non-zero for a loaded filter")
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = w.Metrics()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 300 {
			if i%3 == 0 {
				if err := db.UpdateWhitelist(context.Background(), []string{}); err != nil {
					t.Errorf("empty the whitelist: %v", err)
					return
				}
			} else {
				_ = db.UpdateWhitelist(context.Background(), []string{"one.example", "two.example", "three.example"})
			}
			_ = w.LoadFromDB()
		}
	}()

	for range 300 {
		_ = w.Metrics()
	}
	close(stop)
	wg.Wait()
}
