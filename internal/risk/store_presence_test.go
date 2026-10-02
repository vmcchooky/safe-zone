package risk

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"safe-zone/internal/store"
)

// The RB-3 guard refuses to serve production without persistence. Its live
// trigger is a store that fails to open, not a nil store: store.New returns
// (nil, nil) only for an empty path, and config.String substitutes the default
// for an empty variable, so that path cannot be reached from configuration.
func TestProductionRefusesToStartWithoutAStore(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "production")
	// A path that cannot be opened: a file where a directory has to go.
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAFE_ZONE_SQLITE_PATH", filepath.Join(blocker, "sub", "safe-zone.db"))

	_, err := NewServiceFromEnvForRoleE("")
	if err == nil {
		t.Fatal("production started with no usable store: the control plane would be silently absent")
	}
	if !contains(err.Error(), "refusing to serve without persistence") {
		t.Fatalf("error = %v, want it to name the RB-3 refusal", err)
	}
}

// The same configuration outside production keeps the warn-and-continue
// behaviour, so local development without a database still works.
func TestNonProductionMayStartWithoutAStore(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "local")
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAFE_ZONE_SQLITE_PATH", filepath.Join(blocker, "sub", "safe-zone.db"))

	svc, err := NewServiceFromEnvForRoleE("")
	if err != nil {
		t.Fatalf("a local run without a usable store must still start: %v", err)
	}
	if svc != nil {
		_ = svc.Close()
	}
}

// A store that was closed rather than never opened must be treated as
// unavailable too: StoreDB hands back the handle without checking Enabled().
func TestClosedStoreReportsItselfUnavailable(t *testing.T) {
	db, err := store.New(filepath.Join(t.TempDir(), "closed.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	if !db.Enabled() {
		t.Fatal("precondition: a freshly opened store should be enabled")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if db.Enabled() {
		t.Fatal("a closed store must report itself disabled")
	}
}

// The RAM index is the last line of defence for the whitelist: if it is replaced
// with an empty one, every whitelisted domain falls through to the decision
// pipeline where any layer can block it. The poison floor upstream makes this
// unreachable today, so it is asserted directly.
func TestEmptyTableDoesNotReplaceAPopulatedIndex(t *testing.T) {
	db, err := store.New(filepath.Join(t.TempDir(), "index.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// The floor is bypassed deliberately: this test is about the guard that
	// stands behind it, not about the floor itself.
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")

	ctx := context.Background()
	if err := db.UpdateWhitelist(ctx, []string{"example.com", "tpb.vn"}); err != nil {
		t.Fatal(err)
	}
	w := NewWhitelist(db)
	if err := w.LoadFromDB(); err != nil {
		t.Fatal(err)
	}
	if w.ExactCount() != 2 {
		t.Fatalf("index holds %d entries, want 2", w.ExactCount())
	}

	if err := db.UpdateWhitelist(ctx, []string{}); err != nil {
		t.Fatal(err)
	}
	if err := w.LoadFromDB(); err != nil {
		t.Fatal(err)
	}

	if w.ExactCount() != 2 {
		t.Fatalf("index holds %d entries after an empty table, want the previous 2 retained", w.ExactCount())
	}
	if !w.IsAllowed(ctx, "mail.example.com") {
		t.Fatal("a whitelisted domain stopped resolving after the table emptied: it would fall through to the pipeline and could be blocked")
	}
}

// An empty index over an empty store is still honoured — otherwise a service
// with no whitelist at all would report entries it does not have.
func TestEmptyTableIsHonouredWhenNothingWasLoaded(t *testing.T) {
	db, err := store.New(filepath.Join(t.TempDir(), "index-empty.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")

	w := NewWhitelist(db)
	if err := w.LoadFromDB(); err != nil {
		t.Fatal(err)
	}
	if w.ExactCount() != 0 {
		t.Fatalf("index holds %d entries, want 0", w.ExactCount())
	}
	if w.IsAllowed(context.Background(), "example.com") {
		t.Fatal("nothing is whitelisted, so nothing should match")
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
