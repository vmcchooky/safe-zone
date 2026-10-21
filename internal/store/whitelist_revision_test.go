package store

import (
	"context"
	"path/filepath"
	"testing"
)

// The revision is the signal the other process polls. It must advance on every
// successful replace, including the floor-free restore path, and must not
// advance when a replace is rejected: a revision that moved without the rows
// would tell dns-resolver to reload a set that never changed.
func TestWhitelistRevisionTracksSuccessfulReplaces(t *testing.T) {
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")

	db, err := New(filepath.Join(t.TempDir(), "revision.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()

	revision, err := db.GetWhitelistRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if revision != 0 {
		t.Fatalf("a store that never held a whitelist must report revision 0, got %d", revision)
	}

	if err := db.UpdateWhitelist(ctx, []string{"first.example"}); err != nil {
		t.Fatal(err)
	}
	revision, err = db.GetWhitelistRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if revision != 1 {
		t.Fatalf("after the first replace revision = %d, want 1", revision)
	}

	if err := db.UpdateWhitelist(ctx, []string{"second.example"}); err != nil {
		t.Fatal(err)
	}
	revision, err = db.GetWhitelistRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if revision != 2 {
		t.Fatalf("after the second replace revision = %d, want 2", revision)
	}

	// A restore is a replace: dns-resolver has to notice it too.
	if err := db.RestoreWhitelist(ctx, []string{"first.example"}); err != nil {
		t.Fatal(err)
	}
	revision, err = db.GetWhitelistRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if revision != 3 {
		t.Fatalf("after a restore revision = %d, want 3", revision)
	}

	// Arm the floor and make an import that it rejects.
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "100")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "50")
	if err := db.UpdateWhitelist(ctx, []string{"rejected.example"}); err == nil {
		t.Fatal("expected the import floor to reject the replace")
	}
	revision, err = db.GetWhitelistRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if revision != 3 {
		t.Fatalf("a rejected replace must not bump the revision, got %d want 3", revision)
	}
}
