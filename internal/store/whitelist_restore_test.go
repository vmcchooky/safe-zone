package store

import (
	"context"
	"path/filepath"
	"testing"
)

// A rollback must work in the case it exists for: a bad import replaced a
// small curated list with a huge one, and putting the small list back is a
// large relative drop. The import safety floor compares against the
// current live set, so it refuses exactly that case.
func TestRestoreWhitelistBypassesTheImportFloor(t *testing.T) {
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")

	db, err := New(filepath.Join(t.TempDir(), "restore.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()

	// A small curated list, the kind an operator maintains by hand.
	curated := []string{"curated-one.example", "curated-two.example"}
	if err := db.UpdateWhitelist(ctx, curated); err != nil {
		t.Fatal(err)
	}

	// A bad import replaces it with something much larger.
	large := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		large = append(large, "bad-import-"+string(rune('a'+i%26))+string(rune('a'+(i/26)%26))+".example")
	}
	if err := db.UpdateWhitelist(ctx, large); err != nil {
		t.Fatal(err)
	}
	count, err := db.GetWhitelistCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != len(large) {
		t.Fatalf("the bad import did not land: count=%d want=%d", count, len(large))
	}

	// With the floor armed, putting the small list back is a drop from 200
	// to 2, which the floor refuses.
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "100")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "50")
	if err := db.UpdateWhitelist(ctx, curated); err == nil {
		t.Fatal("expected the import floor to refuse a large relative drop")
	}

	// The restore path must succeed anyway.
	if err := db.RestoreWhitelist(ctx, curated); err != nil {
		t.Fatalf("the restore must not be blocked by the import floor: %v", err)
	}
	count, err = db.GetWhitelistCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != len(curated) {
		t.Fatalf("restored count=%d want=%d", count, len(curated))
	}
}

// A restore must still refuse an entry that would allowlist a whole
// namespace: the public-suffix filter is not a floor and stays in force.
func TestRestoreWhitelistStillFiltersPublicSuffixes(t *testing.T) {
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")

	db, err := New(filepath.Join(t.TempDir(), "restore-filter.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	if err := db.RestoreWhitelist(ctx, []string{"example.com", "com"}); err != nil {
		t.Fatal(err)
	}

	allowed, err := db.IsDomainWhitelisted(ctx, "com")
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("a public suffix must never become an allow-list entry, not even through a restore")
	}
}

// The snapshot restore path uses the floor-free writer.
func TestRestoreWhitelistSnapshotSurvivesASmallerSet(t *testing.T) {
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")

	db, err := New(filepath.Join(t.TempDir(), "restore-snapshot.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	curated := []string{"curated-one.example", "curated-two.example"}
	if err := db.UpdateWhitelist(ctx, curated); err != nil {
		t.Fatal(err)
	}
	id, err := db.SaveWhitelistSnapshot(ctx, "test", curated)
	if err != nil {
		t.Fatal(err)
	}

	large := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		large = append(large, "bad-import-"+string(rune('a'+i%26))+string(rune('a'+(i/26)%26))+".example")
	}
	if err := db.UpdateWhitelist(ctx, large); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "100")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "50")

	restored, err := db.RestoreWhitelistSnapshot(ctx, id)
	if err != nil {
		t.Fatalf("the snapshot rollback must work: %v", err)
	}
	if restored != len(curated) {
		t.Fatalf("restored=%d want=%d", restored, len(curated))
	}
}
