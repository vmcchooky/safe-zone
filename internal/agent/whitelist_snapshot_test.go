package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/risk"
	"safe-zone/internal/store"
)

// A truncated download or a tampered response must never replace the allow
// list. The checksum is checked against the downloaded body before it is
// parsed.
func TestWhitelistUpdateRejectsChecksumMismatch(t *testing.T) {
	db := newTestDB(t)
	wl := risk.NewWhitelist(db)

	csvContent := "1,google.com\n2,facebook.com\n"
	zipBytes := createMockZipBytes(t, "top1m.csv", csvContent)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipBytes)
	}))
	defer server.Close()

	task := NewWhitelistUpdateTask(db, wl, WhitelistUpdateConfig{
		SourceURL:           server.URL,
		Timeout:             10 * time.Second,
		Enabled:             true,
		AllowPrivateSources: true,
		// The digest of something else entirely.
		SHA256: strings.Repeat("ab", 32),
	})

	if err := task.Run(context.Background()); err == nil {
		t.Fatal("expected the checksum mismatch to fail the import")
	}

	allowed, err := db.IsDomainWhitelisted(context.Background(), "google.com")
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("a rejected download must not reach the allow list")
	}
}

func TestWhitelistUpdateAcceptsMatchingChecksum(t *testing.T) {
	db := newTestDB(t)
	wl := risk.NewWhitelist(db)

	csvContent := "1,google.com\n2,facebook.com\n"
	zipBytes := createMockZipBytes(t, "top1m.csv", csvContent)
	sum := sha256.Sum256(zipBytes)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipBytes)
	}))
	defer server.Close()

	task := NewWhitelistUpdateTask(db, wl, WhitelistUpdateConfig{
		SourceURL:           server.URL,
		Timeout:             10 * time.Second,
		Enabled:             true,
		AllowPrivateSources: true,
		SHA256:              hex.EncodeToString(sum[:]),
	})

	if err := task.Run(context.Background()); err != nil {
		t.Fatalf("expected the matching checksum to be accepted, got %v", err)
	}
	allowed, err := db.IsDomainWhitelisted(context.Background(), "google.com")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("expected google.com to be whitelisted")
	}
}

// The import replaces the allow list wholesale, so the previous set must be
// recoverable.
func TestWhitelistUpdateTakesRollbackSnapshot(t *testing.T) {
	// The safety floor is bypassed deliberately: this test is about the
	// rollback snapshot, not about the floor.
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")

	db := newTestDB(t)
	wl := risk.NewWhitelist(db)

	// Seed a previous allow list the operator curated.
	if err := db.UpdateWhitelist(context.Background(), []string{"curated.example"}); err != nil {
		t.Fatal(err)
	}
	if err := wl.LoadFromDB(); err != nil {
		t.Fatal(err)
	}

	csvContent := "1,google.com\n2,facebook.com\n"
	zipBytes := createMockZipBytes(t, "top1m.csv", csvContent)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipBytes)
	}))
	defer server.Close()

	task := NewWhitelistUpdateTask(db, wl, WhitelistUpdateConfig{
		SourceURL:           server.URL,
		Timeout:             10 * time.Second,
		Enabled:             true,
		AllowPrivateSources: true,
	})

	if err := task.Run(context.Background()); err != nil {
		t.Fatalf("expected the import to succeed, got %v", err)
	}

	snapshot, err := db.LatestWhitelistSnapshot(context.Background())
	if err != nil {
		t.Fatalf("expected a rollback snapshot, got %v", err)
	}
	if snapshot.EntryCount != 1 {
		t.Fatalf("snapshot holds %d entries, want 1", snapshot.EntryCount)
	}
	if len(snapshot.Domains) != 1 || snapshot.Domains[0] != "curated.example" {
		t.Fatalf("snapshot must hold the previous allow list, got %v", snapshot.Domains)
	}
}

// The rollback restores the previous allow list.
func TestWhitelistRollbackRestoresPreviousSet(t *testing.T) {
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")

	db := newTestDB(t)
	wl := risk.NewWhitelist(db)

	if err := db.UpdateWhitelist(context.Background(), []string{"curated.example"}); err != nil {
		t.Fatal(err)
	}
	if err := wl.LoadFromDB(); err != nil {
		t.Fatal(err)
	}

	id, err := db.SaveWhitelistSnapshot(context.Background(), "test", []string{"curated.example"})
	if err != nil {
		t.Fatal(err)
	}

	// A bad import replaces the set.
	if err := db.UpdateWhitelist(context.Background(), []string{"bad.example"}); err != nil {
		t.Fatal(err)
	}
	if err := wl.LoadFromDB(); err != nil {
		t.Fatal(err)
	}
	if wl.IsAllowed(context.Background(), "curated.example") {
		t.Fatal("the bad import should have replaced the allow list")
	}

	restored, err := db.RestoreWhitelistSnapshot(context.Background(), id)
	if err != nil {
		t.Fatalf("expected the rollback to succeed, got %v", err)
	}
	if restored != 1 {
		t.Fatalf("expected 1 restored entry, got %d", restored)
	}
	if err := wl.LoadFromDB(); err != nil {
		t.Fatal(err)
	}
	if !wl.IsAllowed(context.Background(), "curated.example") {
		t.Fatal("the rollback must restore the previous allow list")
	}
}

func TestWhitelistSnapshotPrunesOldCopies(t *testing.T) {
	db := newTestDB(t)

	for i := 0; i < store.MaxWhitelistSnapshots+3; i++ {
		if _, err := db.SaveWhitelistSnapshot(context.Background(), "test", []string{"example.com"}); err != nil {
			t.Fatal(err)
		}
	}

	count, err := db.WhitelistSnapshotCount(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count > store.MaxWhitelistSnapshots {
		t.Fatalf("expected at most %d snapshots, got %d", store.MaxWhitelistSnapshots, count)
	}
}

func TestWhitelistSnapshotNotFound(t *testing.T) {
	db := newTestDB(t)

	if _, err := db.LatestWhitelistSnapshot(context.Background()); err != store.ErrWhitelistSnapshotNotFound {
		t.Fatalf("expected ErrWhitelistSnapshotNotFound, got %v", err)
	}
	if _, err := db.RestoreWhitelistSnapshot(context.Background(), 999); err != store.ErrWhitelistSnapshotNotFound {
		t.Fatalf("expected ErrWhitelistSnapshotNotFound, got %v", err)
	}
}
