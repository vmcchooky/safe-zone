package risk

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"safe-zone/internal/config"
)

// A failed allow-list load used to be discarded at the call site, so the
// service ran with an empty allow list and nothing said so. The allow list
// is the primary safety valve: a whitelisted domain short-circuits the feed,
// lexical, ML, AI, OSINT and group enforcement layers.
func TestWhitelistRecordsLoadFailureFromStore(t *testing.T) {
	db := newWhitelistStore(t, "load-failure.db")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")

	root := t.TempDir()
	t.Setenv("SAFE_ZONE_FEED_FILE_ROOT", root)
	writeWhitelistFile(t, root, "whitelist.csv", "example.com\ntpb.vn\n")

	w := NewWhitelist(db)
	if err := w.LoadFromFile("whitelist.csv"); err != nil {
		t.Fatalf("the first load should succeed: %v", err)
	}
	if !w.LoadStatus().Loaded {
		t.Fatal("a successful load must report loaded")
	}
	if err := w.LoadError(); err != nil {
		t.Fatalf("a successful load must not record an error, got %v", err)
	}

	// The safety floor now rejects the import, which is how a truncated or
	// misconfigured feed reaches the whitelist in production.
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "100")
	if err := w.LoadFromFile("whitelist.csv"); err == nil {
		t.Fatal("expected the load below the safety floor to fail")
	}
	if w.LoadError() == nil {
		t.Fatal("the load failure must be recorded")
	}
	status := w.LoadStatus()
	if status.Loaded {
		t.Fatal("a failed load must report loaded=false")
	}
	if status.Error == "" {
		t.Fatal("the load status must carry the failure")
	}
}

// writeWhitelistFile writes a whitelist file into the feed root.
func writeWhitelistFile(t *testing.T, root, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestWhitelistRecordsLoadFailureFromMissingFile(t *testing.T) {
	t.Setenv("SAFE_ZONE_FEED_FILE_ROOT", t.TempDir())

	w := NewWhitelist(nil)
	err := w.LoadFromFile("whitelist-that-does-not-exist.csv")
	if err == nil {
		t.Fatal("a configured but missing allow list must be an error")
	}
	if w.LoadError() == nil {
		t.Fatal("the load failure must be recorded")
	}
	if w.LoadStatus().Loaded {
		t.Fatal("a failed load must report loaded=false")
	}
}

func TestWhitelistEmptyPathIsNotAFailure(t *testing.T) {
	w := NewWhitelist(nil)
	if err := w.LoadFromFile(""); err != nil {
		t.Fatalf("an unset allow list path must not be an error, got %v", err)
	}
	if !w.LoadStatus().Loaded {
		t.Fatal("an unset allow list path is not a load failure")
	}
}

// The service must surface the failure instead of swallowing it.
func TestServiceSurfacesWhitelistLoadFailure(t *testing.T) {
	t.Setenv("SAFE_ZONE_FEED_FILE_ROOT", t.TempDir())

	service := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		RedisTimeout:   10 * time.Millisecond,
		TTLAllowed:     time.Hour,
		TTLSuspicious:  time.Hour,
		TTLBlocked:     time.Hour,
		RecentLimit:    10,
		WhitelistPath:  "whitelist-that-does-not-exist.csv",
	})
	t.Cleanup(func() { _ = service.Close() })

	if service.Whitelist().LoadError() == nil {
		t.Fatal("the service must expose the allow list load failure")
	}
	if service.Whitelist().LoadStatus().Loaded {
		t.Fatal("the service must report the allow list as not loaded")
	}
}

// A successful load through the service keeps the allow list in effect.
func TestServiceReportsHealthyWhitelist(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SAFE_ZONE_FEED_FILE_ROOT", root)
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")

	path := filepath.Join(root, "whitelist.csv")
	if err := os.WriteFile(path, []byte("example.com\ntpb.vn\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	service := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		RedisTimeout:   10 * time.Millisecond,
		TTLAllowed:     time.Hour,
		TTLSuspicious:  time.Hour,
		TTLBlocked:     time.Hour,
		RecentLimit:    10,
		WhitelistPath:  "whitelist.csv",
	})
	t.Cleanup(func() { _ = service.Close() })

	if err := service.Whitelist().LoadError(); err != nil {
		t.Fatalf("expected a healthy allow list, got %v", err)
	}
	if !service.Whitelist().IsAllowed(context.Background(), "example.com") {
		t.Fatal("the allow list should be in effect")
	}
}

// A rejected import must not leave the allow list silently empty.
func TestWhitelistLoadFailureKeepsPreviousIndex(t *testing.T) {
	db := newWhitelistStore(t, "keep-index.db")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")

	root := t.TempDir()
	t.Setenv("SAFE_ZONE_FEED_FILE_ROOT", root)
	writeWhitelistFile(t, root, "whitelist.csv", "example.com\n")

	w := NewWhitelist(db)
	if err := w.LoadFromFile("whitelist.csv"); err != nil {
		t.Fatal(err)
	}
	if w.ExactCount() != 1 {
		t.Fatalf("index holds %d entries, want 1", w.ExactCount())
	}

	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "100")
	if err := w.LoadFromFile("whitelist.csv"); err == nil {
		t.Fatal("expected the reload to fail")
	}
	if w.ExactCount() != 1 {
		t.Fatalf("a failed reload must keep the previous index, holds %d entries", w.ExactCount())
	}
}
