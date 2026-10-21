package risk

import (
	"context"
	"path/filepath"
	"testing"

	"safe-zone/internal/config"
	"safe-zone/internal/store"
)

// B1: an empty SAFE_ZONE_WHITELIST_PATH is the documented DB-only mode. It
// must not be turned into the old implicit "./data/whitelist.txt": a stock
// production deployment has no such file, so the service started with a
// failed allow-list load and refused to boot.
func TestWhitelistPathEmptyMeansDatabaseOnly(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SAFE_ZONE_FEED_FILE_ROOT", root)

	dbPath := filepath.Join(root, "safe-zone.db")
	db, err := store.New(dbPath, 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")
	if err := db.UpdateWhitelist(context.Background(), []string{"db-only.example"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SAFE_ZONE_WHITELIST_PATH", "")
	t.Setenv("SAFE_ZONE_SQLITE_PATH", dbPath)
	t.Setenv("SAFE_ZONE_ADBLOCK_ENABLED", "false")

	service, err := NewServiceFromEnvForRoleE("core-api")
	if err != nil {
		t.Fatalf("an empty whitelist path must start in DB-only mode: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })

	if loadErr := service.Whitelist().LoadError(); loadErr != nil {
		t.Fatalf("DB-only mode must not try to load a file: %v", loadErr)
	}
	if !service.Whitelist().ContainsExactIndex("db-only.example") {
		t.Fatal("the whitelist stored in SQLite must be in effect")
	}
}

// The explicit missing-file path stays an error, and the production startup
// guard is the condition main uses: LoadError != nil && IsProduction().
func TestWhitelistExplicitMissingFileIsRecordedFromEnv(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SAFE_ZONE_FEED_FILE_ROOT", root)
	t.Setenv("SAFE_ZONE_SQLITE_PATH", filepath.Join(root, "safe-zone.db"))
	t.Setenv("SAFE_ZONE_ADBLOCK_ENABLED", "false")
	t.Setenv("SAFE_ZONE_ENV", "production")
	t.Setenv("SAFE_ZONE_WHITELIST_PATH", "missing-whitelist.csv")

	service, err := NewServiceFromEnvForRoleE("core-api")
	if err != nil {
		t.Fatalf("the service reports the failure through LoadError, not the constructor: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })

	if service.Whitelist().LoadError() == nil {
		t.Fatal("an explicitly configured missing whitelist must be recorded")
	}
	if !config.IsProduction() {
		t.Fatal("precondition: the startup guard only fails in production")
	}
}
