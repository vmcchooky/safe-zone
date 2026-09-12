package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// Fresh databases open in incremental vacuum mode, and the one-time
// conversion flag is recorded so restarts skip the rebuild.
func TestIncrementalVacuumMode(t *testing.T) {
	db, err := New(":memory:", 30)
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	defer func() { _ = db.Close() }()

	var mode string
	if err := db.db.QueryRowContext(context.Background(), `PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		t.Fatalf("read vacuum mode: %v", err)
	}
	// SQLite modes: 0 = none, 1 = full, 2 = incremental.
	if mode != "2" {
		t.Fatalf("expected incremental vacuum mode (2), got %q", mode)
	}
	flag, err := db.GetSystemConfig(context.Background(), vacuumIncrementalDoneKey)
	if err != nil || flag != "1" {
		t.Fatalf("expected vacuum conversion flag, got %q (%v)", flag, err)
	}
}

// A legacy database created without incremental vacuum is converted
// exactly once on open.
func TestLegacyDatabaseConvertedToIncrementalVacuum(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	rawDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rawDB.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY)`); err != nil {
		_ = rawDB.Close()
		t.Fatalf("create legacy schema: %v", err)
	}
	var before string
	if err := rawDB.QueryRow(`PRAGMA auto_vacuum`).Scan(&before); err != nil {
		_ = rawDB.Close()
		t.Fatal(err)
	}
	if err := rawDB.Close(); err != nil {
		t.Fatal(err)
	}
	if before != "0" {
		t.Skipf("fixture is not a legacy none-mode database: %q", before)
	}

	db, err := New(path, 30)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	defer func() { _ = db.Close() }()
	var after string
	if err := db.db.QueryRowContext(context.Background(), `PRAGMA auto_vacuum`).Scan(&after); err != nil {
		t.Fatalf("read converted mode: %v", err)
	}
	if after != "2" {
		t.Fatalf("expected conversion to incremental (2), got %q", after)
	}
}

// Retention cleanup must not fail on the vacuum step and must keep
// working across repeated cycles.
func TestCleanupRunsVacuumStep(t *testing.T) {
	db, err := New(":memory:", 30)
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	defer func() { _ = db.Close() }()

	db.RecordAnalysis(TelemetryEntry{Domain: "vacuum.test", Verdict: "SAFE", AnalyzedAt: "2020-01-01T00:00:00Z"})
	db.cleanup()
	db.cleanup()
}
