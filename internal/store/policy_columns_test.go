package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestNewMigratesPolicyColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	rawDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rawDB.Exec(`
		CREATE TABLE analysis_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domain TEXT NOT NULL,
			verdict TEXT NOT NULL,
			score INTEGER NOT NULL,
			confidence REAL NOT NULL,
			reasons TEXT,
			cache_hit INTEGER NOT NULL DEFAULT 0,
			source TEXT,
			analyzed_at TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			client_ip TEXT DEFAULT '',
			client_id TEXT DEFAULT ''
		);
		INSERT INTO analysis_log (domain, verdict, score, confidence, analyzed_at)
		VALUES ('legacy-row.test', 'MALICIOUS', 100, 1.0, '2026-09-01T00:00:00Z');
	`); err != nil {
		_ = rawDB.Close()
		t.Fatalf("create legacy schema: %v", err)
	}
	if err := rawDB.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := New(path, 30)
	if err != nil {
		t.Fatalf("migrate legacy database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	db.RecordAnalysis(TelemetryEntry{
		Domain: "policy-row.test", Verdict: "SAFE", Score: 15,
		Reasons:        []string{"domain is long"},
		Source:         "adblock",
		PolicyAction:   "block",
		PolicyCategory: "unknown",
		AnalyzedAt:     "2026-09-10T00:00:00Z",
	})
	// RecordAnalysis is async; poll until the writer lands both rows.
	deadline := time.Now().Add(5 * time.Second)
	var entries []TelemetryEntry
	for {
		entries, err = db.QueryRecentFiltered(context.Background(), TelemetryFilter{}, 10, 0)
		if err != nil {
			t.Fatalf("query telemetry: %v", err)
		}
		if len(entries) == 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(entries) != 2 {
		t.Fatalf("expected legacy + new rows, got %d", len(entries))
	}
	if entries[0].PolicyAction != "block" || entries[0].PolicyCategory != "unknown" {
		t.Fatalf("expected policy columns on new row, got %+v", entries[0])
	}
	if entries[1].PolicyAction != "" || entries[1].PolicyCategory != "" {
		t.Fatalf("legacy row must backfill empty policy columns, got %+v", entries[1])
	}
}
