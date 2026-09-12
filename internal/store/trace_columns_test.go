package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewMigratesTraceColumns(t *testing.T) {
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
		Domain: "trace-migrate.test", Verdict: "SAFE", Score: 0,
		Source: "lexical", DecisionID: "eval-abc123",
		Trace:          `{"lexical":42}`,
		AnalyzedAt:     "2026-09-12T00:00:00Z",
		PolicyAction:   "",
		PolicyCategory: "",
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, err := db.QueryRecentFiltered(context.Background(), TelemetryFilter{Domain: "trace-migrate.test"}, 10, 0)
		if err != nil {
			t.Fatalf("query telemetry: %v", err)
		}
		if len(entries) == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	entries, err := db.QueryRecentFiltered(context.Background(), TelemetryFilter{Domain: "trace-migrate.test"}, 10, 0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d (%v)", len(entries), err)
	}
	if entries[0].DecisionID != "eval-abc123" {
		t.Fatalf("expected decision id persisted, got %+v", entries[0])
	}
	if !strings.Contains(entries[0].Trace, "lexical") {
		t.Fatalf("expected trace persisted, got %q", entries[0].Trace)
	}
}
