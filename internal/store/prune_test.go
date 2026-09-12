package store

import (
	"testing"
	"time"
)

// P-2: decided reports age out with retention; pending reports are never
// auto-deleted (they are the operator review queue).
func TestCleanupPrunesDecidedReportsOnly(t *testing.T) {
	db, err := New(":memory:", 30)
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	defer func() { _ = db.Close() }()

	old := time.Now().AddDate(0, 0, -31).UTC().Format("2006-01-02 15:04:05")
	seed := []struct {
		domain, status, created string
	}{
		{"old-resolved.test", "resolved", old},
		{"old-rejected.test", "rejected", old},
		{"old-pending.test", "pending", old},
		{"new-resolved.test", "resolved", time.Now().UTC().Format("2006-01-02 15:04:05")},
	}
	for _, row := range seed {
		if _, err := db.db.Exec(
			`INSERT INTO block_reports (domain, status, created_at) VALUES (?, ?, ?)`,
			row.domain, row.status, row.created); err != nil {
			t.Fatalf("seed report: %v", err)
		}
	}

	db.cleanup()

	remaining := make(map[string]string)
	rows, err := db.db.Query(`SELECT domain, status FROM block_reports`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var domain, status string
		if err := rows.Scan(&domain, &status); err != nil {
			t.Fatal(err)
		}
		remaining[domain] = status
	}
	if len(remaining) != 2 || remaining["old-pending.test"] != "pending" || remaining["new-resolved.test"] != "resolved" {
		t.Fatalf("expected only old-pending + new-resolved to survive, got %v", remaining)
	}
}
