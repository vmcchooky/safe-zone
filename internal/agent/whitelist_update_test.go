package agent

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"safe-zone/internal/risk"
	"safe-zone/internal/store"
)

func newTestDB(t *testing.T) *store.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := store.New(path, 30)
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	return db
}

func createMockZipBytes(t *testing.T, filename string, csvContent string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	f, err := zipWriter.Create(filename)
	if err != nil {
		t.Fatalf("failed to create zip file: %v", err)
	}
	_, err = f.Write([]byte(csvContent))
	if err != nil {
		t.Fatalf("failed to write zip file content: %v", err)
	}

	err = zipWriter.Close()
	if err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}
	return buf.Bytes()
}

func TestWhitelistUpdateTaskSuccess(t *testing.T) {
	db := newTestDB(t)
	wl := risk.NewWhitelist(db)

	// Mock CSV data (Tranco format: rank,domain)
	csvContent := `1,google.com
2,facebook.com
3,github.com
`
	zipBytes := createMockZipBytes(t, "top1m.csv", csvContent)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipBytes)
	}))
	defer server.Close()

	cfg := WhitelistUpdateConfig{
		SourceURL: server.URL,
		Timeout:   10 * time.Second,
		Enabled:   true,
	}

	task := NewWhitelistUpdateTask(db, wl, cfg)

	if task.Name() != "whitelist_update" {
		t.Errorf("expected name 'whitelist_update', got %q", task.Name())
	}

	ctx := context.Background()
	if err := task.Run(ctx); err != nil {
		t.Fatalf("expected no error running task, got %v", err)
	}

	// Verify database contains entries
	ok, err := db.IsDomainWhitelisted("google.com")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected google.com to be whitelisted in SQLite")
	}

	// Verify RAM Bloom Filter was reloaded and matches
	if !wl.IsAllowed("facebook.com") {
		t.Fatal("expected facebook.com to be allowed in RAM Bloom Filter")
	}
	if !wl.IsAllowed("sub.github.com") {
		t.Fatal("expected sub.github.com to be allowed via subdomain inheritance")
	}
	if wl.IsAllowed("evil.com") {
		t.Fatal("expected evil.com to NOT be allowed")
	}

	// Verify audit logs were written
	events, err := db.QueryAgentEvents(time.Now().Add(-1*time.Hour), []string{"whitelist_update_completed"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 completed event log, got %d", len(events))
	}
}

func TestWhitelistUpdateTaskDisabled(t *testing.T) {
	db := newTestDB(t)
	wl := risk.NewWhitelist(db)

	cfg := WhitelistUpdateConfig{
		SourceURL: "http://should-not-be-called.invalid",
		Timeout:   10 * time.Second,
		Enabled:   false, // disabled!
	}

	task := NewWhitelistUpdateTask(db, wl, cfg)
	if err := task.Run(context.Background()); err != nil {
		t.Fatalf("expected no error for disabled task, got %v", err)
	}

	// Verify nothing in DB
	list, err := db.GetWhitelist()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty whitelist in DB, got %d", len(list))
	}
}

func TestWhitelistUpdateTaskHttpFailure(t *testing.T) {
	db := newTestDB(t)
	wl := risk.NewWhitelist(db)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := WhitelistUpdateConfig{
		SourceURL: server.URL,
		Timeout:   10 * time.Second,
		Enabled:   true,
	}

	task := NewWhitelistUpdateTask(db, wl, cfg)
	err := task.Run(context.Background())
	if err == nil {
		t.Fatal("expected error on http failure, got nil")
	}

	// Verify audit logs recorded failure
	events, err := db.QueryAgentEvents(time.Now().Add(-1*time.Hour), []string{"whitelist_update_failed"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 failed event log, got %d", len(events))
	}
}

func TestWhitelistUpdateTaskRawCsvFallback(t *testing.T) {
	db := newTestDB(t)
	wl := risk.NewWhitelist(db)

	csvContent := `1,apple.com
2,microsoft.com
`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte(csvContent))
	}))
	defer server.Close()

	cfg := WhitelistUpdateConfig{
		SourceURL: server.URL,
		Timeout:   10 * time.Second,
		Enabled:   true,
	}

	task := NewWhitelistUpdateTask(db, wl, cfg)
	if err := task.Run(context.Background()); err != nil {
		t.Fatalf("expected no error running task, got %v", err)
	}

	// Verify it parsed and loaded raw CSV fallback correctly
	if !wl.IsAllowed("apple.com") {
		t.Fatal("expected apple.com to be allowed")
	}
	if !wl.IsAllowed("microsoft.com") {
		t.Fatal("expected microsoft.com to be allowed")
	}
}
