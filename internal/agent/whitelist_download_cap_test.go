package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/risk"
)

// H4: the whitelist source download must be byte-capped before buffering:
// parseCSV caps at 128MiB after the full body is already in memory.
func TestWhitelistDownloadEnforcesByteCap(t *testing.T) {
	db := newTestDB(t)
	wl := risk.NewWhitelist(db)

	big := strings.Repeat("x", 4*1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(big))
	}))
	defer server.Close()

	task := NewWhitelistUpdateTask(db, wl, WhitelistUpdateConfig{
		SourceURL:           server.URL,
		Timeout:             10 * time.Second,
		Enabled:             true,
		MaxDownloadBytes:    1024,
		AllowPrivateSources: true,
	})
	if err := task.Run(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected download cap error, got %v", err)
	}

	small := NewWhitelistUpdateTask(db, wl, WhitelistUpdateConfig{
		SourceURL:           server.URL,
		Timeout:             10 * time.Second,
		Enabled:             true,
		MaxDownloadBytes:    1 << 20,
		AllowPrivateSources: true,
	})
	if _, err := small.downloadAndParse(context.Background()); err != nil {
		t.Fatalf("small body under cap must download, got %v", err)
	}
}
