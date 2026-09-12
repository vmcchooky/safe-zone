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

// O-9: a compromised whitelist source must not bounce the fetcher to an
// unresolvable or non-public target. The redirect hop passes the shared
// outbound policy (netguard), whose own unit tests pin private-address
// blocking; here we prove the updater actually enforces it.
func TestWhitelistDownloadBlocksBadRedirect(t *testing.T) {
	db := newTestDB(t)
	wl := risk.NewWhitelist(db)

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RFC 2606 .invalid never resolves: the failure is deterministic
		// with or without network access.
		http.Redirect(w, r, "http://no-such-host.invalid/list.txt", http.StatusFound)
	}))
	defer redirector.Close()

	task := NewWhitelistUpdateTask(db, wl, WhitelistUpdateConfig{
		SourceURL:           redirector.URL,
		Timeout:             10 * time.Second,
		Enabled:             true,
		AllowPrivateSources: true,
	})
	if err := task.Run(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "blocked redirect") {
		t.Fatalf("expected blocked-redirect error, got %v", err)
	}
}

// O-9: an explicitly private source URL is rejected before any fetch.
func TestWhitelistDownloadRejectsPrivateSource(t *testing.T) {
	db := newTestDB(t)
	wl := risk.NewWhitelist(db)

	task := NewWhitelistUpdateTask(db, wl, WhitelistUpdateConfig{
		SourceURL: "http://169.254.169.254/latest/meta-data/",
		Timeout:   10 * time.Second,
		Enabled:   true,
	})
	if _, err := task.downloadAndParse(context.Background()); err == nil {
		t.Fatal("expected private source URL to be rejected")
	}
}
