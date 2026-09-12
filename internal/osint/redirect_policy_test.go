package osint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// O-10: redirect hops must pass the same outbound policy as the initial
// source fetch. A compromised warning page must not bounce the fetcher
// off-policy (here: an unresolvable host, deterministic with or without
// network because RFC 2606 .invalid never resolves).
func TestFetchSourceRevalidatesRedirects(t *testing.T) {
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://no-such-host.invalid/warning", http.StatusFound)
	}))
	defer redirector.Close()

	host := strings.TrimPrefix(redirector.URL, "http://")
	service := NewService(Options{
		Enabled:             true,
		Timeout:             time.Second,
		CacheTTL:            time.Hour,
		TrustedDomains:      []string{host},
		AllowPrivateSources: true,
	})

	_, err := service.fetchSource(context.Background(), "evil.example", redirector.URL+"/warning")
	if err == nil || !strings.Contains(err.Error(), "blocked redirect") {
		t.Fatalf("expected blocked redirect error, got %v", err)
	}
}

// Same-host public redirects keep working: the policy blocks targets,
// not the act of redirecting.
func TestFetchSourceFollowsSameHostRedirect(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old" {
			http.Redirect(w, r, "/warning", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(`<html><title>Canh bao</title><body>evil.example lua dao, gia mao.</body></html>`))
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")
	service := NewService(Options{
		Enabled:             true,
		Timeout:             time.Second,
		CacheTTL:            time.Hour,
		TrustedDomains:      []string{host},
		AllowPrivateSources: true,
	})

	evidence, err := service.fetchSource(context.Background(), "evil.example", server.URL+"/old")
	if err != nil {
		t.Fatalf("same-host redirect must be followed, got %v", err)
	}
	if evidence.SourceURL == "" {
		t.Fatal("expected evidence from redirected fetch")
	}
}
