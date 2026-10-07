package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"safe-zone/internal/dns/resolver"
	"safe-zone/internal/dns/server"
	"safe-zone/internal/observability"
	"safe-zone/internal/risk"
)

const testAdminAPIKey = "0123456789abcdef0123456789abcdef"

func newTestRouter(t *testing.T, adminAPIKey string) *httptest.Server {
	t.Helper()
	res := resolver.New(risk.NewService(risk.Options{}), observability.NewRegistry(), nil, resolver.Config{DeploymentTier: "test"}, nil)
	server := httptest.NewServer(server.NewRouter(res, adminAPIKey))
	t.Cleanup(server.Close)
	return server
}

// /metrics publishes the per-endpoint request summary, so it must require the
// admin API key. These tests pin the four states that matter: no credential, a
// wrong credential, the right credential, and the unset-key deployment.
func TestMetricsRequiresAdminBearerToken(t *testing.T) {
	server := newTestRouter(t, testAdminAPIKey)

	t.Run("anonymous is rejected", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/metrics")
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
		}
		if got := resp.Header.Get("WWW-Authenticate"); got == "" {
			t.Error("WWW-Authenticate header is missing, so a scraper cannot tell a credential problem from a routing problem")
		}
	})

	t.Run("wrong key is rejected", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, server.URL+"/metrics", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer wrong-key-wrong-key-wrong-key")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
		}
	})

	t.Run("empty bearer is rejected", func(t *testing.T) {
		// The empty-token case is the reason MatchesBearer refuses to compare
		// when either side is empty: sha256("") == sha256("") would otherwise
		// authenticate this header.
		req, err := http.NewRequest(http.MethodGet, server.URL+"/metrics", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer ")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
		}
	})

	t.Run("correct key is accepted", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, server.URL+"/metrics", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})
}

// An unset key must deny, not allow. Treating "no key configured" as "no
// authentication required" is the exact state where an operator believes
// /metrics is protected while it is public.
func TestMetricsFailsClosedWhenNoAdminKeyConfigured(t *testing.T) {
	server := newTestRouter(t, "")

	resp, err := http.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d with no key configured", resp.StatusCode, http.StatusUnauthorized)
	}
}

// Gating /metrics must not take the client-facing endpoints down with it.
// /healthz backs the container HEALTHCHECK and /v1/version and /v1/policy back
// DoH clients and the block page.
func TestClientFacingEndpointsStayPublic(t *testing.T) {
	server := newTestRouter(t, testAdminAPIKey)

	for _, path := range []string{"/healthz", "/v1/version", "/"} {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(server.URL + path)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode == http.StatusUnauthorized {
				t.Fatalf("%s returned 401 for an anonymous client, but it must stay public", path)
			}
		})
	}
}
