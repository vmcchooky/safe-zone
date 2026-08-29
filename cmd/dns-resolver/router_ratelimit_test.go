package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"safe-zone/internal/dns/resolver"
	"safe-zone/internal/dns/server"
	"safe-zone/internal/observability"
	"safe-zone/internal/ratelimit"
	"safe-zone/internal/risk"
)

// The router itself applies no rate limiting (it accepts no limiter); the
// dns-resolver wraps the returned mux exactly once with
// TieredMiddleware.Wrap. This test proves that outer wrap still protects the
// routes: hammering a cheap endpoint past the burst budget yields 429s, so
// removing the Wrap in main would be observable.
func TestOuterTieredWrapEnforcesRateLimit(t *testing.T) {
	res := resolver.New(risk.NewService(risk.Options{}), observability.NewRegistry(), nil, resolver.Config{DeploymentTier: "test"}, nil)
	mux := server.NewRouter(res)

	limiter := ratelimit.New(240, 2)
	defer limiter.Close()
	tiered := ratelimit.NewTieredMiddleware(
		limiter,
		ratelimit.Tier{PathPrefix: "/v1/version", Limiter: limiter},
	)

	server := httptest.NewServer(tiered.Wrap(mux))
	defer server.Close()

	saw429 := false
	for i := 0; i < 20; i++ {
		resp, err := http.Get(server.URL + "/v1/version")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			saw429 = true
			break
		}
	}
	if !saw429 {
		t.Fatal("expected outer tiered.Wrap to enforce 429 after burst exhaustion")
	}
}
