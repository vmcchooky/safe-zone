package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The report tier must exist with a tight budget: /block/report performs
// unauthenticated database writes, and a missing tier silently falls back
// to the generous default limiter.
func TestReportTierLimitsBlockReport(t *testing.T) {
	t.Setenv("SAFE_ZONE_RATELIMIT_REPORT_RPM", "10")
	t.Setenv("SAFE_ZONE_RATELIMIT_REPORT_BURST", "3")
	t.Setenv("SAFE_ZONE_RATELIMIT_DEFAULT_RPM", "60000")
	t.Setenv("SAFE_ZONE_RATELIMIT_DEFAULT_BURST", "1000")

	tiered, stop := newTieredMiddleware()
	defer stop()
	next := tiered.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	limited := 0
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest(http.MethodPost, "/block/report", strings.NewReader("domain=x.test"))
		req.RemoteAddr = "198.51.100.7:1234"
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("expected /block/report to hit its own tight tier, got no 429s")
	}

	// A sibling path on another tier must be unaffected by report exhaustion.
	req := httptest.NewRequest(http.MethodGet, "/v1/version", nil)
	req.RemoteAddr = "198.51.100.7:1234"
	rec := httptest.NewRecorder()
	next.ServeHTTP(rec, req)
	if rec.Code == http.StatusTooManyRequests {
		t.Fatal("report exhaustion must not spill into other tiers")
	}
}
