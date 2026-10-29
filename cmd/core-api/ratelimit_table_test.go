package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// TestTierTableFirstMatchWins pins the whole prefix-to-limiter table built by
// newTieredMiddleware. Every tier gets a distinct burst sentinel through its
// environment variable, so draining a path's limiter reveals exactly which
// tier served it: a silent reorder or a missing tier (falling through to the
// default limiter's burst) fails the row. limiterFor resolves prefixes in
// order, so overlapping prefixes are decided by table position — the rows
// below include the ones where that matters (/v1/auth/session must land on
// the dashboard tier, /app-background.avif on the /app tier).
func TestTierTableFirstMatchWins(t *testing.T) {
	const (
		authBurst      = 3
		analyzeBurst   = 5
		dashboardBurst = 7
		overrideBurst  = 11
		telemetryBurst = 13
		feedbackBurst  = 17
		reportBurst    = 19
		defaultBurst   = 23
	)
	sentinels := map[string]int{
		"AUTH":      authBurst,
		"ANALYZE":   analyzeBurst,
		"DASHBOARD": dashboardBurst,
		"OVERRIDE":  overrideBurst,
		"TELEMETRY": telemetryBurst,
		"FEEDBACK":  feedbackBurst,
		"REPORT":    reportBurst,
		"DEFAULT":   defaultBurst,
	}
	for tier, burst := range sentinels {
		t.Setenv("SAFE_ZONE_RATELIMIT_"+tier+"_BURST", strconv.Itoa(burst))
		// A high refill rate keeps the bucket from gaining a token between
		// the Allow calls below.
		t.Setenv("SAFE_ZONE_RATELIMIT_"+tier+"_RPM", "100000")
	}

	tiered, stop := newTieredMiddleware()
	defer stop()

	rows := []struct {
		path      string
		wantBurst int
	}{
		{"/v1/auth/login", authBurst},
		{"/v1/analyze", analyzeBurst},
		{"/v1/url-ml/feedback", feedbackBurst},
		{"/block/report", reportBurst},
		{"/assets/app.css", dashboardBurst},
		{"/app", dashboardBurst},
		{"/app-background.avif", dashboardBurst},
		{"/dashboard", dashboardBurst},
		{"/v1/status", dashboardBurst},
		{"/metrics", dashboardBurst},
		{"/metrics/prometheus", dashboardBurst},
		{"/v1/version", dashboardBurst},
		{"/v1/auth/session", dashboardBurst},
		{"/v1/settings/bundle", dashboardBurst},
		{"/v1/overrides", overrideBurst},
		{"/v1/brands", overrideBurst},
		{"/v1/telemetry/recent", telemetryBurst},
		{"/v1/telemetry/stats", telemetryBurst},
		// Unlisted prefixes fall through to the default limiter.
		{"/v1/groups", defaultBurst},
		{"/v1/reports", defaultBurst},
		{"/v1/settings", defaultBurst},
		{"/", defaultBurst},
	}

	for i, row := range rows {
		limiter := tiered.LimiterFor(row.path)
		if limiter == nil {
			t.Errorf("%s: no limiter resolved", row.path)
			continue
		}
		ip := "192.0.2." + strconv.Itoa(10+i)
		count := 0
		for limiter.Allow(ip) {
			count++
			if count > row.wantBurst+2 {
				break
			}
		}
		if count != row.wantBurst {
			t.Errorf("%s: drained %d tokens, want %d (wrong tier or burst)", row.path, count, row.wantBurst)
		}
	}
}

// TestTieredMiddlewareFallsBackForUnlistedPaths keeps the fallback contract
// explicit: a request to an unlisted prefix must be limited by the default
// limiter, never by whichever limiter happens to sit first in the table.
func TestTieredMiddlewareFallsBackForUnlistedPaths(t *testing.T) {
	tiered, stop := newTieredMiddleware()
	defer stop()

	if got := tiered.LimiterFor("/v1/groups"); got == nil {
		t.Fatal("fallback limiter missing")
	}

	// Behavioral check through the middleware itself: the default limiter's
	// shipped burst is 15, so the 16th request from one client on an unlisted
	// path is throttled.
	handler := tiered.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for i := 0; i < 15; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1/groups", nil)
		req.RemoteAddr = "203.0.113.50:4444"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d throttled before the default burst", i+1)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/groups", nil)
	req.RemoteAddr = "203.0.113.50:4444"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("16th request = %d, want 429", rec.Code)
	}
}
