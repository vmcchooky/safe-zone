package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"safe-zone/internal/cache"
	"safe-zone/internal/config"
	"safe-zone/internal/observability"
	"safe-zone/internal/risk"
)

func TestStatusHandlerReportsConfiguredRateLimitingState(t *testing.T) {
	testCases := []struct {
		name    string
		enabled bool
	}{
		{name: "enabled", enabled: true},
		{name: "disabled", enabled: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			riskService := risk.NewService(risk.Options{
				AnalysisConfig:      config.DefaultAnalysisConfig(),
				RedisTimeout:        10 * time.Millisecond,
				ConfigReloadEnabled: true,
			})
			t.Cleanup(func() {
				_ = riskService.Close()
			})

			handler := New(riskService, observability.NewRegistry(), Config{
				DeploymentTier:      "budget-vps",
				RateLimitingEnabled: tc.enabled,
			})

			req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
			rec := httptest.NewRecorder()

			handler.StatusHandler(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("expected status 200, got %d", rec.Code)
			}

			var payload statusResponse
			if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
				t.Fatalf("decode status response: %v", err)
			}

			if payload.RateLimiting == nil {
				t.Fatal("expected rate limiting status in payload")
			}
			if payload.RateLimiting.Enabled != tc.enabled {
				t.Fatalf("expected rate limiting enabled=%t, got %#v", tc.enabled, payload.RateLimiting)
			}
		})
	}
}

// The decision_pipeline block must carry every counter the Service tracks.
// A hand-built literal once silently zeroed the consecutive/timestamp
// fields; this test drives a real feed failure and pins the payload.
func TestStatusHandlerReportsFeedFailureCounters(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	riskService := risk.NewService(risk.Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		Redis:              cache.NewRedis(server.Addr(), "", 0),
		DisableAdblockSync: true,
		RedisTimeout:       2 * time.Second,
	})
	t.Cleanup(func() {
		_ = riskService.Close()
	})
	// Make the feed key the wrong Redis type so the live read fails with
	// WRONGTYPE on the first command. Tearing the server down instead would
	// make go-redis burn its dial retry backoff on every later command.
	if err := server.Set("safe-zone:threat:feed", "not-a-sorted-set"); err != nil {
		t.Fatalf("seed wrong-type feed key: %v", err)
	}
	riskService.Analyze(context.Background(), "unreachable.test", risk.ClientInfo{})

	handler := New(riskService, observability.NewRegistry(), Config{
		DeploymentTier: "test",
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	rec := httptest.NewRecorder()
	handler.StatusHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	var payload statusResponse
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if payload.DecisionPipeline == nil {
		t.Fatal("expected decision_pipeline block in payload")
	}
	pipeline := payload.DecisionPipeline
	if pipeline.FeedLookupFailures < 1 {
		t.Fatalf("feed_lookup_failures = %d, want >= 1", pipeline.FeedLookupFailures)
	}
	if pipeline.FeedConsecutiveFailures != pipeline.FeedLookupFailures {
		t.Fatalf("consecutive = %d, total = %d: they must match with no success in between",
			pipeline.FeedConsecutiveFailures, pipeline.FeedLookupFailures)
	}
	if pipeline.FeedLastFailureAt == "" {
		t.Fatal("feed_last_failure_at must be stamped after failures")
	}
}
