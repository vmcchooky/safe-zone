package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
