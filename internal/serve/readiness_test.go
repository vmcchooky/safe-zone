package serve

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"safe-zone/internal/observability"
)

func TestEvaluateReadinessAllHealthy(t *testing.T) {
	report := EvaluateReadiness(context.Background(),
		ReadinessCheck{Name: "sqlite", Mandatory: true, Check: func(context.Context) error { return nil }},
		ReadinessCheck{Name: "redis", Mandatory: false, Check: func(context.Context) error { return nil }},
	)

	if report.Status != "ok" {
		t.Fatalf("status = %q, want ok", report.Status)
	}
	if report.Checks["sqlite"] != "ok" {
		t.Fatalf("sqlite check = %q, want ok", report.Checks["sqlite"])
	}
}

// An optional dependency that fails degrades the service but keeps it
// serving. A Redis outage must not make the resolver unready: it is still
// answering DNS queries, just with less coverage.
func TestEvaluateReadinessOptionalFailureDegrades(t *testing.T) {
	report := EvaluateReadiness(context.Background(),
		ReadinessCheck{Name: "sqlite", Mandatory: true, Check: func(context.Context) error { return nil }},
		ReadinessCheck{Name: "redis", Mandatory: false, Check: func(context.Context) error { return errors.New("connection refused") }},
	)

	if report.Status != "degraded" {
		t.Fatalf("status = %q, want degraded", report.Status)
	}
	if report.Checks["redis"] != "unavailable" {
		t.Fatalf("the redis check = %q, want unavailable", report.Checks["redis"])
	}
}

// A mandatory dependency that fails means the service cannot do its job.
func TestEvaluateReadinessMandatoryFailureIsNotReady(t *testing.T) {
	report := EvaluateReadiness(context.Background(),
		ReadinessCheck{Name: "sqlite", Mandatory: true, Check: func(context.Context) error { return errors.New("disk I/O error") }},
	)

	if report.Status != "not_ready" {
		t.Fatalf("status = %q, want not_ready", report.Status)
	}
}

// /readyz is public on both services. The raw dependency error can name an
// internal path, host or credential, so it must stay in the log and never
// reach the response body.
func TestReadinessHandlerDoesNotExposeDependencyErrors(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)

	secret := "open /var/lib/safe-zone/private.db: permission denied"
	ReadinessHandler("core-api", observability.NewRegistry(),
		ReadinessCheck{
			Name:      "sqlite",
			Mandatory: true,
			Check:     func(context.Context) error { return errors.New(secret) },
		},
	)(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	if strings.Contains(recorder.Body.String(), "permission denied") || strings.Contains(recorder.Body.String(), "/var/lib") {
		t.Fatalf("response leaked the raw dependency error: %s", recorder.Body.String())
	}

	var payload struct {
		Checks map[string]string `json:"checks"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, recorder.Body.String())
	}
	if payload.Checks["sqlite"] != "unavailable" {
		t.Fatalf("sqlite check = %q, want unavailable", payload.Checks["sqlite"])
	}
}

// A check failure must be visible to monitoring even though the public body
// only says "unavailable". Each code-defined check gets its own bounded
// counter for both outcomes.
func TestReadinessHandlerCountsEachCheck(t *testing.T) {
	registry := observability.NewRegistry()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)

	ReadinessHandler("core-api", registry,
		ReadinessCheck{Name: "sqlite", Mandatory: true, Check: func(context.Context) error { return nil }},
		ReadinessCheck{Name: "redis", Mandatory: false, Check: func(context.Context) error { return errors.New("connection refused") }},
	)(recorder, request)

	counters := registry.Snapshot().Counters
	if counters["readiness_check_sqlite_ok_total"] != 1 {
		t.Fatalf("sqlite ok counter = %d, want 1 (all counters: %v)", counters["readiness_check_sqlite_ok_total"], counters)
	}
	if counters["readiness_check_redis_failures_total"] != 1 {
		t.Fatalf("redis failure counter = %d, want 1 (all counters: %v)", counters["readiness_check_redis_failures_total"], counters)
	}
}

func TestReadinessHandlerStatusCodes(t *testing.T) {
	cases := []struct {
		name       string
		check      ReadinessCheck
		wantCode   int
		wantStatus string
	}{
		{
			name:       "healthy",
			check:      ReadinessCheck{Name: "sqlite", Mandatory: true, Check: func(context.Context) error { return nil }},
			wantCode:   http.StatusOK,
			wantStatus: "ok",
		},
		{
			name:       "degraded",
			check:      ReadinessCheck{Name: "redis", Mandatory: false, Check: func(context.Context) error { return errors.New("down") }},
			wantCode:   http.StatusOK,
			wantStatus: "degraded",
		},
		{
			name:       "not ready",
			check:      ReadinessCheck{Name: "sqlite", Mandatory: true, Check: func(context.Context) error { return errors.New("down") }},
			wantCode:   http.StatusServiceUnavailable,
			wantStatus: "not_ready",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/readyz", nil)

			ReadinessHandler("core-api", observability.NewRegistry(), tc.check)(recorder, request)

			if recorder.Code != tc.wantCode {
				t.Fatalf("status code = %d, want %d", recorder.Code, tc.wantCode)
			}

			var payload map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
				t.Fatalf("response is not JSON: %v (%s)", err, recorder.Body.String())
			}
			if payload["status"] != tc.wantStatus {
				t.Fatalf("status = %v, want %q", payload["status"], tc.wantStatus)
			}
			if payload["service"] != "core-api" {
				t.Fatalf("service = %v, want core-api", payload["service"])
			}
		})
	}
}

// A probe that hangs is worse than one that fails, so each check is
// bounded.
func TestReadinessCheckTimesOut(t *testing.T) {
	report := EvaluateReadiness(context.Background(),
		ReadinessCheck{
			Name:      "sqlite",
			Mandatory: true,
			Check: func(ctx context.Context) error {
				<-ctx.Done()
				return ctx.Err()
			},
		},
	)

	if report.Status != "not_ready" {
		t.Fatalf("status = %q, want not_ready", report.Status)
	}
}
