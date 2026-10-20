package serve

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
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
	if report.Checks["redis"] == "ok" {
		t.Fatal("the redis check must carry the failure")
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

			ReadinessHandler("core-api", tc.check)(recorder, request)

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
