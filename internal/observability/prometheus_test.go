package observability

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRenderPrometheusGolden(t *testing.T) {
	registry := NewRegistry()
	registry.Observe("GET", "/v1/status", 200, 512, 12*time.Millisecond)
	registry.Observe("POST", "/v1/auth/login", 401, 96, 3*time.Millisecond)
	registry.IncCounter("risk.block.decisions")

	var out strings.Builder
	if err := RenderPrometheus(&out, registry.Snapshot()); err != nil {
		t.Fatal(err)
	}
	got := out.String()

	for _, want := range []string{
		"# TYPE safe_zone_uptime_seconds gauge",
		`safe_zone_http_requests_total{method="GET",path="/v1/status",status="200"} 1`,
		`safe_zone_http_request_duration_milliseconds_sum{method="GET",path="/v1/status",status="200"} 12`,
		`safe_zone_http_request_duration_milliseconds_max{method="GET",path="/v1/status",status="200"} 12`,
		`safe_zone_http_response_bytes_total{method="GET",path="/v1/status",status="200"} 512`,
		`safe_zone_http_requests_total{method="POST",path="/v1/auth/login",status="401"} 1`,
		"safe_zone_risk_block_decisions_total 1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("prometheus output missing %q\ngot:\n%s", want, got)
		}
	}
}

func TestPrometheusCounterNameNormalizes(t *testing.T) {
	cases := map[string]string{
		"risk.block":        "safe_zone_risk_block_total",
		"already_total":     "safe_zone_already_total",
		"weird name/spaces": "safe_zone_weird_name_spaces_total",
		"observability_request_series_overflow_total": "safe_zone_observability_request_series_overflow_total",
	}
	for in, want := range cases {
		if got := prometheusCounterName(in); got != want {
			t.Fatalf("prometheusCounterName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderPrometheusEscapesLabelValues(t *testing.T) {
	registry := NewRegistry()
	registry.Observe("GET", `/pa"th\n`, 200, 0, time.Millisecond)

	var out strings.Builder
	if err := RenderPrometheus(&out, registry.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `path="/pa\"th\\n"`) {
		t.Fatalf("label values not escaped:\n%s", out.String())
	}
}

func TestPrometheusHandlerContentTypeAndMethod(t *testing.T) {
	registry := NewRegistry()

	req := httptest.NewRequest("POST", "/metrics/prometheus", nil)
	rec := httptest.NewRecorder()
	registry.PrometheusHandler()(rec, req)
	if rec.Code != 405 {
		t.Fatalf("POST /metrics/prometheus = %d, want 405", rec.Code)
	}

	req = httptest.NewRequest("GET", "/metrics/prometheus", nil)
	rec = httptest.NewRecorder()
	registry.PrometheusHandler()(rec, req)
	if rec.Code != 200 {
		t.Fatalf("GET /metrics/prometheus = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != prometheusContentType {
		t.Fatalf("content type = %q, want %q", ct, prometheusContentType)
	}
	if !strings.Contains(rec.Body.String(), "safe_zone_uptime_seconds") {
		t.Fatalf("expected uptime series in body:\n%s", rec.Body.String())
	}
}
