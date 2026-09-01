package observability

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestRegistryCollapsesUntrustedNotFoundPaths(t *testing.T) {
	registry := NewRegistry()
	for i := 0; i < 100; i++ {
		registry.Observe(http.MethodGet, fmt.Sprintf("/scanner-%d/.env", i), http.StatusNotFound, 10, time.Millisecond)
	}
	registry.Observe(http.MethodGet, "/app/assets/old-a.js", http.StatusNotFound, 10, time.Millisecond)
	registry.Observe(http.MethodGet, "/app/assets/old-b.js", http.StatusNotFound, 10, time.Millisecond)

	snapshot := registry.Snapshot()
	if len(snapshot.RequestSummary) != 2 {
		t.Fatalf("expected two bounded 404 series, got %d: %#v", len(snapshot.RequestSummary), snapshot.RequestSummary)
	}
	if got := snapshot.RequestSummary["GET /:not-found 404"].Count; got != 100 {
		t.Fatalf("expected 100 generic not-found requests, got %d", got)
	}
	if got := snapshot.RequestSummary["GET /app/assets/:missing 404"].Count; got != 2 {
		t.Fatalf("expected two missing SPA assets, got %d", got)
	}
}

func TestRegistryCapsRequestSeries(t *testing.T) {
	registry := NewRegistry()
	for i := 0; i < maxRequestSeries+50; i++ {
		registry.Observe(http.MethodGet, fmt.Sprintf("/ok/%d", i), http.StatusOK, 1, 0)
	}

	snapshot := registry.Snapshot()
	if got := len(snapshot.RequestSummary); got != maxRequestSeries {
		t.Fatalf("expected request series cap %d, got %d", maxRequestSeries, got)
	}
	overflow, ok := snapshot.RequestSummary[overflowRequestSeriesKey]
	if !ok || overflow.Count == 0 {
		t.Fatalf("expected overflow aggregation series, got %#v", overflow)
	}
	if got := snapshot.Counters[requestSeriesOverflowCounter]; got != 51 {
		t.Fatalf("expected 51 overflow observations, got %d", got)
	}
}

func TestRegistryBoundsOversizedPathsAndUnknownMethods(t *testing.T) {
	registry := NewRegistry()
	registry.Observe("PROPFIND", "/"+string(make([]byte, maxMetricPathBytes+1)), http.StatusTooManyRequests, 0, 0)

	snapshot := registry.Snapshot()
	if _, ok := snapshot.RequestSummary["OTHER /:oversized 429"]; !ok {
		t.Fatalf("expected bounded unknown request series, got %#v", snapshot.RequestSummary)
	}
}
