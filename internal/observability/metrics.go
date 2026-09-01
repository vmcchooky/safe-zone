package observability

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	maxRequestSeries             = 256
	maxMetricPathBytes           = 256
	overflowRequestSeriesKey     = "OTHER /:overflow"
	requestSeriesOverflowCounter = "observability_request_series_overflow_total"
)

type Registry struct {
	startedAt time.Time
	mu        sync.Mutex
	requests  map[string]*RequestSummary
	counters  map[string]int64
}

type RequestSummary struct {
	Count               int64 `json:"count"`
	Bytes               int64 `json:"bytes"`
	TotalDurationMillis int64 `json:"total_duration_ms"`
	MaxDurationMillis   int64 `json:"max_duration_ms"`
	LastStatus          int   `json:"last_status"`
}

type Snapshot struct {
	StartedAt      string                    `json:"started_at"`
	UptimeSeconds  int64                     `json:"uptime_seconds"`
	RequestSummary map[string]RequestSummary `json:"request_summary"`
	Counters       map[string]int64          `json:"counters,omitempty"`
}

func NewRegistry() *Registry {
	return &Registry{
		startedAt: time.Now().UTC(),
		requests:  make(map[string]*RequestSummary),
		counters:  make(map[string]int64),
	}
}

func (r *Registry) Observe(method, path string, statusCode int, bytesWritten int, duration time.Duration) {
	if r == nil {
		return
	}

	method = normalizeMetricMethod(method)
	path = normalizeMetricPath(path, statusCode)
	key := fmt.Sprintf("%s %s %d", method, path, statusCode)

	r.mu.Lock()
	defer r.mu.Unlock()

	summary, ok := r.requests[key]
	if !ok && len(r.requests) >= maxRequestSeries-1 {
		key = overflowRequestSeriesKey
		summary, ok = r.requests[key]
		r.counters[requestSeriesOverflowCounter]++
	}
	if !ok {
		summary = &RequestSummary{}
		r.requests[key] = summary
	}

	durationMillis := duration.Milliseconds()
	summary.Count++
	summary.Bytes += int64(bytesWritten)
	summary.TotalDurationMillis += durationMillis
	if durationMillis > summary.MaxDurationMillis {
		summary.MaxDurationMillis = durationMillis
	}
	summary.LastStatus = statusCode
}

func normalizeMetricMethod(method string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return method
	default:
		return "OTHER"
	}
}

func normalizeMetricPath(path string, statusCode int) string {
	if path == "" {
		path = "/"
	}
	if len(path) > maxMetricPathBytes {
		return "/:oversized"
	}

	// Internet scanners generate an unbounded set of missing paths. Preserve a
	// dedicated SPA-asset series because it can reveal a stale deployment, but
	// collapse other 404s so attacker-controlled input cannot grow the registry.
	if statusCode == http.StatusNotFound {
		switch {
		case strings.HasPrefix(path, "/app/assets/"):
			return "/app/assets/:missing"
		case strings.HasPrefix(path, "/assets/"):
			return "/assets/:missing"
		default:
			return "/:not-found"
		}
	}

	return path
}

func (r *Registry) Snapshot() Snapshot {
	if r == nil {
		return Snapshot{}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	requestSummary := make(map[string]RequestSummary, len(r.requests))
	for key, value := range r.requests {
		requestSummary[key] = *value
	}
	counters := make(map[string]int64, len(r.counters))
	for key, value := range r.counters {
		counters[key] = value
	}

	return Snapshot{
		StartedAt:      r.startedAt.Format(time.RFC3339Nano),
		UptimeSeconds:  int64(time.Since(r.startedAt).Seconds()),
		RequestSummary: requestSummary,
		Counters:       counters,
	}
}

func (r *Registry) IncCounter(name string) {
	if r == nil || name == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.counters[name]++
}
