package observability

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// prometheusContentType is the Prometheus text exposition format version 0.0.4
// that every scraper expects.
const prometheusContentType = "text/plain; version=0.0.4; charset=utf-8"

// prometheusPrefix namespaces every metric so the Safe Zone series never
// collide with runtime or third-party series in the same scrape.
const prometheusPrefix = "safe_zone_"

// RenderPrometheus writes snap in the Prometheus text exposition format. It is
// a pure function of the registry snapshot: no new state, no dependency, and
// cardinality stays bounded by the same maxRequestSeries cap that bounds the
// JSON snapshot.
//
// The request summary map is keyed "METHOD path status"; each entry fans out
// into a request counter, duration sum/count/max and response-bytes counter
// sharing one label set, which is how a scraper reconstructs rates and
// quantile-free latency from pre-aggregated data.
func RenderPrometheus(w io.Writer, snap Snapshot) error {
	var b strings.Builder

	writeGauge(&b, "uptime_seconds", "Seconds since the metrics registry started.", snap.UptimeSeconds)

	// Emit request series in a deterministic order so scrapers see stable
	// output and tests can golden-compare.
	keys := make([]string, 0, len(snap.RequestSummary))
	for key := range snap.RequestSummary {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		summary := snap.RequestSummary[key]
		method, path, status := splitRequestSeriesKey(key)
		labels := fmt.Sprintf("method=%q,path=%q,status=%q", method, path, status)

		writeCounterLabeled(&b, "http_requests_total", "Total requests observed by the API surface.", labels, summary.Count)
		writeCounterLabeled(&b, "http_request_duration_milliseconds_sum", "Cumulative request duration in milliseconds.", labels, summary.TotalDurationMillis)
		writeCounterLabeled(&b, "http_request_duration_milliseconds_count", "Total requests observed by the API surface.", labels, summary.Count)
		writeGaugeLabeled(&b, "http_request_duration_milliseconds_max", "Slowest observed request duration in milliseconds.", labels, summary.MaxDurationMillis)
		writeCounterLabeled(&b, "http_response_bytes_total", "Total response bytes written.", labels, summary.Bytes)
	}

	// Counters come from IncCounter with free-form names, so both the metric
	// name and its ordering need normalizing before they are valid exposition.
	counterNames := make([]string, 0, len(snap.Counters))
	for name := range snap.Counters {
		counterNames = append(counterNames, name)
	}
	sort.Strings(counterNames)
	for _, name := range counterNames {
		writeCounter(&b, prometheusCounterName(name), "Safe Zone counter.", snap.Counters[name])
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// PrometheusHandler serves the registry snapshot in Prometheus text format.
// Route registration keeps the same admin gate as the JSON /metrics handler —
// the label set is identical, so it leaks the same API surface.
func (r *Registry) PrometheusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", prometheusContentType)
		if err := RenderPrometheus(w, r.Snapshot()); err != nil {
			// Headers are already sent; nothing actionable beyond logging via
			// the standard mechanism scrapers understand (truncated body).
			return
		}
	}
}

func splitRequestSeriesKey(key string) (method, path, status string) {
	first := strings.IndexByte(key, ' ')
	if first < 0 {
		return key, "", ""
	}
	second := strings.IndexByte(key[first+1:], ' ')
	if second < 0 {
		return key[:first], key[first+1:], ""
	}
	second += first + 1
	return key[:first], key[first+1 : second], key[second+1:]
}

// prometheusCounterName normalizes an IncCounter name into a valid exposition
// metric: illegal characters become underscores and the _total suffix that
// Prometheus requires for counters is appended when missing.
func prometheusCounterName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == ':':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := prometheusPrefix + b.String()
	if !strings.HasSuffix(out, "_total") {
		out += "_total"
	}
	return out
}

func writeMetricHeader(b *strings.Builder, name, help, kind string) {
	fmt.Fprintf(b, "# HELP %s%s %s\n", prometheusPrefix, name, help)
	fmt.Fprintf(b, "# TYPE %s%s %s\n", prometheusPrefix, name, kind)
}

func writeGauge(b *strings.Builder, name, help string, value int64) {
	writeMetricHeader(b, name, help, "gauge")
	fmt.Fprintf(b, "%s%s %d\n", prometheusPrefix, name, value)
}

func writeGaugeLabeled(b *strings.Builder, name, help, labels string, value int64) {
	fmt.Fprintf(b, "%s%s{%s} %d\n", prometheusPrefix, name, labels, value)
}

func writeCounterLabeled(b *strings.Builder, name, help, labels string, value int64) {
	// HELP/TYPE are emitted once per series family by convention; the request
	// fan-out repeats them because each label set stands alone, and scrapers
	// accept repeated headers for the same family.
	writeMetricHeader(b, name, help, "counter")
	fmt.Fprintf(b, "%s%s{%s} %d\n", prometheusPrefix, name, labels, value)
}

func writeCounter(b *strings.Builder, name, help string, value int64) {
	writeMetricHeader(b, name, help, "counter")
	fmt.Fprintf(b, "%s %d\n", name, value)
}
