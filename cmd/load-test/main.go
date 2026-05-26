package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

const (
	testTypeDoH       = "doh"
	testTypeAPI       = "api"
	scenarioMixed     = "mixed"
	scenarioCacheHit  = "cache-hit"
	scenarioCacheMiss = "cache-miss"
)

var defaultDomains = []string{
	"google.com",
	"facebook.com",
	"wikipedia.org",
	"evil-phishing.com",
	"bad-tracker.net",
	"secure-login-example.com",
	"xjfjwqeoas.com",
}

var defaultCacheHitDomains = []string{
	"google.com",
	"facebook.com",
	"wikipedia.org",
	"example.com",
}

type config struct {
	targetURL          string
	testType           string
	scenario           string
	concurrency        int
	duration           time.Duration
	rate               int
	warmup             int
	timeout            time.Duration
	domains            []string
	jsonOutput         bool
	maxP95             time.Duration
	maxP99             time.Duration
	maxErrorRate       float64
	minCacheHitRate    float64
	requireCacheMetric bool
}

type result struct {
	statusCode    int
	latency       time.Duration
	err           error
	cacheHit      bool
	cacheHitKnown bool
}

type summary struct {
	TargetURL       string         `json:"target_url"`
	TestType        string         `json:"test_type"`
	Scenario        string         `json:"scenario"`
	Concurrency     int            `json:"concurrency"`
	DurationSeconds float64        `json:"duration_seconds"`
	Total           int            `json:"total_requests"`
	Successes       int            `json:"successes"`
	Errors          int            `json:"errors"`
	Throughput      float64        `json:"throughput_rps"`
	ErrorRate       float64        `json:"error_rate_percent"`
	CacheHitRate    *float64       `json:"cache_hit_rate_percent,omitempty"`
	CacheHits       int            `json:"cache_hits,omitempty"`
	CacheKnown      int            `json:"cache_metric_known,omitempty"`
	Latency         latencySummary `json:"latency"`
	StatusCodes     map[int]int    `json:"status_codes"`
	ErrorKinds      map[string]int `json:"error_kinds,omitempty"`
	LoadGenerator   processStats   `json:"load_generator"`
	Pass            bool           `json:"pass"`
	Failures        []string       `json:"failures,omitempty"`
	latencies       []time.Duration
	elapsed         time.Duration
}

type latencySummary struct {
	MinMS float64 `json:"min_ms"`
	P50MS float64 `json:"p50_ms"`
	P95MS float64 `json:"p95_ms"`
	P99MS float64 `json:"p99_ms"`
	MaxMS float64 `json:"max_ms"`
}

type processStats struct {
	HeapAllocMB float64 `json:"heap_alloc_mb"`
	SysMB       float64 `json:"sys_mb"`
	NumGC       uint32  `json:"num_gc"`
	Goroutines  int     `json:"goroutines"`
}

type domainPicker struct {
	custom   []string
	scenario string
	count    atomic.Uint64
}

func main() {
	cfg, err := parseConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load-test: %v\n", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if !cfg.jsonOutput {
		printConfig(cfg)
	}

	if cfg.warmup > 0 {
		if !cfg.jsonOutput {
			fmt.Printf("Warmup:      %d requests\n\n", cfg.warmup)
		}
		warmup(context.Background(), cfg)
	}

	runCtx, cancel := context.WithTimeout(ctx, cfg.duration)
	defer cancel()

	started := time.Now()
	results := run(runCtx, cfg)
	report := summarize(results, time.Since(started), cfg)
	report.LoadGenerator = collectProcessStats()
	report.Pass, report.Failures = evaluateThresholds(report, cfg)

	if cfg.jsonOutput {
		encoded, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(encoded))
	} else {
		printSummary(report)
	}
	if !report.Pass {
		os.Exit(1)
	}
}

func parseConfig() (config, error) {
	var cfg config
	var rawDomains string

	flag.StringVar(&cfg.targetURL, "url", "http://localhost:8081/dns-query", "target HTTP URL")
	flag.StringVar(&cfg.testType, "type", testTypeDoH, "test type: doh or api")
	flag.StringVar(&cfg.scenario, "scenario", scenarioMixed, "scenario: mixed, cache-hit, or cache-miss")
	flag.IntVar(&cfg.concurrency, "concurrency", 10, "number of concurrent workers")
	flag.DurationVar(&cfg.duration, "duration", 10*time.Second, "total test duration")
	flag.IntVar(&cfg.rate, "rate", 0, "global target requests per second; 0 means unlimited")
	flag.IntVar(&cfg.warmup, "warmup", 0, "number of warmup requests before timed run")
	flag.DurationVar(&cfg.timeout, "timeout", 10*time.Second, "per-request timeout")
	flag.StringVar(&rawDomains, "domains", "", "optional comma-separated domains to query")
	flag.BoolVar(&cfg.jsonOutput, "json", false, "print machine-readable JSON summary")
	flag.DurationVar(&cfg.maxP95, "max-p95", 0, "fail if p95 latency exceeds this duration; 0 disables")
	flag.DurationVar(&cfg.maxP99, "max-p99", 0, "fail if p99 latency exceeds this duration; 0 disables")
	flag.Float64Var(&cfg.maxErrorRate, "max-error-rate", -1, "fail if error rate percent exceeds this value; negative disables")
	flag.Float64Var(&cfg.minCacheHitRate, "min-cache-hit-rate", -1, "fail if cache hit rate percent is below this value; negative disables")
	flag.BoolVar(&cfg.requireCacheMetric, "require-cache-metric", false, "fail if cache hit rate cannot be measured")
	flag.Parse()

	cfg.testType = strings.ToLower(strings.TrimSpace(cfg.testType))
	if cfg.testType != testTypeDoH && cfg.testType != testTypeAPI {
		return config{}, fmt.Errorf("-type must be %q or %q", testTypeDoH, testTypeAPI)
	}
	cfg.scenario = strings.ToLower(strings.TrimSpace(cfg.scenario))
	if cfg.scenario != scenarioMixed && cfg.scenario != scenarioCacheHit && cfg.scenario != scenarioCacheMiss {
		return config{}, fmt.Errorf("-scenario must be %q, %q, or %q", scenarioMixed, scenarioCacheHit, scenarioCacheMiss)
	}
	if strings.TrimSpace(cfg.targetURL) == "" {
		return config{}, fmt.Errorf("-url is required")
	}
	if cfg.concurrency <= 0 {
		return config{}, fmt.Errorf("-concurrency must be greater than 0")
	}
	if cfg.duration <= 0 {
		return config{}, fmt.Errorf("-duration must be greater than 0")
	}
	if cfg.timeout <= 0 {
		return config{}, fmt.Errorf("-timeout must be greater than 0")
	}
	if cfg.rate < 0 {
		return config{}, fmt.Errorf("-rate must be 0 or greater")
	}

	for _, value := range strings.Split(rawDomains, ",") {
		domain := strings.TrimSpace(value)
		if domain != "" {
			cfg.domains = append(cfg.domains, domain)
		}
	}

	return cfg, nil
}

func printConfig(cfg config) {
	fmt.Printf("Safe Zone Load Test\n")
	fmt.Printf("Target:      %s\n", cfg.targetURL)
	fmt.Printf("Type:        %s\n", cfg.testType)
	fmt.Printf("Scenario:    %s\n", cfg.scenario)
	fmt.Printf("Concurrency: %d\n", cfg.concurrency)
	fmt.Printf("Duration:    %s\n", cfg.duration)
	if cfg.rate > 0 {
		fmt.Printf("Rate limit:  %d req/s\n", cfg.rate)
	} else {
		fmt.Printf("Rate limit:  unlimited\n")
	}
	fmt.Println()
}

func warmup(parent context.Context, cfg config) {
	ctx, cancel := context.WithTimeout(parent, maxDuration(5*time.Second, cfg.timeout*time.Duration(cfg.warmup)))
	defer cancel()
	client := &http.Client{Timeout: cfg.timeout}
	picker := &domainPicker{custom: cfg.domains, scenario: cfg.scenario}
	for i := 0; i < cfg.warmup; i++ {
		_, _, _, _ = sendRequest(ctx, client, cfg, picker.Next())
	}
}

func run(ctx context.Context, cfg config) []result {
	resultCh := make(chan result, cfg.concurrency*4)
	var wg sync.WaitGroup
	picker := &domainPicker{custom: cfg.domains, scenario: cfg.scenario}
	client := &http.Client{Timeout: cfg.timeout}
	limiter := newRateLimiter(ctx, cfg.rate)

	for workerID := 0; workerID < cfg.concurrency; workerID++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if limiter != nil {
					select {
					case <-ctx.Done():
						return
					case _, ok := <-limiter:
						if !ok {
							return
						}
					}
				} else {
					select {
					case <-ctx.Done():
						return
					default:
					}
				}

				started := time.Now()
				statusCode, cacheHit, cacheHitKnown, err := sendRequest(ctx, client, cfg, picker.Next())
				res := result{
					statusCode:    statusCode,
					latency:       time.Since(started),
					err:           err,
					cacheHit:      cacheHit,
					cacheHitKnown: cacheHitKnown,
				}

				select {
				case resultCh <- res:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	results := make([]result, 0, cfg.concurrency*16)
	for res := range resultCh {
		results = append(results, res)
	}
	return results
}

func newRateLimiter(ctx context.Context, rate int) <-chan time.Time {
	if rate <= 0 {
		return nil
	}

	interval := time.Second / time.Duration(rate)
	if interval <= 0 {
		interval = time.Nanosecond
	}

	ticker := time.NewTicker(interval)
	ch := make(chan time.Time)
	go func() {
		defer close(ch)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case tick := <-ticker.C:
				select {
				case ch <- tick:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return ch
}

func sendRequest(ctx context.Context, client *http.Client, cfg config, domain string) (int, bool, bool, error) {
	switch cfg.testType {
	case testTypeDoH:
		return sendDoHRequest(ctx, client, cfg.targetURL, domain)
	case testTypeAPI:
		return sendAPIRequest(ctx, client, cfg.targetURL, domain)
	default:
		return 0, false, false, fmt.Errorf("unknown test type %q", cfg.testType)
	}
}

func sendDoHRequest(ctx context.Context, client *http.Client, targetURL, domain string) (int, bool, bool, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.RecursionDesired = true

	body, err := msg.Pack()
	if err != nil {
		return 0, false, false, fmt.Errorf("pack dns query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return 0, false, false, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	status, _, err := doRequest(client, req)
	return status, false, false, err
}

func sendAPIRequest(ctx context.Context, client *http.Client, targetURL, domain string) (int, bool, bool, error) {
	payload, err := json.Marshal(map[string]string{"domain": domain})
	if err != nil {
		return 0, false, false, fmt.Errorf("marshal api payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(payload))
	if err != nil {
		return 0, false, false, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	status, body, err := doRequest(client, req)
	if err != nil {
		return status, false, false, err
	}
	var response struct {
		CacheHit bool `json:"cache_hit"`
	}
	if json.Unmarshal(body, &response) != nil {
		return status, false, false, nil
	}
	return status, response.CacheHit, true, nil
}

func doRequest(client *http.Client, req *http.Request) (int, []byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, body, fmt.Errorf("http status %d", resp.StatusCode)
	}
	return resp.StatusCode, body, nil
}

func (p *domainPicker) Next() string {
	next := p.count.Add(1) - 1
	if len(p.custom) > 0 {
		return p.custom[boundedIndex(next, len(p.custom))]
	}
	switch p.scenario {
	case scenarioCacheHit:
		return defaultCacheHitDomains[boundedIndex(next, len(defaultCacheHitDomains))]
	case scenarioCacheMiss:
		return randomDomain(next)
	default:
		domain := defaultDomains[boundedIndex(next, len(defaultDomains))]
		if domain != "" {
			return domain
		}
		return randomDomain(next)
	}
}

func boundedIndex(next uint64, length int) int {
	// #nosec G115 -- modulo bounds idx to [0, length), and length is already an int.
	return int(next % uint64(length))
}

func randomDomain(seed uint64) string {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("user-%d-%d.test", time.Now().UnixNano(), seed)
	}
	return fmt.Sprintf("user-%d-%s.test", time.Now().UnixNano(), hex.EncodeToString(buf[:]))
}

func summarize(results []result, elapsed time.Duration, cfg config) summary {
	s := summary{
		TargetURL:       cfg.targetURL,
		TestType:        cfg.testType,
		Scenario:        cfg.scenario,
		Concurrency:     cfg.concurrency,
		DurationSeconds: elapsed.Seconds(),
		StatusCodes:     make(map[int]int),
		ErrorKinds:      make(map[string]int),
		elapsed:         elapsed,
	}

	for _, res := range results {
		s.Total++
		s.latencies = append(s.latencies, res.latency)
		if res.statusCode > 0 {
			s.StatusCodes[res.statusCode]++
		}
		if res.cacheHitKnown {
			s.CacheKnown++
			if res.cacheHit {
				s.CacheHits++
			}
		}
		if res.err == nil && res.statusCode == http.StatusOK {
			s.Successes++
			continue
		}
		s.Errors++
		if res.err != nil {
			s.ErrorKinds[classifyError(res.err)]++
		}
	}

	sort.Slice(s.latencies, func(i, j int) bool {
		return s.latencies[i] < s.latencies[j]
	})
	s.Throughput = qps(s.Total, elapsed)
	s.ErrorRate = errorRate(s)
	if s.CacheKnown > 0 {
		rate := float64(s.CacheHits) * 100 / float64(s.CacheKnown)
		s.CacheHitRate = &rate
	}
	s.Latency = latencySummary{
		MinMS: durationMS(percentile(s.latencies, 0)),
		P50MS: durationMS(percentile(s.latencies, 50)),
		P95MS: durationMS(percentile(s.latencies, 95)),
		P99MS: durationMS(percentile(s.latencies, 99)),
		MaxMS: durationMS(percentile(s.latencies, 100)),
	}
	return s
}

func classifyError(err error) string {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "client.timeout") || strings.Contains(message, "timeout") || strings.Contains(message, "deadline exceeded"):
		return "timeout"
	case strings.Contains(message, "connection refused"):
		return "connection refused"
	case strings.Contains(message, "no such host"):
		return "dns lookup"
	case strings.Contains(message, "http status"):
		return "non-200 status"
	default:
		return "request error"
	}
}

func printSummary(s summary) {
	fmt.Println("Summary")
	fmt.Println("=======")
	fmt.Printf("Total requests: %d\n", s.Total)
	fmt.Printf("Throughput:     %.2f req/s\n", s.Throughput)
	fmt.Printf("Success rate:   %.2f%% (%d OK / %d errors)\n", successRate(s), s.Successes, s.Errors)
	fmt.Printf("Error rate:     %.2f%%\n", s.ErrorRate)
	if s.CacheHitRate != nil {
		fmt.Printf("Cache hit rate: %.2f%% (%d hits / %d measured)\n", *s.CacheHitRate, s.CacheHits, s.CacheKnown)
	} else {
		fmt.Printf("Cache hit rate: n/a (not exposed by %s responses)\n", s.TestType)
	}
	fmt.Println()

	fmt.Println("Latency")
	fmt.Println("-------")
	fmt.Printf("Min: %s\n", formatLatencyMS(s.Latency.MinMS))
	fmt.Printf("p50: %s\n", formatLatencyMS(s.Latency.P50MS))
	fmt.Printf("p95: %s\n", formatLatencyMS(s.Latency.P95MS))
	fmt.Printf("p99: %s\n", formatLatencyMS(s.Latency.P99MS))
	fmt.Printf("Max: %s\n", formatLatencyMS(s.Latency.MaxMS))
	fmt.Println()

	fmt.Println("Load Generator")
	fmt.Println("--------------")
	fmt.Printf("Heap alloc: %.2f MB\n", s.LoadGenerator.HeapAllocMB)
	fmt.Printf("Sys memory: %.2f MB\n", s.LoadGenerator.SysMB)
	fmt.Printf("Goroutines: %d\n", s.LoadGenerator.Goroutines)
	fmt.Println()

	fmt.Println("HTTP Status Codes")
	fmt.Println("-----------------")
	if len(s.StatusCodes) == 0 {
		fmt.Println("(none)")
	} else {
		for _, code := range sortedStatusCodes(s.StatusCodes) {
			fmt.Printf("%d %-24s %d\n", code, http.StatusText(code), s.StatusCodes[code])
		}
	}

	if len(s.ErrorKinds) > 0 {
		fmt.Println()
		fmt.Println("Errors")
		fmt.Println("------")
		for _, name := range sortedErrorKinds(s.ErrorKinds) {
			fmt.Printf("%-24s %d\n", name, s.ErrorKinds[name])
		}
	}

	fmt.Println()
	if s.Pass {
		fmt.Println("Gate: PASS")
	} else {
		fmt.Println("Gate: FAIL")
		for _, failure := range s.Failures {
			fmt.Printf("- %s\n", failure)
		}
	}
}

func qps(total int, elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	return float64(total) / elapsed.Seconds()
}

func successRate(s summary) float64 {
	if s.Total == 0 {
		return 0
	}
	return float64(s.Successes) * 100 / float64(s.Total)
}

func errorRate(s summary) float64 {
	if s.Total == 0 {
		return 0
	}
	return float64(s.Errors) * 100 / float64(s.Total)
}

func percentile(values []time.Duration, pct float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	if pct <= 0 {
		return values[0]
	}
	if pct >= 100 {
		return values[len(values)-1]
	}

	rank := (pct / 100) * float64(len(values)-1)
	index := int(rank + 0.5)
	return values[index]
}

func durationMS(value time.Duration) float64 {
	return float64(value.Microseconds()) / 1000
}

func formatLatencyMS(value float64) string {
	return fmt.Sprintf("%.2f ms", value)
}

func sortedStatusCodes(counts map[int]int) []int {
	codes := make([]int, 0, len(counts))
	for code := range counts {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	return codes
}

func sortedErrorKinds(counts map[string]int) []string {
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func collectProcessStats() processStats {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return processStats{
		HeapAllocMB: bytesToMB(mem.HeapAlloc),
		SysMB:       bytesToMB(mem.Sys),
		NumGC:       mem.NumGC,
		Goroutines:  runtime.NumGoroutine(),
	}
}

func bytesToMB(value uint64) float64 {
	return float64(value) / 1024 / 1024
}

func evaluateThresholds(s summary, cfg config) (bool, []string) {
	var failures []string
	if cfg.maxP95 > 0 && percentile(s.latencies, 95) > cfg.maxP95 {
		failures = append(failures, fmt.Sprintf("p95 latency %s exceeds threshold %s", formatLatencyMS(s.Latency.P95MS), cfg.maxP95))
	}
	if cfg.maxP99 > 0 && percentile(s.latencies, 99) > cfg.maxP99 {
		failures = append(failures, fmt.Sprintf("p99 latency %s exceeds threshold %s", formatLatencyMS(s.Latency.P99MS), cfg.maxP99))
	}
	if cfg.maxErrorRate >= 0 && s.ErrorRate > cfg.maxErrorRate {
		failures = append(failures, fmt.Sprintf("error rate %.2f%% exceeds threshold %.2f%%", s.ErrorRate, cfg.maxErrorRate))
	}
	if cfg.requireCacheMetric && s.CacheHitRate == nil {
		failures = append(failures, "cache hit rate was not measurable")
	}
	if cfg.minCacheHitRate >= 0 {
		if s.CacheHitRate == nil {
			failures = append(failures, fmt.Sprintf("cache hit rate unavailable; required >= %.2f%%", cfg.minCacheHitRate))
		} else if *s.CacheHitRate < cfg.minCacheHitRate {
			failures = append(failures, fmt.Sprintf("cache hit rate %.2f%% below threshold %.2f%%", *s.CacheHitRate, cfg.minCacheHitRate))
		}
	}
	if s.Total == 0 || math.IsNaN(s.Throughput) {
		failures = append(failures, "no requests completed")
	}
	return len(failures) == 0, failures
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
