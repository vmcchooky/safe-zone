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
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

const (
	testTypeDoH = "doh"
	testTypeAPI = "api"
)

var defaultDomains = []string{
	"google.com",
	"facebook.com",
	"wikipedia.org",
	"evil-phishing.com",
	"bad-tracker.net",
	"",
	"",
}

type config struct {
	targetURL   string
	testType    string
	concurrency int
	duration    time.Duration
	rate        int
	domains     []string
}

type result struct {
	statusCode int
	latency    time.Duration
	err        error
}

type summary struct {
	total       int
	successes   int
	errors      int
	latencies   []time.Duration
	statusCodes map[int]int
	errorKinds  map[string]int
	elapsed     time.Duration
}

type domainPicker struct {
	custom []string
	count  atomic.Uint64
}

func main() {
	cfg, err := parseConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load-test: %v\n", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, cfg.duration)
	defer cancel()

	fmt.Printf("Safe Zone Load Test\n")
	fmt.Printf("Target:      %s\n", cfg.targetURL)
	fmt.Printf("Type:        %s\n", cfg.testType)
	fmt.Printf("Concurrency: %d\n", cfg.concurrency)
	fmt.Printf("Duration:    %s\n", cfg.duration)
	if cfg.rate > 0 {
		fmt.Printf("Rate limit:  %d req/s\n", cfg.rate)
	} else {
		fmt.Printf("Rate limit:  unlimited\n")
	}
	fmt.Println()

	started := time.Now()
	results := run(ctx, cfg)
	report := summarize(results, time.Since(started))
	printSummary(report)
}

func parseConfig() (config, error) {
	var cfg config
	var rawDomains string

	flag.StringVar(&cfg.targetURL, "url", "http://localhost:8081/dns-query", "target HTTP URL")
	flag.StringVar(&cfg.testType, "type", testTypeDoH, "test type: doh or api")
	flag.IntVar(&cfg.concurrency, "concurrency", 10, "number of concurrent workers")
	flag.DurationVar(&cfg.duration, "duration", 10*time.Second, "total test duration")
	flag.IntVar(&cfg.rate, "rate", 0, "global target requests per second; 0 means unlimited")
	flag.StringVar(&rawDomains, "domains", "", "optional comma-separated domains to query")
	flag.Parse()

	cfg.testType = strings.ToLower(strings.TrimSpace(cfg.testType))
	if cfg.testType != testTypeDoH && cfg.testType != testTypeAPI {
		return config{}, fmt.Errorf("-type must be %q or %q", testTypeDoH, testTypeAPI)
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

func run(ctx context.Context, cfg config) []result {
	resultCh := make(chan result, cfg.concurrency*4)
	var wg sync.WaitGroup
	picker := &domainPicker{custom: cfg.domains}
	client := &http.Client{Timeout: 10 * time.Second}
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

				domain := picker.Next()
				started := time.Now()
				statusCode, err := sendRequest(ctx, client, cfg, domain)
				res := result{
					statusCode: statusCode,
					latency:    time.Since(started),
					err:        err,
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

func sendRequest(ctx context.Context, client *http.Client, cfg config, domain string) (int, error) {
	switch cfg.testType {
	case testTypeDoH:
		return sendDoHRequest(ctx, client, cfg.targetURL, domain)
	case testTypeAPI:
		return sendAPIRequest(ctx, client, cfg.targetURL, domain)
	default:
		return 0, fmt.Errorf("unknown test type %q", cfg.testType)
	}
}

func sendDoHRequest(ctx context.Context, client *http.Client, targetURL, domain string) (int, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.RecursionDesired = true

	body, err := msg.Pack()
	if err != nil {
		return 0, fmt.Errorf("pack dns query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	return doRequest(client, req)
}

func sendAPIRequest(ctx context.Context, client *http.Client, targetURL, domain string) (int, error) {
	payload, err := json.Marshal(map[string]string{"domain": domain})
	if err != nil {
		return 0, fmt.Errorf("marshal api payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(payload))
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	return doRequest(client, req)
}

func doRequest(client *http.Client, req *http.Request) (int, error) {
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("http status %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

func (p *domainPicker) Next() string {
	next := p.count.Add(1) - 1
	if len(p.custom) > 0 {
		return p.custom[boundedIndex(next, len(p.custom))]
	}

	domain := defaultDomains[boundedIndex(next, len(defaultDomains))]
	if domain != "" {
		return domain
	}
	return randomDomain(next)
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

func summarize(results []result, elapsed time.Duration) summary {
	s := summary{
		statusCodes: make(map[int]int),
		errorKinds:  make(map[string]int),
		elapsed:     elapsed,
	}

	for _, res := range results {
		s.total++
		s.latencies = append(s.latencies, res.latency)
		if res.statusCode > 0 {
			s.statusCodes[res.statusCode]++
		}
		if res.err == nil && res.statusCode == http.StatusOK {
			s.successes++
			continue
		}
		s.errors++
		if res.err != nil {
			s.errorKinds[classifyError(res.err)]++
		}
	}

	sort.Slice(s.latencies, func(i, j int) bool {
		return s.latencies[i] < s.latencies[j]
	})
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
	fmt.Printf("Total requests: %d\n", s.total)
	fmt.Printf("Throughput:     %.2f req/s\n", qps(s.total, s.elapsed))
	fmt.Printf("Success rate:   %.2f%% (%d OK / %d errors)\n", successRate(s), s.successes, s.errors)
	fmt.Println()

	fmt.Println("Latency")
	fmt.Println("-------")
	fmt.Printf("Min: %s\n", formatLatency(percentile(s.latencies, 0)))
	fmt.Printf("p50: %s\n", formatLatency(percentile(s.latencies, 50)))
	fmt.Printf("p90: %s\n", formatLatency(percentile(s.latencies, 90)))
	fmt.Printf("p99: %s\n", formatLatency(percentile(s.latencies, 99)))
	fmt.Printf("Max: %s\n", formatLatency(percentile(s.latencies, 100)))
	fmt.Println()

	fmt.Println("HTTP Status Codes")
	fmt.Println("-----------------")
	if len(s.statusCodes) == 0 {
		fmt.Println("(none)")
	} else {
		for _, code := range sortedStatusCodes(s.statusCodes) {
			fmt.Printf("%d %-24s %d\n", code, http.StatusText(code), s.statusCodes[code])
		}
	}

	if len(s.errorKinds) > 0 {
		fmt.Println()
		fmt.Println("Errors")
		fmt.Println("------")
		for _, name := range sortedErrorKinds(s.errorKinds) {
			fmt.Printf("%-24s %d\n", name, s.errorKinds[name])
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
	if s.total == 0 {
		return 0
	}
	return float64(s.successes) * 100 / float64(s.total)
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

func formatLatency(value time.Duration) string {
	return fmt.Sprintf("%.2f ms", float64(value.Microseconds())/1000)
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
