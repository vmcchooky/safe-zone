// Command load-ramp is an open-loop HTTP load generator for Safe Zone local
// capacity testing. It schedules requests at a target rate (requested RPS),
// reuses keep-alive connections aggressively, and reports achieved RPS plus
// latency percentiles and an error taxonomy so generator saturation can be
// distinguished from server saturation.
//
// Measurement tool for localhost/compose targets only: it performs no external
// DNS lookups beyond the literal target host address given via -url.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type config struct {
	targetURL     string
	workload      string
	rate          int
	duration      time.Duration
	warmup        time.Duration
	conns         int
	timeout       time.Duration
	maxLatSamples int
}

type summary struct {
	Workload        string         `json:"workload"`
	TargetURL       string         `json:"target_url"`
	RequestedRPS    int            `json:"requested_rps"`
	Scheduled       int64          `json:"scheduled"`
	AchievedRPS     float64        `json:"achieved_rps"`
	DurationSeconds float64        `json:"duration_seconds"`
	Connections     int            `json:"connections"`
	WarmupSeconds   float64        `json:"warmup_seconds"`
	Sent            int64          `json:"sent"`
	Completed       int64          `json:"completed"`
	QueueDrops      int64          `json:"scheduler_queue_drops"`
	MaxQueueDepth   int64          `json:"max_queue_depth"`
	NewConnections  int64          `json:"new_connections"`
	Status2xx       int64          `json:"status_2xx"`
	Status4xx       int64          `json:"status_4xx"`
	Status5xx       int64          `json:"status_5xx"`
	ErrorsTimeout   int64          `json:"errors_timeout"`
	ErrorsConnReset int64          `json:"errors_conn_reset"`
	ErrorsOther     int64          `json:"errors_other"`
	ErrorRateExact  float64        `json:"error_rate_exact"`
	LatencyMS       latencySummary `json:"latency_ms"`
	LatencySamples  int            `json:"latency_samples"`
	KeepAliveRatio  float64        `json:"keepalive_reuse_ratio"`
}

type latencySummary struct {
	P50  float64 `json:"p50"`
	P90  float64 `json:"p90"`
	P95  float64 `json:"p95"`
	P99  float64 `json:"p99"`
	Max  float64 `json:"max"`
	Mean float64 `json:"mean"`
}

const (
	hitPoolSize   = 64
	missPoolSize  = 8192
	urlPoolSize   = 64
	queueCapacity = 32768
)

type requestSet struct {
	getPaths  []string
	postSpecs []postSpec
}

type postSpec struct {
	path string
	body []byte
}

func buildRequestSet(base, workload string) requestSet {
	rs := requestSet{}
	switch workload {
	case "cache-hit":
		for i := 0; i < hitPoolSize; i++ {
			rs.getPaths = append(rs.getPaths,
				base+"/v1/analyze?domain=ramp-hit-"+pad(i%100)+"-"+fmt.Sprint(i)+".example")
		}
	case "analyze-mixed":
		// Deterministic miss pool: each request rotates through pre-generated
		// domains so cache behavior stays reproducible across A/B runs while
		// never collapsing onto a single cached payload.
		for i := 0; i < missPoolSize; i++ {
			rs.getPaths = append(rs.getPaths,
				base+"/v1/analyze?domain=ramp-miss-"+pad(i)+".example")
		}
	case "url-shadow":
		for i := 0; i < urlPoolSize; i++ {
			domain := fmt.Sprintf("ramp-url-%02d.example", i)
			full := fmt.Sprintf("https://%s/ramp/load/%d?step=%d", domain, i, i%7)
			body := fmt.Sprintf(`{"domain":"%s","requested_url":"%s","caller_class":"sdk"}`, domain, full)
			rs.postSpecs = append(rs.postSpecs, postSpec{
				path: base + "/v1/analyze",
				body: []byte(body),
			})
		}
	default: // health
		rs.getPaths = []string{base + "/healthz"}
	}
	return rs
}

func pad(n int) string {
	s := fmt.Sprint(n)
	for len(s) < 5 {
		s = "0" + s
	}
	return s
}

func main() {
	cfg := parseConfig()
	base := strings.TrimRight(cfg.targetURL, "/")
	reqSet := buildRequestSet(base, cfg.workload)

	tr := &http.Transport{
		Proxy:                 nil,
		MaxIdleConns:          cfg.conns,
		MaxIdleConnsPerHost:   cfg.conns,
		IdleConnTimeout:       120 * time.Second,
		DisableCompression:    true,
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: cfg.timeout,
	}
	var newConns atomic.Int64
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		newConns.Add(1)
		return dialer.DialContext(ctx, network, addr)
	}
	client := &http.Client{Transport: tr, Timeout: cfg.timeout}

	if cfg.warmup > 0 {
		runWindow(client, cfg, reqSet, cfg.warmup)
		newConns.Store(0) // warm-up dials must not pollute keep-alive accounting
	}

	res := runWindow(client, cfg, reqSet, cfg.duration)

	errs := res.errTimeout + res.errReset + res.errOther
	out := summary{
		Workload:        cfg.workload,
		TargetURL:       base,
		RequestedRPS:    cfg.rate,
		Scheduled:       int64(float64(cfg.rate) * cfg.duration.Seconds()),
		AchievedRPS:     float64(res.completed) / cfg.duration.Seconds(),
		DurationSeconds: cfg.duration.Seconds(),
		Connections:     cfg.conns,
		WarmupSeconds:   cfg.warmup.Seconds(),
		Sent:            res.sent,
		Completed:       res.completed,
		QueueDrops:      res.drops,
		MaxQueueDepth:   res.maxQueue,
		NewConnections:  newConns.Load(),
		Status2xx:       res.status2xx,
		Status4xx:       res.status4xx,
		Status5xx:       res.status5xx,
		ErrorsTimeout:   res.errTimeout,
		ErrorsConnReset: res.errReset,
		ErrorsOther:     res.errOther,
		LatencyMS:       percentileSummary(res.latencies),
		LatencySamples:  len(res.latencies),
	}
	if total := float64(res.completed); total > 0 {
		out.ErrorRateExact = float64(errs) / total
		if total > 0 && newConns.Load() > 0 {
			out.KeepAliveRatio = 1 - float64(newConns.Load())/total
		} else if newConns.Load() == 0 {
			out.KeepAliveRatio = 1
		}
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

type windowResult struct {
	sent       int64
	completed  int64
	drops      int64
	maxQueue   int64
	status2xx  int64
	status4xx  int64
	status5xx  int64
	errTimeout int64
	errReset   int64
	errOther   int64
	latencies  []float64
}

func runWindow(client *http.Client, cfg config, reqSet requestSet, duration time.Duration) windowResult {
	var (
		sent, completed, drops, maxQueue atomic.Int64
		status2xx, status4xx, status5xx  atomic.Int64
		errTimeout, errReset, errOther   atomic.Int64
	)

	tokens := make(chan struct{}, queueCapacity)
	stopSched := make(chan struct{})
	windowOver := make(chan struct{})
	var accepting atomic.Bool
	accepting.Store(true)

	// Open-loop scheduler: releases tokens at the requested rate regardless of
	// responses, stopping exactly at the window boundary. Queue capacity bounds
	// memory; overflow counts as a scheduler drop, which means neither the
	// generator nor the server kept up. The scheduler owns no context: its
	// lifetime is the wall-clock deadline alone, so the measurement window
	// cannot be inflated by an unrelated grace period.
	go func() {
		defer close(stopSched)
		deadline := time.Now().Add(duration)
		burst := cfg.rate / 100
		if burst < 1 {
			burst = 1
		}
		ticksPerSecond := cfg.rate / burst
		if ticksPerSecond < 1 {
			ticksPerSecond = 1
		}
		interval := time.Duration(int64(time.Second) / int64(ticksPerSecond))
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if !time.Now().Before(deadline) {
				return
			}
			for b := 0; b < burst; b++ {
				select {
				case tokens <- struct{}{}:
					sent.Add(1)
					d := int64(len(tokens))
					for {
						m := maxQueue.Load()
						if d <= m || maxQueue.CompareAndSwap(m, d) {
							break
						}
					}
				default:
					drops.Add(1)
				}
			}
		}
	}()

	expected := int64(float64(cfg.rate) * duration.Seconds())
	stride := expected / int64(cfg.maxLatSamples)
	if stride < 1 {
		stride = 1
	}
	var sampleIndex atomic.Int64
	var latMu sync.Mutex
	latencies := make([]float64, 0, expected/stride+1024)

	var cursor atomic.Uint64
	var wg sync.WaitGroup
	for range cfg.conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-windowOver:
					return
				case <-tokens:
					if !accepting.Load() {
						// Boundary crossed between enqueue and pickup:
						// charge the token as a scheduled-but-unsent drop
						// instead of leaking a send past the window.
						drops.Add(1)
						return
					}
				}
				started := time.Now()
				status, err := doRequest(client, cfg.workload, reqSet, &cursor)
				elapsed := time.Since(started)
				switch {
				case err != nil:
					switch classifyError(err) {
					case errClassTimeout:
						errTimeout.Add(1)
					case errClassReset:
						errReset.Add(1)
					default:
						errOther.Add(1)
					}
				case status >= 200 && status < 300:
					completed.Add(1)
					status2xx.Add(1)
				case status >= 400 && status < 500:
					completed.Add(1)
					status4xx.Add(1)
				case status >= 500:
					completed.Add(1)
					status5xx.Add(1)
				default:
					completed.Add(1)
					errOther.Add(1)
				}
				idx := sampleIndex.Add(1)
				if (idx-1)%stride == 0 {
					ms := float64(elapsed.Microseconds()) / 1000.0
					latMu.Lock()
					latencies = append(latencies, ms)
					latMu.Unlock()
				}
			}
		}()
	}

	<-stopSched // scheduler returned: send window lasted exactly `duration`

	// Refuse new work, wake parked workers, then wait only for requests that
	// were already in flight (bounded by the client timeout). Nothing new is
	// scheduled past the boundary, keeping achieved-RPS honest.
	accepting.Store(false)
	close(windowOver)
	wg.Wait()

	// Tokens left in the queue after the boundary were scheduled but never
	// dispatched; count them as dropped so Sent == Completed + errors + drops
	// stays reconcilable.
	drops.Add(remainingTokens(tokens))

	return windowResult{
		sent: sent.Load(), completed: completed.Load(), drops: drops.Load(),
		maxQueue: maxQueue.Load(), status2xx: status2xx.Load(), status4xx: status4xx.Load(),
		status5xx: status5xx.Load(), errTimeout: errTimeout.Load(), errReset: errReset.Load(),
		errOther: errOther.Load(), latencies: latencies,
	}
}

func remainingTokens(ch chan struct{}) int64 {
	var n int64
	for {
		select {
		case <-ch:
			n++
		default:
			return n
		}
	}
}

var bodyDiscardLimit = 16 << 10

func nextIndex(cursor *atomic.Uint64, pool int) int {
	return int((cursor.Add(1) - 1) % uint64(pool))
}

func doRequest(client *http.Client, workload string, reqSet requestSet, cursor *atomic.Uint64) (int, error) {
	switch workload {
	case "url-shadow":
		spec := reqSet.postSpecs[nextIndex(cursor, len(reqSet.postSpecs))]
		req, err := http.NewRequest(http.MethodPost, spec.path, bytes.NewReader(spec.body))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		return drain(resp)
	default:
		path := reqSet.getPaths[nextIndex(cursor, len(reqSet.getPaths))]
		resp, err := client.Get(path)
		if err != nil {
			return 0, err
		}
		return drain(resp)
	}
}

func drain(resp *http.Response) (int, error) {
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, int64(bodyDiscardLimit)))
	return resp.StatusCode, nil
}

type errClass int

const (
	errClassOther errClass = iota
	errClassTimeout
	errClassReset
)

func classifyError(err error) errClass {
	if err == nil {
		return errClassOther
	}
	type timeouter interface{ Timeout() bool }
	if t, ok := err.(timeouter); ok && t.Timeout() {
		return errClassTimeout
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "Client.Timeout"), strings.Contains(msg, "deadline exceeded"),
		strings.Contains(msg, "i/o timeout"):
		return errClassTimeout
	case strings.Contains(msg, "reset"), strings.Contains(msg, "broken pipe"):
		return errClassReset
	default:
		return errClassOther
	}
}

func percentileSummary(samples []float64) latencySummary {
	n := len(samples)
	if n == 0 {
		return latencySummary{}
	}
	sorted := make([]float64, n)
	copy(sorted, samples)
	sort.Float64s(sorted)
	pick := func(p float64) float64 {
		rank := int(p*float64(n-1) + 0.5)
		return round3(sorted[rank])
	}
	var sum float64
	for _, v := range sorted {
		sum += v
	}
	return latencySummary{
		P50: pick(0.50), P90: pick(0.90), P95: pick(0.95),
		P99: pick(0.99), Max: round3(sorted[n-1]),
		Mean: round3(sum / float64(n)),
	}
}

func round3(v float64) float64 { return float64(int(v*1000+0.5)) / 1000 }

func parseConfig() config {
	var cfg config
	flag.StringVar(&cfg.targetURL, "url", "http://127.0.0.1:8080", "base URL of the local target")
	flag.StringVar(&cfg.workload, "workload", "health", "health|cache-hit|analyze-mixed|url-shadow")
	flag.IntVar(&cfg.rate, "rate", 1000, "target requests per second (open-loop)")
	flag.DurationVar(&cfg.duration, "duration", 30*time.Second, "measurement window")
	flag.DurationVar(&cfg.warmup, "warmup", 10*time.Second, "unmeasured warm-up window at same rate")
	flag.IntVar(&cfg.conns, "conns", 64, "persistent connections / worker goroutines")
	flag.DurationVar(&cfg.timeout, "timeout", 5*time.Second, "per-request timeout")
	flag.IntVar(&cfg.maxLatSamples, "max-latency-samples", 500000, "latency sample budget")
	flag.Parse()
	return cfg
}
