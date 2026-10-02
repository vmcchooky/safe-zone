package ratelimit_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"safe-zone/internal/ratelimit"
)

// ── Limiter tests ──────────────────────────────────────────────────────────────

// The key map must stay bounded. It was previously unbounded, so a flood
// that rotated the client IP (one forged X-Forwarded-For value per request)
// grew the map faster than the 5-minute idle sweep could reclaim it.
func TestLimiterKeyMapStaysBounded(t *testing.T) {
	const maxKeys = 50
	l := ratelimit.NewWithMaxKeys(60, 1, maxKeys)
	defer l.Close()

	for i := range 2000 {
		if !l.Allow(fmt.Sprintf("10.0.0.%d", i%256) + fmt.Sprintf(".%d", i/256)) {
			t.Fatalf("first request for a fresh key must be allowed (i=%d)", i)
		}
	}

	if got := l.Len(); got > maxKeys {
		t.Fatalf("tracked keys = %d, want <= %d", got, maxKeys)
	}
}

// A client that keeps sending traffic must not be evicted, or the limiter
// hands it a fresh burst and its rate limit resets.
func TestEvictionKeepsAnActiveClient(t *testing.T) {
	l := ratelimit.NewWithMaxKeys(60, 1, 3)
	defer l.Close()

	const active = "active-client"
	l.Allow(active)

	// Flood with fresh one-shot keys while keeping the active client warm
	// often enough that it is always among the most recently used.
	for i := range 50 {
		l.Allow(fmt.Sprintf("flood-%d", i))
		if i%2 == 0 {
			time.Sleep(time.Millisecond)
			l.Allow(active)
		}
	}

	if got := l.Len(); got > 3 {
		t.Fatalf("tracked keys = %d, want <= 3", got)
	}
	// The active client spent its burst, so a surviving bucket still denies it.
	// A wiped bucket would allow it.
	if l.Allow(active) {
		t.Fatal("the active client lost its bucket to eviction and had its rate limit reset")
	}
}

// The shipped constructor must apply the cap too: every service builds its
// limiters with New, not NewWithMaxKeys.
func TestNewAppliesDefaultKeyCap(t *testing.T) {
	l := ratelimit.New(60, 1)
	defer l.Close()

	for i := range ratelimit.DefaultMaxKeys + 5000 {
		l.Allow(fmt.Sprintf("key-%d", i))
	}

	if got := l.Len(); got > ratelimit.DefaultMaxKeys {
		t.Fatalf("tracked keys = %d, want <= DefaultMaxKeys (%d)", got, ratelimit.DefaultMaxKeys)
	}
}

func TestLimiterUnlimitedWhenMaxKeysNonPositive(t *testing.T) {
	l := ratelimit.NewWithMaxKeys(60, 1, 0)
	defer l.Close()

	for i := range 500 {
		l.Allow(fmt.Sprintf("key-%d", i))
	}
	if got := l.Len(); got != 500 {
		t.Fatalf("tracked keys = %d, want 500 (cap disabled)", got)
	}
}

// Eviction must not stall the limiter. A previous implementation sorted the
// whole key space under the write lock, which measured 88-215 ms at 50k keys
// and blocked every concurrent caller for the duration.
//
// The fill deliberately makes every key a repeat visitor (hits >= 2). That is
// the worst case: the one-shot pass finds nothing to take and has to walk the
// active list before the sweep pass can start. Filling with fresh one-shot keys
// instead would let the cheap pass do all the work and measure nothing — which
// is what an earlier version of this test accidentally did.
func TestEvictionDoesNotStallTheLimiter(t *testing.T) {
	const maxKeys = 20_000
	l := ratelimit.NewWithMaxKeys(600, 1000, maxKeys) // high burst, so keys land in active
	defer l.Close()

	for i := range maxKeys {
		key := fmt.Sprintf("key-%d", i)
		l.Allow(key)
		l.Allow(key) // repeat visitor, so pass 1 cannot drain it
	}
	if got := l.Len(); got != maxKeys {
		t.Fatalf("precondition: %d keys tracked, want %d", got, maxKeys)
	}

	worst := time.Duration(0)
	for i := range 200 {
		// Each insert trips eviction, because the map is already at the cap.
		start := time.Now()
		l.Allow(fmt.Sprintf("trigger-%d", i))
		if elapsed := time.Since(start); elapsed > worst {
			worst = elapsed
		}
	}
	t.Logf("worst eviction-bearing request: %v at %d tracked keys", worst, maxKeys)

	// Generous against the measured 12.5 ms worst case, but far below the
	// 88-215 ms of the sorted implementation, and loose enough not to flake on
	// a slow or ARM host.
	if worst > 100*time.Millisecond {
		t.Fatalf("slowest eviction-bearing request took %v; eviction is stalling the limiter", worst)
	}
}

func TestLimiter_AllowBasic(t *testing.T) {
	l := ratelimit.New(60, 3) // 1 req/sec, burst 3
	defer l.Close()

	// Should allow up to burst immediately.
	for i := range 3 {
		if !l.Allow("ip1") {
			t.Fatalf("request %d should be allowed (within burst)", i+1)
		}
	}
	// 4th request should be denied.
	if l.Allow("ip1") {
		t.Fatal("4th request should be rate limited")
	}
}

func TestLimiter_BurstCapacity(t *testing.T) {
	l := ratelimit.New(60, 5) // burst=5
	defer l.Close()

	allowed := 0
	for range 10 {
		if l.Allow("client") {
			allowed++
		}
	}
	if allowed != 5 {
		t.Fatalf("expected 5 allowed (burst), got %d", allowed)
	}
}

func TestLimiter_TokenRefill(t *testing.T) {
	// 120 req/min → 2 tokens/sec, burst=1
	l := ratelimit.New(120, 1)
	defer l.Close()

	if !l.Allow("x") {
		t.Fatal("first request should be allowed")
	}
	if l.Allow("x") {
		t.Fatal("second immediate request should be denied")
	}

	// Wait ~600ms; at 2 tokens/sec we should have ~1.2 tokens → allow.
	time.Sleep(600 * time.Millisecond)
	if !l.Allow("x") {
		t.Fatal("request after refill delay should be allowed")
	}
}

func TestLimiter_MultipleKeys(t *testing.T) {
	l := ratelimit.New(60, 1) // burst=1 per key
	defer l.Close()

	// Each IP gets its own bucket.
	if !l.Allow("ip1") {
		t.Fatal("ip1 first request should be allowed")
	}
	if !l.Allow("ip2") {
		t.Fatal("ip2 first request should be allowed")
	}
	// Second request from ip1 is denied, but not ip2's quota.
	if l.Allow("ip1") {
		t.Fatal("ip1 second request should be denied")
	}
	if l.Allow("ip2") {
		t.Fatal("ip2 second request should also be denied")
	}
}

func TestLimiter_Disabled(t *testing.T) {
	l := ratelimit.New(0, 0) // rate=0 → always allow
	defer l.Close()

	for range 1000 {
		if !l.Allow("any") {
			t.Fatal("disabled limiter should always allow")
		}
	}
}

func TestLimiter_NilSafe(t *testing.T) {
	var l *ratelimit.Limiter
	if !l.Allow("x") {
		t.Fatal("nil limiter should always allow")
	}
	l.Close() // must not panic
}

func TestLimiter_ConcurrentAccess(t *testing.T) {
	l := ratelimit.New(6000, 100) // high rate for concurrency test
	defer l.Close()

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Allow("shared-ip")
		}()
	}
	wg.Wait() // no panic = pass (use -race to detect data races)
}

func TestLimiter_SecondsUntilNextToken(t *testing.T) {
	l := ratelimit.New(60, 1) // 1 req/sec, burst=1
	defer l.Close()

	l.Allow("ip") // consume the only token

	wait := l.SecondsUntilNextToken("ip")
	if wait <= 0 || wait > 2 {
		t.Fatalf("expected wait ~1s, got %f", wait)
	}
}

func TestLimiter_SecondsUntilNextToken_NewKey(t *testing.T) {
	l := ratelimit.New(60, 5)
	defer l.Close()

	// Key not yet seen → full burst available → 0 wait.
	wait := l.SecondsUntilNextToken("new-ip")
	if wait != 0 {
		t.Fatalf("expected 0 wait for new key, got %f", wait)
	}
}

func TestLimiter_Len(t *testing.T) {
	l := ratelimit.New(60, 5)
	defer l.Close()

	l.Allow("a")
	l.Allow("b")
	l.Allow("c")

	if n := l.Len(); n != 3 {
		t.Fatalf("expected 3 tracked keys, got %d", n)
	}
}

// ── Middleware tests ───────────────────────────────────────────────────────────

func TestMiddleware_AllowsNormal(t *testing.T) {
	l := ratelimit.New(60, 5)
	defer l.Close()

	handler := ratelimit.NewTieredMiddleware(l).Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestMiddleware_Returns429(t *testing.T) {
	l := ratelimit.New(60, 1) // burst=1
	defer l.Close()

	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := ratelimit.NewTieredMiddleware(l).Wrap(ok)

	do := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/v1/analyze", nil)
		req.RemoteAddr = "10.0.0.2:9999"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	rec1 := do()
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request should be 200, got %d", rec1.Code)
	}
	rec2 := do()
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request should be 429, got %d", rec2.Code)
	}
}

func TestMiddleware_RetryAfterHeader(t *testing.T) {
	l := ratelimit.New(60, 1) // 1 req/sec, burst=1
	defer l.Close()

	handler := ratelimit.NewTieredMiddleware(l).Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "1.2.3.4:80"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	send() // consume burst
	rec := send()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" {
		t.Fatal("expected Retry-After header")
	}
}

func TestMiddleware_RetryAfterBody(t *testing.T) {
	l := ratelimit.New(60, 1)
	defer l.Close()

	handler := ratelimit.NewTieredMiddleware(l).Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "9.9.9.9:80"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	send()
	rec := send()

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "rate limit exceeded" {
		t.Fatalf("unexpected error field: %v", body["error"])
	}
	if _, ok := body["retry_after_seconds"]; !ok {
		t.Fatal("missing retry_after_seconds in body")
	}
}

func TestMiddleware_IPFromXForwardedFor(t *testing.T) {
	l := ratelimit.New(60, 1)
	defer l.Close()

	handler := ratelimit.NewTieredMiddleware(l).Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	send := func(xff string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("X-Forwarded-For", xff)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// Two different real IPs from the same proxy — treated as separate clients.
	r1 := send("192.168.1.1, proxy")
	r2 := send("192.168.1.2, proxy")
	if r1.Code != http.StatusOK {
		t.Fatalf("ip1 first request should be 200, got %d", r1.Code)
	}
	if r2.Code != http.StatusOK {
		t.Fatalf("ip2 first request should be 200, got %d", r2.Code)
	}
}

func TestMiddleware_IPFromXRealIP(t *testing.T) {
	l := ratelimit.New(60, 1)
	defer l.Close()

	handler := ratelimit.NewTieredMiddleware(l).Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Real-IP", "203.0.113.5")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for real-IP client, got %d", rec.Code)
	}
}

func TestTieredMiddleware_DifferentLimitsPerPath(t *testing.T) {
	analyzeLimiter := ratelimit.New(60, 1)  // burst=1
	defaultLimiter := ratelimit.New(60, 10) // burst=10
	defer analyzeLimiter.Close()
	defer defaultLimiter.Close()

	tm := ratelimit.NewTieredMiddleware(
		defaultLimiter,
		ratelimit.Tier{PathPrefix: "/v1/analyze", Limiter: analyzeLimiter},
	)

	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := tm.Wrap(ok)

	sendTo := func(path string) int {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.RemoteAddr = "5.5.5.5:80"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	// /v1/analyze burst=1 → 2nd denied
	if sendTo("/v1/analyze") != http.StatusOK {
		t.Fatal("first /v1/analyze should be 200")
	}
	if sendTo("/v1/analyze") != http.StatusTooManyRequests {
		t.Fatal("second /v1/analyze should be 429")
	}

	// /healthz default limiter (burst=10) → still allowed
	if sendTo("/healthz") != http.StatusOK {
		t.Fatal("/healthz should still be 200 (different limiter)")
	}
}
