package ratelimit_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"safe-zone/internal/ratelimit"
)

// ── Limiter tests ──────────────────────────────────────────────────────────────

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

	handler := ratelimit.Middleware(l, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	handler := ratelimit.Middleware(l, ok)

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

	handler := ratelimit.Middleware(l, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
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

	handler := ratelimit.Middleware(l, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
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

	handler := ratelimit.Middleware(l, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

	handler := ratelimit.Middleware(l, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
