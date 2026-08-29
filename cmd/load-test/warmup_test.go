package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A canceled (or interrupted) context must abort the warmup phase promptly:
// warmup is bounded and responsive to Ctrl+C/SIGTERM.
func TestWarmupRespectsCanceledContext(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config{
		targetURL:   server.URL,
		testType:    testTypeAPI,
		warmup:      1000,
		timeout:     5 * time.Second,
		concurrency: 1,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started := time.Now()
	warmup(ctx, cfg)
	elapsed := time.Since(started)

	if got := atomic.LoadInt32(&requests); got != 0 {
		t.Fatalf("canceled warmup must not issue requests, got %d", got)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("canceled warmup must return promptly, took %v", elapsed)
	}
}

// A live warmup completes its full quota when the context stays open.
func TestWarmupCompletesWhenContextAlive(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config{
		targetURL:   server.URL,
		testType:    testTypeAPI,
		warmup:      5,
		timeout:     5 * time.Second,
		concurrency: 1,
	}

	warmup(context.Background(), cfg)

	if got := atomic.LoadInt32(&requests); got != 5 {
		t.Fatalf("expected 5 warmup requests, got %d", got)
	}
}
