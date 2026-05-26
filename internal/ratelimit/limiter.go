package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a per-key in-memory token bucket rate limiter.
// It is safe for concurrent use and automatically cleans up idle keys.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens refilled per second
	burst   int     // max tokens (burst capacity)
	done    chan struct{}
	once    sync.Once
}

type bucket struct {
	tokens    float64
	lastCheck time.Time
}

// New creates a Limiter that allows ratePerMinute requests on average
// with a maximum burst of burst requests. Pass ratePerMinute <= 0 to
// create a disabled (always-allow) limiter.
func New(ratePerMinute float64, burst int) *Limiter {
	l := &Limiter{
		buckets: make(map[string]*bucket),
		rate:    ratePerMinute / 60.0, // convert to per-second
		burst:   burst,
		done:    make(chan struct{}),
	}
	if ratePerMinute > 0 {
		go l.cleanupLoop()
	}
	return l
}

// Allow reports whether key has tokens available and consumes one if so.
// Returns true (allow) when rate <= 0 (disabled limiter).
func (l *Limiter) Allow(key string) bool {
	if l == nil || l.rate <= 0 {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{
			tokens:    float64(l.burst),
			lastCheck: now,
		}
		l.buckets[key] = b
	}

	// Refill tokens based on elapsed time.
	elapsed := now.Sub(b.lastCheck).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > float64(l.burst) {
		b.tokens = float64(l.burst)
	}
	b.lastCheck = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// SecondsUntilNextToken returns how many seconds until the key has
// at least one token available. Returns 0 if already allowed.
func (l *Limiter) SecondsUntilNextToken(key string) float64 {
	if l == nil || l.rate <= 0 {
		return 0
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok || b.tokens >= 1 {
		return 0
	}

	deficit := 1.0 - b.tokens
	return deficit / l.rate
}

// Close stops the background cleanup goroutine. Safe to call multiple times.
func (l *Limiter) Close() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		close(l.done)
	})
}

// cleanupLoop removes idle buckets every 5 minutes to prevent memory leaks.
func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-l.done:
			return
		case <-ticker.C:
			l.cleanup()
		}
	}
}

func (l *Limiter) cleanup() {
	const idleThreshold = 10 * time.Minute
	cutoff := time.Now().Add(-idleThreshold)

	l.mu.Lock()
	defer l.mu.Unlock()

	for key, b := range l.buckets {
		if b.lastCheck.Before(cutoff) {
			delete(l.buckets, key)
		}
	}
}

// Len returns the number of tracked keys. Useful for tests and diagnostics.
func (l *Limiter) Len() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
