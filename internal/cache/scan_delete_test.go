package cache

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func newScanTestRedis(t *testing.T) (*miniredis.Miniredis, *Redis) {
	t.Helper()
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	redisCache := NewRedis(server.Addr(), "", 0)
	t.Cleanup(func() { _ = redisCache.Close() })
	return server, redisCache
}

// Reaching the cursor end exactly at the scan budget is a complete pass and
// must not be reported as incomplete.
func TestScanDeleteCompleteExactlyAtBudgetBoundary(t *testing.T) {
	server, redisCache := newScanTestRedis(t)

	for i := 0; i < 10; i++ {
		if err := redisCache.SetString(context.Background(), fmt.Sprintf("safe-zone:analysis:bounded.test:model:r%d", i), "{}", time.Hour); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	deleted, err := redisCache.ScanDelete(context.Background(), "safe-zone:analysis:bounded.test:model:*", 10)
	if err != nil {
		t.Fatalf("exact-boundary pass must succeed, got %v", err)
	}
	if deleted != 10 {
		t.Fatalf("expected all 10 matching keys deleted, got %d", deleted)
	}
	if server.Exists("safe-zone:analysis:bounded.test:model:r0") {
		t.Fatal("expected matching keys to be deleted")
	}
}

// A budget exhausted with a live cursor is a partial delete: it must surface
// as ErrScanIncomplete, and retrying until success removes every matching
// key without ever touching keys outside the pattern.
func TestScanDeleteBudgetExhaustionIsRetriableFailure(t *testing.T) {
	_, redisCache := newScanTestRedis(t)

	const total = 250
	for i := 0; i < total; i++ {
		if err := redisCache.SetString(context.Background(), fmt.Sprintf("safe-zone:analysis:flood.test:model:r%03d", i), "{}", time.Hour); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	// Keys outside the target scope that must survive every pass.
	neighbors := []string{
		"safe-zone:analysis:flood-othersuffix.test",
		"safe-zone:analysis:other.test",
		"safe-zone:analysis:flood.test",
		"feed:revision",
	}
	for _, key := range neighbors {
		if err := redisCache.SetString(context.Background(), key, "{}", time.Hour); err != nil {
			t.Fatalf("seed neighbor: %v", err)
		}
	}

	totalDeleted := int64(0)
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		deleted, err := redisCache.ScanDelete(context.Background(), "safe-zone:analysis:flood.test:model:*", 100)
		totalDeleted += deleted
		if err == nil {
			lastErr = nil
			break
		}
		if !errors.Is(err, ErrScanIncomplete) {
			t.Fatalf("expected ErrScanIncomplete, got %v", err)
		}
		lastErr = err
	}
	if lastErr != nil {
		t.Fatalf("retries must eventually complete the delete, got %v", lastErr)
	}
	if totalDeleted != total {
		t.Fatalf("expected all %d matching keys deleted across retries, got %d", total, totalDeleted)
	}
	for _, key := range neighbors {
		if value, _ := redisCache.GetString(context.Background(), key); value == "" {
			t.Fatalf("key outside the pattern must survive: %s", key)
		}
	}
}
