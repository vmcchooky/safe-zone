package osint

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// The in-memory evidence map is bounded: expired reports go first, then
// the oldest check. Redis TTL copies survive, so eviction costs a refetch.
func TestMemoryEvictionBoundsMap(t *testing.T) {
	service := NewService(Options{Enabled: true})
	ctx := context.Background()

	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	for i := 0; i < maxMemoryReports+10; i++ {
		service.store(ctx, fmt.Sprintf("stale-%d.test", i), Report{
			Domain:    fmt.Sprintf("stale-%d.test", i),
			CheckedAt: old,
			ExpiresAt: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano),
		})
	}
	service.store(ctx, "fresh.test", Report{
		Domain:    "fresh.test",
		CheckedAt: time.Now().UTC().Format(time.RFC3339Nano),
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
	})
	if n := len(service.memory); n > maxMemoryReports {
		t.Fatalf("memory map exceeded cap: %d > %d", n, maxMemoryReports)
	}
	if _, ok := service.memory["fresh.test"]; !ok {
		t.Fatal("fresh report must survive eviction")
	}
}

func TestMemoryEvictionDropsOldestWhenFull(t *testing.T) {
	service := NewService(Options{Enabled: true})
	ctx := context.Background()

	base := time.Now().UTC()
	for i := 0; i < maxMemoryReports; i++ {
		domain := fmt.Sprintf("full-%d.test", i)
		service.store(ctx, domain, Report{
			Domain:    domain,
			CheckedAt: base.Add(time.Duration(i) * time.Second).UTC().Format(time.RFC3339Nano),
			ExpiresAt: base.Add(24 * time.Hour).UTC().Format(time.RFC3339Nano),
		})
	}
	service.store(ctx, "newest.test", Report{
		Domain:    "newest.test",
		CheckedAt: base.Add(48 * time.Hour).UTC().Format(time.RFC3339Nano),
		ExpiresAt: base.Add(72 * time.Hour).UTC().Format(time.RFC3339Nano),
	})
	if n := len(service.memory); n != maxMemoryReports {
		t.Fatalf("expected exactly capped size %d, got %d", maxMemoryReports, n)
	}
	if _, ok := service.memory["full-0.test"]; ok {
		t.Fatal("oldest report must be evicted first")
	}
	if _, ok := service.memory["newest.test"]; !ok {
		t.Fatal("newest report must be kept")
	}
}
