package cache

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestRedisPublishJSONAndSubscribeRoundTrip(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	redisCache := NewRedis(server.Addr(), "", 0)
	defer func() {
		if err := redisCache.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	ch, closeSub, err := redisCache.Subscribe(context.Background(), "safe-zone:test:channel")
	if err != nil {
		t.Fatal(err)
	}

	payload := struct {
		Type     string `json:"type"`
		Revision string `json:"revision"`
		Source   string `json:"source"`
	}{
		Type:     "analysis_config_updated",
		Revision: "abc123",
		Source:   "core-api",
	}
	if err := redisCache.PublishJSON(context.Background(), "safe-zone:test:channel", payload); err != nil {
		t.Fatal(err)
	}

	select {
	case raw, ok := <-ch:
		if !ok {
			t.Fatal("subscription channel closed before delivering message")
		}

		var got struct {
			Type     string `json:"type"`
			Revision string `json:"revision"`
			Source   string `json:"source"`
		}
		if err := json.Unmarshal([]byte(raw), &got); err != nil {
			t.Fatalf("expected valid JSON payload, got %q: %v", raw, err)
		}
		if got != payload {
			t.Fatalf("unexpected payload: got %#v want %#v", got, payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for published message")
	}

	if err := closeSub(); err != nil {
		t.Fatal(err)
	}

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected subscription channel to close after cleanup")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for subscription cleanup")
	}
}

func TestRedisPubSubDisabled(t *testing.T) {
	redisCache := NewRedis("", "", 0)

	if err := redisCache.PublishJSON(context.Background(), "safe-zone:test:channel", map[string]string{"type": "noop"}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("expected ErrDisabled from PublishJSON, got %v", err)
	}

	ch, closeSub, err := redisCache.Subscribe(context.Background(), "safe-zone:test:channel")
	if !errors.Is(err, ErrDisabled) {
		t.Fatalf("expected ErrDisabled from Subscribe, got %v", err)
	}
	if ch != nil {
		t.Fatal("expected nil subscription channel when redis is disabled")
	}
	if closeSub != nil {
		t.Fatal("expected nil cleanup func when redis is disabled")
	}
}

func TestParseRedisRuntimeStats(t *testing.T) {
	stats, err := parseRedisRuntimeStats("# Memory\r\nused_memory:12345\r\nmaxmemory:268435456\r\nmaxmemory_policy:volatile-lru\r\n# Stats\r\nevicted_keys:7\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if stats.UsedMemoryBytes != 12345 {
		t.Fatalf("expected used memory 12345, got %d", stats.UsedMemoryBytes)
	}
	if stats.MaxMemoryBytes != 268435456 || !stats.HasMaxMemory {
		t.Fatalf("unexpected maxmemory state: %#v", stats)
	}
	if stats.MaxMemoryPolicy != "volatile-lru" {
		t.Fatalf("expected volatile-lru, got %q", stats.MaxMemoryPolicy)
	}
	if stats.EvictedKeys != 7 {
		t.Fatalf("expected 7 evicted keys, got %d", stats.EvictedKeys)
	}
	if safe, known := stats.ProtectsNonExpiringKeys(); !known || !safe {
		t.Fatalf("expected volatile-lru to protect non-expiring keys, safe=%t known=%t", safe, known)
	}
}

func TestRedisRuntimeStatsProtectionPolicy(t *testing.T) {
	tests := []struct {
		name  string
		stats RedisRuntimeStats
		safe  bool
		known bool
	}{
		{name: "unlimited", stats: RedisRuntimeStats{HasMaxMemory: true}, safe: true, known: true},
		{name: "volatile lru", stats: RedisRuntimeStats{HasMaxMemory: true, MaxMemoryBytes: 1, MaxMemoryPolicy: "volatile-lru"}, safe: true, known: true},
		{name: "volatile lfu", stats: RedisRuntimeStats{HasMaxMemory: true, MaxMemoryBytes: 1, MaxMemoryPolicy: "volatile-lfu"}, safe: true, known: true},
		{name: "volatile random", stats: RedisRuntimeStats{HasMaxMemory: true, MaxMemoryBytes: 1, MaxMemoryPolicy: "volatile-random"}, safe: true, known: true},
		{name: "volatile ttl", stats: RedisRuntimeStats{HasMaxMemory: true, MaxMemoryBytes: 1, MaxMemoryPolicy: "volatile-ttl"}, safe: true, known: true},
		{name: "no eviction", stats: RedisRuntimeStats{HasMaxMemory: true, MaxMemoryBytes: 1, MaxMemoryPolicy: "noeviction"}, safe: true, known: true},
		{name: "all keys lru", stats: RedisRuntimeStats{HasMaxMemory: true, MaxMemoryBytes: 1, MaxMemoryPolicy: "allkeys-lru"}, safe: false, known: true},
		{name: "all keys lfu", stats: RedisRuntimeStats{HasMaxMemory: true, MaxMemoryBytes: 1, MaxMemoryPolicy: "allkeys-lfu"}, safe: false, known: true},
		{name: "all keys random", stats: RedisRuntimeStats{HasMaxMemory: true, MaxMemoryBytes: 1, MaxMemoryPolicy: "allkeys-random"}, safe: false, known: true},
		{name: "unlimited unsafe policy", stats: RedisRuntimeStats{HasMaxMemory: true, MaxMemoryPolicy: "allkeys-lru"}, safe: true, known: true},
		{name: "missing maxmemory", stats: RedisRuntimeStats{MaxMemoryPolicy: "volatile-lru"}, safe: false, known: false},
		{name: "missing policy", stats: RedisRuntimeStats{HasMaxMemory: true, MaxMemoryBytes: 1}, safe: false, known: false},
		{name: "unknown", stats: RedisRuntimeStats{}, safe: false, known: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			safe, known := tc.stats.ProtectsNonExpiringKeys()
			if safe != tc.safe || known != tc.known {
				t.Fatalf("got safe=%t known=%t, want safe=%t known=%t", safe, known, tc.safe, tc.known)
			}
		})
	}
}

func TestParseRedisRuntimeStatsRejectsInvalidCounters(t *testing.T) {
	if _, err := parseRedisRuntimeStats("used_memory:not-a-number\n"); err == nil {
		t.Fatal("expected invalid used_memory to fail")
	}
}
