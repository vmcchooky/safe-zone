package risk

import (
	"context"
	"testing"
	"time"

	"safe-zone/internal/cache"
	"safe-zone/internal/config"

	"github.com/alicebob/miniredis/v2"
)

// A caller can supply these durations through Options without also supplying a
// default. The environment helper that feeds them only falls back when the variable
// is unset or unparseable, so an explicit "0" arrives intact — and both values fail in
// opposite directions at their sites.
//
//   - TTLs: go-redis attaches no expiry unless the duration is positive, so a zero TTL
//     writes an immortal analysis-verdict cache entry.
//   - RedisTimeout: every cache call is wrapped in context.WithTimeout(ctx, d), so a
//     zero timeout makes each one already expired before it starts.
//
// These tests pin the fallback rather than the field assignment alone, and the last
// one measures the consequence: a cache write made with the service's own blocked TTL
// must actually carry an expiry.
func TestNonPositiveDurationsFallBackToDefaults(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options Options
		want    func(*Service) time.Duration
	}{
		{
			name:    "redis timeout",
			options: Options{RedisTimeout: 0},
			want:    func(s *Service) time.Duration { return s.redisTimeout },
		},
		{
			name:    "allowed ttl",
			options: Options{TTLAllowed: 0},
			want:    func(s *Service) time.Duration { return s.ttlAllowed },
		},
		{
			name:    "suspicious ttl",
			options: Options{TTLSuspicious: 0},
			want:    func(s *Service) time.Duration { return s.ttlSuspicious },
		},
		{
			name:    "blocked ttl",
			options: Options{TTLBlocked: 0},
			want:    func(s *Service) time.Duration { return s.ttlBlocked },
		},
	} {
		t.Run(tc.name+" zero", func(t *testing.T) {
			svc := NewService(tc.options)
			if got := tc.want(svc); got <= 0 {
				t.Fatalf("%s = %s, want a positive default", tc.name, got)
			}
		})
		t.Run(tc.name+" negative", func(t *testing.T) {
			opts := tc.options
			// A negative duration is worse than zero for the TTLs: go-redis treats
			// -1ns as KeepTTL rather than as "no expiry".
			switch tc.name {
			case "redis timeout":
				opts.RedisTimeout = -time.Second
			case "allowed ttl":
				opts.TTLAllowed = -time.Second
			case "suspicious ttl":
				opts.TTLSuspicious = -time.Second
			case "blocked ttl":
				opts.TTLBlocked = -time.Second
			}
			svc := NewService(opts)
			if got := tc.want(svc); got <= 0 {
				t.Fatalf("%s = %s, want a positive default", tc.name, got)
			}
		})
	}
}

// The fallbacks must not clamp a value an operator chose deliberately.
func TestPositiveDurationsAreLeftAlone(t *testing.T) {
	svc := NewService(Options{
		RedisTimeout:  3 * time.Second,
		TTLAllowed:    30 * time.Minute,
		TTLSuspicious: 45 * time.Minute,
		TTLBlocked:    90 * time.Minute,
	})
	if svc.redisTimeout != 3*time.Second {
		t.Fatalf("redisTimeout = %s, want the supplied 3s", svc.redisTimeout)
	}
	if svc.ttlAllowed != 30*time.Minute {
		t.Fatalf("ttlAllowed = %s, want the supplied 30m", svc.ttlAllowed)
	}
	if svc.ttlSuspicious != 45*time.Minute {
		t.Fatalf("ttlSuspicious = %s, want the supplied 45m", svc.ttlSuspicious)
	}
	if svc.ttlBlocked != 90*time.Minute {
		t.Fatalf("ttlBlocked = %s, want the supplied 90m", svc.ttlBlocked)
	}
}

// The field assertion is the easy half. This is the half that shows the consequence:
// a cache entry written with the service's own TTL has to carry an expiry, and it does
// not when the TTL reaches zero.
func TestCacheWriteWithAZeroConfiguredTTLGainsAnExpiry(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	defer server.Close()

	cacheLayer := cache.NewRedis(server.Addr(), "", 0)

	svc := NewService(Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		Redis:              cacheLayer,
		DisableAdblockSync: true,
		// The misconfiguration this guards against: an operator sets the variable to 0.
		TTLBlocked: 0,
	})

	ttl := svc.ttlBlocked
	if ttl <= 0 {
		t.Fatalf("blocked TTL = %s; a cache write with it would be immortal", ttl)
	}
	if err := cacheLayer.SetJSON(context.Background(), "analysis:example.test", map[string]any{"v": 1}, ttl); err != nil {
		t.Fatalf("write cache entry: %v", err)
	}
	exp := server.TTL("analysis:example.test")
	if exp == 0 {
		t.Fatal("cached entry has no expiry; it would outlive any feed update")
	}
	if exp > ttl {
		t.Fatalf("cached entry expires in %s, longer than the configured %s", exp, ttl)
	}
}
