package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"safe-zone/internal/feed"
)

// The internal core-api feed-sync task must score members with the same
// configured TTL contract as the CLI tools and the OSINT promotion:
// SAFE_ZONE_FEED_TTL_DAYS resolved through feed.TTLFromDays. This drives the
// real task against a local feed file and a Redis-compatible server and
// reads the resulting expiry scores back from the ZSET.
func TestFeedSyncTaskScoresMembersWithConfiguredTTL(t *testing.T) {
	server, redisCache := newTestRedis(t)
	db := newTestStore(t)

	feedDir := t.TempDir()
	feedPath := filepath.Join(feedDir, "local-feed.txt")
	if err := os.WriteFile(feedPath, []byte("ttl-parity.test\nttl-parity-two.test\n"), 0o600); err != nil {
		t.Fatalf("write feed fixture: %v", err)
	}

	ttl := 48 * time.Hour
	task := NewFeedSyncTask(db, FeedSyncConfig{
		Sources:       []string{"local-feed.txt"},
		FileRoot:      feedDir,
		RedisAddr:     server.Addr(),
		FeedKey:       testThreatKey,
		Timeout:       10 * time.Second,
		AdmissionMode: feed.AdmissionLegacy,
		TTL:           ttl,
	})

	if err := task.Run(context.Background()); err != nil {
		t.Fatalf("feed sync run: %v", err)
	}

	wantScore := float64(time.Now().Add(ttl).Unix())
	for _, domain := range []string{"ttl-parity.test", "ttl-parity-two.test"} {
		score, err := redisCache.ZScore(context.Background(), testThreatKey, domain)
		if err != nil {
			t.Fatalf("synced domain %s missing from threat zset: %v", domain, err)
		}
		if score < wantScore-float64(time.Hour.Seconds()) || score > wantScore+float64(time.Hour.Seconds()) {
			t.Fatalf("domain %s score %v does not reflect configured TTL %v", domain, score, ttl)
		}
	}
}

// A non-positive TTL keeps the documented feed.Sync fallback so existing
// configurations that never set the TTL behave exactly as before.
func TestFeedSyncTaskZeroTTLUsesFeedSyncDefault(t *testing.T) {
	server, redisCache := newTestRedis(t)
	db := newTestStore(t)

	feedDir := t.TempDir()
	feedPath := filepath.Join(feedDir, "local-feed.txt")
	if err := os.WriteFile(feedPath, []byte("ttl-default.test\n"), 0o600); err != nil {
		t.Fatalf("write feed fixture: %v", err)
	}

	task := NewFeedSyncTask(db, FeedSyncConfig{
		Sources:       []string{"local-feed.txt"},
		FileRoot:      feedDir,
		RedisAddr:     server.Addr(),
		FeedKey:       testThreatKey,
		Timeout:       10 * time.Second,
		AdmissionMode: feed.AdmissionLegacy,
		TTL:           0,
	})

	if err := task.Run(context.Background()); err != nil {
		t.Fatalf("feed sync run: %v", err)
	}

	score, err := redisCache.ZScore(context.Background(), testThreatKey, "ttl-default.test")
	if err != nil {
		t.Fatalf("synced domain missing from threat zset: %v", err)
	}
	wantScore := float64(time.Now().Add(feed.DefaultSyncTTL).Unix())
	if score < wantScore-float64(time.Hour.Seconds()) || score > wantScore+float64(time.Hour.Seconds()) {
		t.Fatalf("default fallback score %v does not match the 14-day contract", score)
	}
}
