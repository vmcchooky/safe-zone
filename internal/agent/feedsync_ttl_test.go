package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

// The churn split must change only the expiry window, never admission. This
// drives the real task and asserts both halves of that contract at once: a
// recycled-label tenant and a dedicated domain are both written, the tenant
// carries the shortened score, and the dedicated domain keeps the full window.
func TestFeedSyncTaskShortensChurnTenantExpiryOnly(t *testing.T) {
	server, redisCache := newTestRedis(t)
	db := newTestStore(t)

	feedDir := t.TempDir()
	feedPath := filepath.Join(feedDir, "local-feed.txt")
	contents := strings.Join([]string{
		"campaign-42.duckdns.org", // churn tenant: shortened window
		"cid.ipfs.dweb.link",      // churn tenant: shortened window
		"evil.example.com",        // dedicated: full window
		"phish.pages.dev",         // self-service but not churn: full window
		"f-emc.ngsp.gov.vn",       // named critical service: full window
	}, "\n") + "\n"
	if err := os.WriteFile(feedPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("write feed fixture: %v", err)
	}

	base := 14 * 24 * time.Hour
	churn := 3 * 24 * time.Hour
	task := NewFeedSyncTask(db, FeedSyncConfig{
		Sources:       []string{"local-feed.txt"},
		FileRoot:      feedDir,
		RedisAddr:     server.Addr(),
		FeedKey:       testThreatKey,
		Timeout:       10 * time.Second,
		AdmissionMode: feed.AdmissionLegacy,
		TTL:           base,
		ChurnTTL:      churn,
	})

	if err := task.Run(context.Background()); err != nil {
		t.Fatalf("feed sync run: %v", err)
	}

	ctx := context.Background()
	now := time.Now()
	// Tolerance absorbs whole-second score truncation on both sides.
	tol := float64((2 * time.Minute).Seconds())

	for domain, want := range map[string]time.Duration{
		"campaign-42.duckdns.org": churn,
		"cid.ipfs.dweb.link":      churn,
		"evil.example.com":        base,
		"phish.pages.dev":         base,
		"f-emc.ngsp.gov.vn":       base,
	} {
		score, err := redisCache.ZScore(ctx, testThreatKey, domain)
		if err != nil {
			// Admission must never be the thing that drops a member:
			// a missing entry here would mean the churn split started
			// refusing hostnames instead of shortening their expiry.
			t.Fatalf("domain %s missing from threat zset: %v", domain, err)
		}
		wantScore := float64(now.Add(want).Unix())
		if score < wantScore-tol || score > wantScore+tol {
			t.Fatalf("domain %s score %v does not reflect TTL %v (want ~%v)", domain, score, want, wantScore)
		}
	}
}

// With the churn window disabled the split must be a complete no-op: every
// member, churn tenant included, keeps the base window.
func TestFeedSyncTaskChurnDisabledKeepsBaseWindow(t *testing.T) {
	server, redisCache := newTestRedis(t)
	db := newTestStore(t)

	feedDir := t.TempDir()
	feedPath := filepath.Join(feedDir, "local-feed.txt")
	if err := os.WriteFile(feedPath, []byte("campaign-42.duckdns.org\n"), 0o600); err != nil {
		t.Fatalf("write feed fixture: %v", err)
	}

	base := 14 * 24 * time.Hour
	task := NewFeedSyncTask(db, FeedSyncConfig{
		Sources:       []string{"local-feed.txt"},
		FileRoot:      feedDir,
		RedisAddr:     server.Addr(),
		FeedKey:       testThreatKey,
		Timeout:       10 * time.Second,
		AdmissionMode: feed.AdmissionLegacy,
		TTL:           base,
		ChurnTTL:      0,
	})

	if err := task.Run(context.Background()); err != nil {
		t.Fatalf("feed sync run: %v", err)
	}

	score, err := redisCache.ZScore(context.Background(), testThreatKey, "campaign-42.duckdns.org")
	if err != nil {
		t.Fatalf("churn tenant missing from threat zset: %v", err)
	}
	wantScore := float64(time.Now().Add(base).Unix())
	tol := float64((2 * time.Minute).Seconds())
	if score < wantScore-tol || score > wantScore+tol {
		t.Fatalf("disabled churn TTL must keep the base window, got %v want ~%v", score, wantScore)
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
