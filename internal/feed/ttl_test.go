package feed

import (
	"testing"
	"time"
)

// Both sync entrypoints and the OSINT promotion derive their TTL from
// SAFE_ZONE_FEED_TTL_DAYS (default 14) through this helper; the default must
// match the feed.Sync fallback.
func TestTTLFromDays(t *testing.T) {
	ttl, err := TTLFromDays(14)
	if err != nil || ttl != 14*24*time.Hour {
		t.Fatalf("expected 14d TTL, got %v (err %v)", ttl, err)
	}
	if _, err := TTLFromDays(0); err == nil {
		t.Fatal("expected rejection of zero TTL")
	}
	if _, err := TTLFromDays(-3); err == nil {
		t.Fatal("expected rejection of negative TTL")
	}
}
