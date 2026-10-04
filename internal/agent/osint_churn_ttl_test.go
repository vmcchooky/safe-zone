package agent

import (
	"context"
	"testing"
	"time"

	"safe-zone/internal/feed"
)

// A promoted member and a feed-synced member were being given different expiry
// windows. The feed path applies feed.MemberTTL, which shortens the window for a
// tenant leaf under a churn-prone root; the OSINT promotion path scored the raw base
// TTL. For a label like campaign-42.ddns.net that is the exact harm the churn split
// exists to bound: the entry records "this label was malicious on date X" and keeps
// blocking long after the label has been released back into the pool for an
// unrelated party.
//
// The contract already said the two must not drift — internal/feed/ttl.go names the
// OSINT promotion explicitly in both TTLFromDays and ChurnTTLFromDays. The code did
// not implement the second half of that promise.

func TestOSINTPromotionShortensExpiryForChurnProneTenant(t *testing.T) {
	const (
		base  = 14 * 24 * time.Hour
		churn = 3 * 24 * time.Hour
	)
	if feed.MemberTTL("campaign-42.ddns.net", base, churn) != churn {
		t.Fatal("fixture domain is not treated as churn-prone; the test would not exercise the fix")
	}

	_, redisCache := newTestRedis(t)
	db := newTestStore(t)
	task := &OSINTTask{
		store:  db,
		osint:  &fakeEvidence{enabled: false},
		redis:  redisCache,
		config: OSINTConfig{MaxPerCycle: 10, Lookback: 24 * time.Hour, ThreatKey: testThreatKey, TTL: base, ChurnTTL: churn},
	}

	if !task.promote(context.Background(), "campaign-42.ddns.net", 1) {
		t.Fatal("promotion of a churn-prone tenant must succeed")
	}

	got, err := redisCache.ZScore(context.Background(), testThreatKey, "campaign-42.ddns.net")
	if err != nil {
		t.Fatalf("read the promoted member: %v", err)
	}
	remaining := time.Until(time.Unix(int64(got), 0))
	if remaining > churn+time.Hour {
		t.Fatalf("promoted churn tenant expires in %s, want the churn window of %s; "+
			"a full base window here is the regression", remaining.Round(time.Hour), churn)
	}
}

func TestOSINTPromotionKeepsBaseTTLForAnOrdinaryDomain(t *testing.T) {
	const base = 14 * 24 * time.Hour
	churn := 3 * 24 * time.Hour

	_, redisCache := newTestRedis(t)
	db := newTestStore(t)
	task := &OSINTTask{
		store:  db,
		osint:  &fakeEvidence{enabled: false},
		redis:  redisCache,
		config: OSINTConfig{MaxPerCycle: 10, Lookback: 24 * time.Hour, ThreatKey: testThreatKey, TTL: base, ChurnTTL: churn},
	}

	if !task.promote(context.Background(), "ordinary-evil.test", 1) {
		t.Fatal("promotion must succeed")
	}

	got, err := redisCache.ZScore(context.Background(), testThreatKey, "ordinary-evil.test")
	if err != nil {
		t.Fatalf("read the promoted member: %v", err)
	}
	remaining := time.Until(time.Unix(int64(got), 0))
	if remaining < base-time.Hour || remaining > base+time.Hour {
		t.Fatalf("promoted ordinary domain expires in %s, want the base window of %s",
			remaining.Round(time.Hour), base)
	}
}

// A churn window of zero disables the split by contract, so a promoted tenant falls
// back to the base TTL rather than being given an unbounded or zero-length window.
func TestOSINTPromotionFallsBackToBaseTTLWhenChurnIsDisabled(t *testing.T) {
	const base = 14 * 24 * time.Hour

	_, redisCache := newTestRedis(t)
	db := newTestStore(t)
	task := &OSINTTask{
		store:  db,
		osint:  &fakeEvidence{enabled: false},
		redis:  redisCache,
		config: OSINTConfig{MaxPerCycle: 10, Lookback: 24 * time.Hour, ThreatKey: testThreatKey, TTL: base, ChurnTTL: 0},
	}

	if !task.promote(context.Background(), "campaign-42.ddns.net", 1) {
		t.Fatal("promotion must succeed")
	}

	got, err := redisCache.ZScore(context.Background(), testThreatKey, "campaign-42.ddns.net")
	if err != nil {
		t.Fatalf("read the promoted member: %v", err)
	}
	remaining := time.Until(time.Unix(int64(got), 0))
	if remaining < base-time.Hour || remaining > base+time.Hour {
		t.Fatalf("with churn disabled the base window must apply, got %s", remaining.Round(time.Hour))
	}
}
