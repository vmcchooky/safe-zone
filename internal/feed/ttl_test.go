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

func TestChurnTTLFromDaysContract(t *testing.T) {
	// Disabled: zero and negative both mean "no split", never an error, so an
	// operator can turn the feature off without an invalid-config crash.
	for _, days := range []int{0, -1, -14} {
		got, err := ChurnTTLFromDays(days)
		if err != nil {
			t.Fatalf("ChurnTTLFromDays(%d) must disable rather than fail: %v", days, err)
		}
		if got != 0 {
			t.Fatalf("ChurnTTLFromDays(%d) = %s, want 0", days, got)
		}
	}
	// Too short is refused, not clamped: silently raising a 1-day request to
	// the 2-day floor would hide a misconfiguration that under-blocks.
	for _, days := range []int{1, MinChurnTTLDays - 1} {
		if _, err := ChurnTTLFromDays(days); err == nil {
			t.Fatalf("ChurnTTLFromDays(%d) must be refused as below the %d-day floor", days, MinChurnTTLDays)
		}
	}
	got, err := ChurnTTLFromDays(MinChurnTTLDays)
	if err != nil {
		t.Fatalf("ChurnTTLFromDays(%d) must be accepted: %v", MinChurnTTLDays, err)
	}
	if want := MinChurnTTLDays * 24 * time.Hour; got != want {
		t.Fatalf("ChurnTTLFromDays(%d) = %s, want %s", MinChurnTTLDays, got, want)
	}
}

// The production configuration is sync=24h, churn=3d. This test pins that
// combination as valid so a future tightening of the floor cannot quietly
// break the deployed setting.
func TestChurnTTLProductionCombinationIsValid(t *testing.T) {
	churn, err := ChurnTTLFromDays(3)
	if err != nil {
		t.Fatalf("3-day churn TTL must be valid: %v", err)
	}
	if err := CheckChurnTTLAgainstInterval(churn, 24*time.Hour); err != nil {
		t.Fatalf("3-day churn TTL must clear the 24h production interval: %v", err)
	}
}

func TestCheckChurnTTLAgainstInterval(t *testing.T) {
	day := 24 * time.Hour
	if err := CheckChurnTTLAgainstInterval(0, 24*time.Hour); err != nil {
		t.Fatalf("a disabled churn TTL must never trip the interval guard: %v", err)
	}
	if err := CheckChurnTTLAgainstInterval(-time.Hour, 24*time.Hour); err != nil {
		t.Fatalf("a negative churn TTL must never trip the interval guard: %v", err)
	}
	// Equal is refused too: a member could expire exactly at the next cycle
	// boundary, leaving a coverage hole the instant the sync starts.
	if err := CheckChurnTTLAgainstInterval(24*time.Hour, 24*time.Hour); err == nil {
		t.Fatal("a churn TTL equal to the interval must be refused")
	}
	if err := CheckChurnTTLAgainstInterval(23*time.Hour, 24*time.Hour); err == nil {
		t.Fatal("a churn TTL below the interval must be refused")
	}
	if err := CheckChurnTTLAgainstInterval(2*day, 24*time.Hour); err != nil {
		t.Fatalf("a churn TTL above the interval must be accepted: %v", err)
	}
	if err := CheckChurnTTLAgainstInterval(2*day, 0); err == nil {
		t.Fatal("a non-positive interval must be refused so the guard cannot be bypassed")
	}
}

func TestMemberTTLShortensOnlyChurnTenants(t *testing.T) {
	base := 14 * 24 * time.Hour
	churn := 3 * 24 * time.Hour

	cases := map[string]time.Duration{
		// Recycled-label tenants get the short window.
		"campaign-42.duckdns.org": churn,
		"x7.trycloudflare.com":    churn,
		"cid.ipfs.dweb.link":      churn,
		"blog.weebly.com":         churn,
		// Everything else keeps the full window, including self-service
		// hosting roots that are scoring concerns, not churn concerns.
		"evil.pages.dev":      base,
		"evil.github.io":      base,
		"evil.example.com":    base,
		"microsoft.com":       base,
		"nganhang.vn":         base,
		"docs.google.com":     base,
		"attacker.web.app":    base,
		"1.2.3.4":             base,
		"cdn.jsdelivr.net":    base,
		"a.b.c.evil.co.uk":    base,
		"notweebly.com":       base,
		"sub.pages.dev":       base,
		"very.deep.pages.dev": base,
	}
	for domain, want := range cases {
		if got := MemberTTL(domain, base, churn); got != want {
			t.Fatalf("MemberTTL(%q) = %s, want %s", domain, got, want)
		}
	}
}

// A disabled or oversized churn window must degrade to the base TTL everywhere,
// so no configuration can make a member outlive the operator's intent.
func TestMemberTTLDegradesToBase(t *testing.T) {
	base := 14 * 24 * time.Hour
	for _, churn := range []time.Duration{0, -time.Hour, base, base * 3} {
		if got := MemberTTL("campaign-42.duckdns.org", base, churn); got != base {
			t.Fatalf("churn=%s must degrade to the base window, got %s", churn, got)
		}
	}
	// A non-positive base falls back to the package default rather than
	// scoring a member with a past expiry, which would drop it immediately.
	if got := MemberTTL("evil.example.com", 0, 3*24*time.Hour); got != DefaultSyncTTL {
		t.Fatalf("zero base TTL must fall back to DefaultSyncTTL, got %s", got)
	}
	// The fallback is a base, not a bypass: a churn tenant still gets the
	// shortened window on top of the default base.
	if got := MemberTTL("campaign-42.duckdns.org", 0, 3*24*time.Hour); got != 3*24*time.Hour {
		t.Fatalf("zero base TTL must still apply the churn window, got %s", got)
	}
}
