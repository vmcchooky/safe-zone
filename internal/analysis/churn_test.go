package analysis

import "testing"

// The churn class must never widen into a blocking decision. Every case here
// asserts classification only; the feed and risk gates own whether a member
// blocks, and an exact IOC on a self-service tenant keeps blocking regardless.
func TestChurnProneRootMatchesTenantLeafOnly(t *testing.T) {
	cases := map[string]struct {
		domain string
		want   string
	}{
		"dynamic dns tenant":         {"campaign-42.duckdns.org", "duckdns.org"},
		"free bulk host tenant":      {"a1b2.000webhostapp.com", "000webhostapp.com"},
		"tunnel tenant":              {"x7.trycloudflare.com", "trycloudflare.com"},
		"ipfs gateway tenant":        {"cid.ipfs.dweb.link", "dweb.link"},
		"nested under churn root":    {"a.b.weebly.com", "weebly.com"},
		"case and trailing dot":      {"CAMPAIGN.duckdns.org.", "duckdns.org"},
		"uppercase mixed":            {"Evil.DuckDNS.org", "duckdns.org"},
		"apex is never a tenant":     {"duckdns.org", ""},
		"blogspot apex":              {"blogspot.com", ""},
		"public suffix is no tenant": {"co.uk", ""},
		// pages.dev and github.io are self-service but sit behind an
		// account signup, so they are scoring/parent-walk roots, not
		// churn roots. They must not inherit the shortened window.
		"self-service but not churn": {"evil.pages.dev", ""},
		"github pages not churn":     {"evil.github.io", ""},
		"dedicated domain":           {"evil.example.com", ""},
		"churn root as label":        {"duckdns.org.example.com", ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := ChurnProneRoot(tc.domain); got != tc.want {
				t.Fatalf("ChurnProneRoot(%q) = %q, want %q", tc.domain, got, tc.want)
			}
			if want := tc.want != ""; IsChurnProneTenant(tc.domain) != want {
				t.Fatalf("IsChurnProneTenant(%q) = %v, want %v", tc.domain, !want, want)
			}
		})
	}
}

// A churn root must never be confused with a subdomain of it: a domain that
// merely has the churn root as its rightmost label is a different registrable
// domain entirely and stays on the base window.
func TestChurnProneRootDoesNotMatchSuffixOfOtherDomain(t *testing.T) {
	if ChurnProneRoot("notweebly.com") != "" {
		t.Fatal("weebly.com must not match as a suffix of notweebly.com")
	}
	if ChurnProneRoot("my.duckdns.org.attacker.example") != "" {
		t.Fatal("a churn root buried mid-domain is not a tenant relationship")
	}
}
