package whois

import (
	"strings"
	"testing"
)

// FuzzParseAndScore feeds arbitrary bytes through the WHOIS response parser.
// WHOIS text comes from third-party servers, so scoring must never panic and
// must stay inside its documented bounds: at most 25 for age plus 5 for
// privacy guard, and a clean zero when no creation date is found (fail open).
func FuzzParseAndScore(f *testing.F) {
	seeds := []string{
		"",
		"No match for domain EXAMPLE.COM.",
		"Domain Name: EXAMPLE.COM\nCreation Date: 2020-01-15T10:00:00Z\nRegistrar: Example Registrar, Inc.\n",
		"created: 15-Jan-2024\nregistrar: WhoisGuard Protected\n",
		"Creation Date: not-a-date\nRegistrar: \x00\xff\n",
		"creation date: 2035-12-31\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		r := ParseAndScoreForTest(raw)
		if r.Score < 0 || r.Score > 30 {
			t.Fatalf("ParseAndScore(%q) score out of bounds: %d", raw, r.Score)
		}
		if !r.Found {
			if r.Score != 0 || r.DomainAgeDays != 0 || len(r.Reasons) != 0 {
				t.Fatalf("ParseAndScore(%q) = %+v: unfound result must be a clean zero", raw, r)
			}
		}
	})
}

// FuzzRegisteredDomain checks the apex extractor: the result must always be
// empty or a dot-joined suffix of the normalized input.
func FuzzRegisteredDomain(f *testing.F) {
	seeds := []string{
		"mail.example.com",
		"vietcombank.com.vn",
		"a",
		"",
		"EXAMPLE.COM.",
		"..",
		"a.b.c.d.e.f.co",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, domain string) {
		out := RegisteredDomainForTest(domain)
		if out == "" {
			return
		}
		want := strings.ToLower(strings.TrimSuffix(domain, "."))
		if !strings.HasSuffix(want, out) {
			t.Fatalf("RegisteredDomain(%q) = %q, not a suffix of %q", domain, out, want)
		}
	})
}
