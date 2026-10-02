package risk

import (
	"os"
	"path/filepath"
	"testing"

	"safe-zone/internal/analysis"
)

// A whitelist entry that is a public suffix is never something anybody can
// register, so it is never what the operator meant. But IsAllowed walks parent
// suffixes, so an entry of "com" answered true for every .com domain and
// "github.io" answered true for every *.github.io domain. Because the hit is
// reported as a "whitelist" result it short-circuits every later layer: threat
// feed, lexical scoring, ML, AI, OSINT and group enforcement. One bad line in
// a 1M-row import silently disabled protection for that whole namespace.
func TestWhitelistRejectsPublicSuffixEntries(t *testing.T) {
	rejected := []string{
		"com",
		"net",
		"org",
		"io",
		"co.uk",
		"com.vn",
		"co.jp",
		"gov.uk",
		"github.io",
		"appspot.com",
	}
	for _, entry := range rejected {
		t.Run(entry, func(t *testing.T) {
			if isWhitelistEntrySafe(entry) {
				t.Fatalf("%q is a public suffix and must not be accepted as a whitelist entry", entry)
			}
		})
	}
}

func TestWhitelistAcceptsRegistrableDomains(t *testing.T) {
	accepted := []string{
		"example.com",
		"google.com",
		"example.co.uk",
		"tpb.vn",
		"bank.vn",
		"user.github.io", // github.io is a public suffix, but this is registrable
	}
	for _, entry := range accepted {
		t.Run(entry, func(t *testing.T) {
			if !isWhitelistEntrySafe(entry) {
				t.Fatalf("%q is a registrable domain and must be accepted", entry)
			}
		})
	}
}

// The walk must stop at the registrable label. A whitelist already in the
// database from an older build can still contain a public suffix, so the
// lookup itself has to be safe and not rely on ingest validation alone.
func TestIsAllowedNeverMatchesBelowTheRegistrableLabel(t *testing.T) {
	w := NewWhitelist(nil)
	// Simulate a database that already holds the unsafe entries: built through
	// the real index builder so the state is one the runtime could reach.
	bf, exact := buildIndex([]string{
		"com",
		"github.io",
		"co.uk",
		"vn",
		"google.com",
		"example.co.uk",
	})
	w.publish(bf, exact)

	mustNotMatch := []string{
		"evil.com",
		"secure-login-wallet.com",
		"phishing-site.github.io",
		"attacker.github.io",
		"login-bank.co.uk",
		"malware.vn",
		"anything.co.uk",
	}
	for _, domain := range mustNotMatch {
		t.Run(domain, func(t *testing.T) {
			if w.IsAllowed(t.Context(), domain) {
				t.Fatalf("%q must not be allowlisted by a public-suffix entry", domain)
			}
		})
	}

	// A registrable entry still works, including for its subdomains and for a
	// multi-label public suffix.
	if !w.IsAllowed(t.Context(), "google.com") {
		t.Fatal("an exact registrable entry must match")
	}
	if !w.IsAllowed(t.Context(), "mail.google.com") {
		t.Fatal("a registrable entry must match its subdomains")
	}
	if !w.IsAllowed(t.Context(), "login.example.co.uk") {
		t.Fatal("the walk must reach the registrable label of a multi-label suffix")
	}
}

// The walk floor is what implements the above. Pin its arithmetic directly so
// a refactor of the loop cannot silently change the boundary.
func TestRegistrableWalkFloorStopsAtRegistrableLabel(t *testing.T) {
	cases := []struct {
		domain string
		want   int
	}{
		{"login.example.com", 1},   // can check login.example.com, example.com
		{"a.b.c.example.com", 3},   // ...down to example.com
		{"login.example.co.uk", 1}, // suffix is co.uk: floor is example.co.uk
		{"example.com", 0},         // already at the floor
		{"com", 0},                 // not a registrable domain: no walk
		{"", 0},                    // unusable input
		{"localhost", 0},           // single label
		{"user.github.io", 0},      // already the registrable label
		{"a.user.github.io", 1},    // one level above user.github.io
	}
	for _, tc := range cases {
		t.Run(tc.domain, func(t *testing.T) {
			if got := analysis.RegistrableWalkFloor(tc.domain); got != tc.want {
				t.Fatalf("analysis.RegistrableWalkFloor(%q) = %d, want %d", tc.domain, got, tc.want)
			}
		})
	}
}

// The file ingest path is the other half: it must drop the unsafe lines, keep
// the rest, and say so. Failing the whole import would cost the operator every
// other entry in a 1M-row file.
func TestLoadFromFileDropsUnsafeEntriesAndKeepsTheRest(t *testing.T) {
	dir := t.TempDir()
	// LoadFromFile resolves paths inside SAFE_ZONE_FEED_FILE_ROOT, so the
	// import has to be written relative to that root.
	t.Setenv("SAFE_ZONE_FEED_FILE_ROOT", dir)
	path := "whitelist.txt"
	content := "" +
		"# comment\n" +
		"google.com\n" +
		"com\n" + // unsafe: every .com
		"co.uk\n" + // unsafe: every .co.uk
		"tpb.vn\n" +
		"github.io\n" + // unsafe: private public suffix, every *.github.io
		"bank.vn\n" +
		"not a domain!!\n" +
		"login.example.co.uk\n"
	if err := os.WriteFile(filepath.Join(dir, path), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	w := NewWhitelist(nil)
	if err := w.LoadFromFile(path); err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}

	for _, expected := range []string{"google.com", "tpb.vn", "bank.vn", "login.example.co.uk"} {
		if !w.IsAllowed(t.Context(), expected) {
			t.Fatalf("%q should have been imported and match", expected)
		}
	}
	// "example.co.uk" was never an entry, and the walk stops at the
	// registrable label rather than descending, so it must not match either.
	if w.IsAllowed(t.Context(), "example.co.uk") {
		t.Fatal("a parent that was never allowlisted must not match")
	}
	for _, dropped := range []string{"com", "co.uk", "github.io"} {
		if w.ContainsExactIndex(dropped) {
			t.Fatalf("%q is a public suffix and must not be stored", dropped)
		}
	}
	// The one that was genuinely malformed is still dropped.
	if w.IsAllowed(t.Context(), "com") {
		t.Fatal("a stored public suffix would allowlist the whole namespace")
	}
}
