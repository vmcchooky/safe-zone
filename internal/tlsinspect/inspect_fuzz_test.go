package tlsinspect

import (
	"strings"
	"testing"
)

// FuzzMatchHostname feeds arbitrary pattern/host pairs through the wildcard
// matcher. Certificate names are attacker-controlled, so matching must never
// panic, must stay reflexive, and a positive match must always satisfy the
// documented contract: exact equality, or a "*." pattern whose remainder is
// a same-depth suffix of the host (*.example.com matches mail.example.com
// but not example.com).
func FuzzMatchHostname(f *testing.F) {
	seeds := [][2]string{
		{"*.example.com", "mail.example.com"},
		{"example.com", "example.com"},
		{"*.example.com", "example.com"},
		{"*", "x"},
		{"", ""},
		{"*.com", "a.com"},
		{"\x00*.example.com", "mail.example.com"},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, host string) {
		if !matchHostname(pattern, pattern) {
			t.Fatalf("matchHostname(%q, %q) = false, want reflexive true", pattern, pattern)
		}
		if !matchHostname(pattern, host) {
			return
		}
		if pattern == host {
			return
		}
		if !strings.HasPrefix(pattern, "*.") {
			t.Fatalf("matchHostname(%q, %q) = true without exact equality or wildcard prefix", pattern, host)
		}
		suffix := pattern[1:]
		if !strings.HasSuffix(host, suffix) || strings.Count(host, ".") != strings.Count(suffix, ".") {
			t.Fatalf("matchHostname(%q, %q) = true but %q is not a same-depth suffix", pattern, host, suffix)
		}
	})
}
