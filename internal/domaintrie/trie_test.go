package domaintrie

import (
	"bytes"
	"testing"
)

func TestDomainTrie(t *testing.T) {
	trie := NewTrie()

	// Test Empty Match
	if trie.Match("example.com") {
		t.Errorf("Empty trie should not match anything")
	}

	// Test Add and Exact Match
	trie.Add("ads.example.com")
	if !trie.Match("ads.example.com") {
		t.Errorf("Expected match for ads.example.com")
	}

	// Test Subdomain Match (Wildcard behavior)
	if !trie.Match("sub.ads.example.com") {
		t.Errorf("Expected match for sub.ads.example.com because parent ads.example.com is blocked")
	}

	// Test Sibling No Match
	if trie.Match("myads.example.com") {
		t.Errorf("Did not expect match for myads.example.com")
	}

	// Test Parent No Match
	if trie.Match("example.com") {
		t.Errorf("Did not expect match for example.com (only child ads.example.com is blocked)")
	}

	// Test Count
	if count := trie.Count(); count != 1 {
		t.Errorf("Expected count 1, got %d", count)
	}

	// Add Root Domain
	trie.Add("evil.com")
	if !trie.Match("evil.com") {
		t.Errorf("Expected match for evil.com")
	}
	if !trie.Match("a.b.c.evil.com") {
		t.Errorf("Expected match for a.b.c.evil.com")
	}

	// Test Clear
	trie.Clear()
	if trie.Match("evil.com") {
		t.Errorf("Did not expect match after clear")
	}
	if count := trie.Count(); count != 0 {
		t.Errorf("Expected count 0 after clear, got %d", count)
	}
}

func TestTrieWriteTo(t *testing.T) {
	trie := NewTrie()

	// Add domains out of order
	trie.Add("z.com")
	trie.Add("a.com")
	trie.Add("b.example.com")
	trie.Add("a.example.com")

	var buf bytes.Buffer
	_, err := trie.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	expected := "a.com\na.example.com\nb.example.com\nz.com\n"
	if buf.String() != expected {
		t.Errorf("WriteTo output mismatch.\nGot:\n%s\nWant:\n%s", buf.String(), expected)
	}
}

func TestTrieTrailingDot(t *testing.T) {
	trie := NewTrie()
	trie.Add("ads.example.com.")
	if !trie.Match("ads.example.com") {
		t.Errorf("Expected match for ads.example.com (added with trailing dot)")
	}
	if !trie.Match("ads.example.com.") {
		t.Errorf("Expected match for ads.example.com. (queried with trailing dot)")
	}
}

func TestTrieDoubleDot(t *testing.T) {
	trie := NewTrie()
	trie.Add("ads..example.com")
	// The empty label should be skipped; effectively "ads.example.com"
	if !trie.Match("ads.example.com") {
		t.Errorf("Expected match for ads.example.com (added via double-dot)")
	}
}

func TestTrieCaseInsensitive(t *testing.T) {
	trie := NewTrie()
	trie.Add("ADS.EXAMPLE.COM")
	if !trie.Match("ads.example.com") {
		t.Errorf("Expected case-insensitive match for ads.example.com")
	}
	if !trie.Match("Ads.Example.Com") {
		t.Errorf("Expected case-insensitive match for Ads.Example.Com")
	}
}

func TestTrieSafetyGuard(t *testing.T) {
	trie := NewTrie()

	// Single-label domains (bare TLDs) must be rejected.
	rejected := []string{"com", "vn", "org", "net", "io"}
	for _, tld := range rejected {
		trie.Add(tld)
		if trie.Count() != 0 {
			t.Errorf("single-label TLD %q should be rejected", tld)
		}
	}

	// Multi-label public suffixes must also be rejected.
	multiLabelSuffixes := []string{"co.uk", "com.vn", "edu.vn", "ac.jp", "com.au", "org.uk"}
	for _, ps := range multiLabelSuffixes {
		before := trie.Count()
		trie.Add(ps)
		if trie.Count() != before {
			t.Errorf("public suffix %q should be rejected, but was added", ps)
		}
	}

	// Multi-label REAL domains must still work.
	trie.Add("evil.com")
	if !trie.Match("evil.com") {
		t.Errorf("Expected match for evil.com (registrable domain)")
	}
	trie.Add("ads.example.co.uk")
	if !trie.Match("ads.example.co.uk") {
		t.Errorf("Expected match for ads.example.co.uk")
	}
}

func TestTrieIDN(t *testing.T) {
	trie := NewTrie()

	// Add Punycode form, match Unicode form
	trie.Add("xn--e1afmapc.xn--p1ai") // пример.рф in punycode
	if !trie.Match("xn--e1afmapc.xn--p1ai") {
		t.Errorf("Expected match for punycode domain")
	}

	trie2 := NewTrie()
	// Add a Unicode domain, match with Punycode
	trie2.Add("münchen.de")
	if !trie2.Match("xn--mnchen-3ya.de") {
		t.Errorf("Expected match: added Unicode 'münchen.de', queried Punycode 'xn--mnchen-3ya.de'")
	}
	if !trie2.Match("münchen.de") {
		t.Errorf("Expected match: added and queried Unicode 'münchen.de'")
	}
}

func TestTrieEmptyDomain(t *testing.T) {
	trie := NewTrie()
	trie.Add("")
	trie.Add("   ")
	if trie.Count() != 0 {
		t.Errorf("Expected count 0 for empty/whitespace domains, got %d", trie.Count())
	}
	if trie.Match("") {
		t.Errorf("Match on empty string should return false")
	}
}

func TestTrieDuplicateAdd(t *testing.T) {
	trie := NewTrie()
	trie.Add("ads.example.com")
	trie.Add("ads.example.com")
	trie.Add("ads.example.com")
	if count := trie.Count(); count != 1 {
		t.Errorf("Expected count 1 after duplicate adds, got %d", count)
	}
}
