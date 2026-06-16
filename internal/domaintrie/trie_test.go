package domaintrie

import (
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
