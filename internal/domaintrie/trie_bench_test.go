package domaintrie

import (
	"fmt"
	"testing"
)

func BenchmarkTrieMatch(b *testing.B) {
	trie := NewTrie()
	// Load 100k synthetic domains
	for i := 0; i < 100_000; i++ {
		trie.Add(fmt.Sprintf("tracker%d.ads.network%d.com", i%1000, i/1000))
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = trie.Match("sub.tracker42.ads.network7.com")
	}
}

func BenchmarkTrieMatchMiss(b *testing.B) {
	trie := NewTrie()
	for i := 0; i < 100_000; i++ {
		trie.Add(fmt.Sprintf("tracker%d.ads.network%d.com", i%1000, i/1000))
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = trie.Match("safe.legit-website.org")
	}
}

func BenchmarkTrieAdd(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		trie := NewTrie()
		for j := 0; j < 1000; j++ {
			trie.Add(fmt.Sprintf("tracker%d.ads.network%d.com", j%100, j/100))
		}
	}
}
