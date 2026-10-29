package resolver

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestResponseCacheDisabledAtZeroEntries pins the SAFE_ZONE_DNS_CACHE_ENTRIES=0
// contract: the cache is nil, every operation is a safe no-op, and stats
// report disabled rather than a half-built object. Operators disable the
// cache to troubleshoot upstream behaviour, so a nil cache must never panic
// and never change answers.
func TestResponseCacheDisabledAtZeroEntries(t *testing.T) {
	cache := NewResponseCache(0)
	if cache != nil {
		t.Fatal("NewResponseCache(0) must return nil")
	}

	query := cacheTestQuery(1, "example.com")
	response := cacheTestAResponse(query, 60)

	if cache.Cacheable(query) {
		t.Fatal("nil cache must report nothing cacheable")
	}
	if got, ok := cache.Get(query); got != nil || ok {
		t.Fatal("nil cache must never hit")
	}
	if stored, evicted := cache.Put(query, response); stored || evicted {
		t.Fatal("nil cache must not store")
	}
	if cache.GetStale(query) != nil {
		t.Fatal("nil cache has no stale data")
	}
	if cache.ShouldRefresh(query) {
		t.Fatal("nil cache never refreshes")
	}
	if cache.BeginRefresh(query) {
		t.Fatal("nil cache never grants a refresh slot")
	}
	cache.EndRefresh(query) // must not panic
	if stats := cache.Stats(); stats.Enabled {
		t.Fatalf("stats on a nil cache must report disabled, got %+v", stats)
	}
}

// TestResponseCacheZeroTTLNotStored pins the boundary of the negative-cache
// rules: a response whose smallest TTL clamps to zero has no freshness
// lifetime at all and must not enter the cache, otherwise it would be served
// with a zero TTL forever or outlive the SOA minimum it was supposed to
// honour.
func TestResponseCacheZeroTTLNotStored(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := newResponseCache(4, DNSCacheMaxTTLSeconds, func() time.Time { return now })

	query := cacheTestQuery(1, "zero-ttl.example")
	response := cacheTestAResponse(query, 0)
	if stored, evicted := cache.Put(query, response); stored || evicted {
		t.Fatal("a zero-TTL response must not be stored")
	}
	if _, ok := cache.Get(query); ok {
		t.Fatal("zero-TTL entry must not be retrievable")
	}

	// An NXDOMAIN whose SOA minimum is zero is equally uncacheable, even with
	// long TTLs on the SOA record itself.
	negative := new(dns.Msg)
	negative.SetRcode(query, dns.RcodeNameError)
	negative.Ns = append(negative.Ns, &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns1.example.",
		Mbox:    "hostmaster.example.",
		Serial:  1,
		Refresh: 1,
		Retry:   1,
		Expire:  1,
		Minttl:  0,
	})
	if stored, _ := cache.Put(query, negative); stored {
		t.Fatal("an NXDOMAIN with SOA minimum 0 must not be stored")
	}
}

// Benchmarks for the hot path: a hit must stay cheap (copy + TTL aging), a
// miss must not touch the LRU, and full-capacity insertion must evict at a
// bounded cost.
func BenchmarkResponseCacheHit(b *testing.B) {
	now := time.Unix(1_700_000_000, 0)
	cache := newResponseCache(4096, DNSCacheMaxTTLSeconds, func() time.Time { return now })
	query := cacheTestQuery(1, "example.com")
	cache.Put(query, cacheTestAResponse(query, 300))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := cache.Get(query); !ok {
			b.Fatal("expected hit")
		}
	}
}

func BenchmarkResponseCacheMiss(b *testing.B) {
	now := time.Unix(1_700_000_000, 0)
	cache := newResponseCache(4096, DNSCacheMaxTTLSeconds, func() time.Time { return now })
	query := cacheTestQuery(1, "example.com")
	cache.Put(query, cacheTestAResponse(query, 300))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		miss := cacheTestQuery(uint16(i+2), fmt.Sprintf("miss-%d.example", i))
		if _, ok := cache.Get(miss); ok {
			b.Fatal("expected miss")
		}
	}
}

func BenchmarkResponseCachePutEviction(b *testing.B) {
	now := time.Unix(1_700_000_000, 0)
	cache := newResponseCache(4096, DNSCacheMaxTTLSeconds, func() time.Time { return now })
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		query := cacheTestQuery(uint16(i%65535+1), fmt.Sprintf("evict-%d.example", i))
		if stored, _ := cache.Put(query, cacheTestAResponse(query, 300)); !stored {
			b.Fatal("expected store")
		}
	}
}
