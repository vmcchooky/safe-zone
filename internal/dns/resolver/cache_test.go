package resolver

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestResponseCacheHitRestoresIDAndAgesTTL(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := newResponseCache(4, 300, func() time.Time { return now })
	query := cacheTestQuery(1, "example.com")
	response := cacheTestAResponse(query, 60)

	stored, evicted := cache.Put(query, response)
	if !stored || evicted {
		t.Fatalf("Put() = stored=%v evicted=%v; want true,false", stored, evicted)
	}
	if response.Answer[0].Header().Ttl != 60 {
		t.Fatalf("Put mutated the caller's response TTL: %d", response.Answer[0].Header().Ttl)
	}

	now = now.Add(10 * time.Second)
	replay := cacheTestQuery(2, "ExAmPle.COM")
	got, ok := cache.Get(replay)
	if !ok {
		t.Fatal("expected a cache hit within the record TTL")
	}
	if got.Id != replay.Id {
		t.Fatalf("cached response ID = %d; want caller ID %d", got.Id, replay.Id)
	}
	if got.Question[0].Name != replay.Question[0].Name {
		t.Fatalf("cached question = %q; want caller spelling %q", got.Question[0].Name, replay.Question[0].Name)
	}
	aRecord, ok := got.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("cached answer is %T; want *dns.A", got.Answer[0])
	}
	if aRecord.Hdr.Ttl != 50 {
		t.Fatalf("aged TTL = %d; want 50", aRecord.Hdr.Ttl)
	}
	if aRecord.Hdr.Name != replay.Question[0].Name {
		t.Fatalf("answer owner = %q; want caller spelling %q", aRecord.Hdr.Name, replay.Question[0].Name)
	}

	// The cache must hand out copies: one caller mutating its answer cannot
	// poison the next caller.
	aRecord.A = net.ParseIP("203.0.113.99")
	again, ok := cache.Get(replay)
	if !ok {
		t.Fatal("expected a second cache hit")
	}
	if gotIP := again.Answer[0].(*dns.A).A.String(); gotIP != "192.0.2.1" {
		t.Fatalf("cached answer was mutated by a previous caller: %s", gotIP)
	}
}

func TestResponseCacheExpiresAtMessageTTL(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := newResponseCache(4, 300, func() time.Time { return now })
	query := cacheTestQuery(1, "expires.example")
	if stored, _ := cache.Put(query, cacheTestAResponse(query, 60)); !stored {
		t.Fatal("expected response to be stored")
	}

	now = now.Add(59 * time.Second)
	if _, ok := cache.Get(query); !ok {
		t.Fatal("expected a hit one second before expiry")
	}
	now = now.Add(time.Second)
	if _, ok := cache.Get(query); ok {
		t.Fatal("expected a miss at the record TTL")
	}
}

func TestResponseCacheNegativeAnswerUsesSOAMinimum(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := newResponseCache(4, 300, func() time.Time { return now })
	query := cacheTestQuery(1, "missing.example")
	response := new(dns.Msg)
	response.SetRcode(query, dns.RcodeNameError)
	response.Answer = []dns.RR{&dns.CNAME{
		Hdr:    dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "missing.example.",
	}}
	response.Ns = []dns.RR{&dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:      "ns.example.",
		Mbox:    "hostmaster.example.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  60,
	}}

	if stored, _ := cache.Put(query, response); !stored {
		t.Fatal("expected NXDOMAIN with SOA to be stored")
	}
	now = now.Add(59 * time.Second)
	got, ok := cache.Get(query)
	if !ok {
		t.Fatal("expected a hit inside the SOA MINIMUM")
	}
	soa, ok := got.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatalf("cached authority is %T; want *dns.SOA", got.Ns[0])
	}
	if soa.Hdr.Ttl != 1 {
		t.Fatalf("aged SOA TTL = %d; want 1 so the DoH max-age matches the entry", soa.Hdr.Ttl)
	}
	now = now.Add(2 * time.Second)
	if _, ok := cache.Get(query); ok {
		t.Fatal("expected a miss after the SOA MINIMUM")
	}
}

func TestResponseCacheRejectsUncacheableInput(t *testing.T) {
	cache := newResponseCache(4, 300, time.Now)

	t.Run("query with a client-specific EDNS option", func(t *testing.T) {
		query := cacheTestQuery(1, "example.com")
		query.SetEdns0(1232, false)
		query.IsEdns0().Option = append(query.IsEdns0().Option, &dns.EDNS0_COOKIE{
			Code:   dns.EDNS0COOKIE,
			Cookie: "0011223344556677",
		})
		if cache.Cacheable(query) {
			t.Fatal("query with a cookie must not be cacheable")
		}
		if stored, _ := cache.Put(query, cacheTestAResponse(query, 60)); stored {
			t.Fatal("query with a cookie must not be stored")
		}
	})

	t.Run("query with two questions", func(t *testing.T) {
		query := cacheTestQuery(1, "example.com")
		query.Question = append(query.Question, dns.Question{Name: "other.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
		if cache.Cacheable(query) {
			t.Fatal("multi-question query must not be cacheable")
		}
	})

	t.Run("servfail response", func(t *testing.T) {
		query := cacheTestQuery(1, "servfail.example")
		response := cacheTestAResponse(query, 60)
		response.Rcode = dns.RcodeServerFailure
		if stored, _ := cache.Put(query, response); stored {
			t.Fatal("SERVFAIL must not be cached")
		}
	})

	t.Run("truncated response", func(t *testing.T) {
		query := cacheTestQuery(1, "truncated.example")
		response := cacheTestAResponse(query, 60)
		response.Truncated = true
		if stored, _ := cache.Put(query, response); stored {
			t.Fatal("truncated response must not be cached")
		}
	})

	t.Run("oversized response", func(t *testing.T) {
		query := cacheTestQuery(1, "large.example")
		response := cacheTestAResponse(query, 60)
		response.Answer = append(response.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{strings.Repeat("x", maxDNSCacheMessageSize)},
		})
		if stored, _ := cache.Put(query, response); stored {
			t.Fatal("oversized response must not be cached")
		}
	})

	t.Run("response carrying an EDNS option", func(t *testing.T) {
		query := cacheTestQuery(1, "cookie.example")
		response := cacheTestAResponse(query, 60)
		response.Extra = append(response.Extra, &dns.OPT{
			Hdr:    dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232},
			Option: []dns.EDNS0{&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0011223344556677"}},
		})
		if stored, _ := cache.Put(query, response); stored {
			t.Fatal("response with a cookie must not be cached")
		}
	})
}

func TestResponseCacheEvictsLeastRecentlyUsed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := newResponseCache(2, 300, func() time.Time { return now })
	queryA := cacheTestQuery(1, "a.example")
	queryB := cacheTestQuery(2, "b.example")
	queryC := cacheTestQuery(3, "c.example")

	if stored, _ := cache.Put(queryA, cacheTestAResponse(queryA, 60)); !stored {
		t.Fatal("expected A to be stored")
	}
	if stored, _ := cache.Put(queryB, cacheTestAResponse(queryB, 60)); !stored {
		t.Fatal("expected B to be stored")
	}
	if _, ok := cache.Get(queryA); !ok {
		t.Fatal("expected A to be a hit before eviction")
	}
	if stored, evicted := cache.Put(queryC, cacheTestAResponse(queryC, 60)); !stored || !evicted {
		t.Fatalf("Put(C) = stored=%v evicted=%v; want true,true", stored, evicted)
	}

	if _, ok := cache.Get(queryB); ok {
		t.Fatal("B was least recently used and should have been evicted")
	}
	if _, ok := cache.Get(queryA); !ok {
		t.Fatal("A should survive because it was refreshed")
	}
	if _, ok := cache.Get(queryC); !ok {
		t.Fatal("C should survive")
	}
}

func TestResponseCacheCapsLongTTL(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := newResponseCache(4, 30, func() time.Time { return now })
	query := cacheTestQuery(1, "longttl.example")
	if stored, _ := cache.Put(query, cacheTestAResponse(query, 300)); !stored {
		t.Fatal("expected response to be stored")
	}

	now = now.Add(29 * time.Second)
	got, ok := cache.Get(query)
	if !ok {
		t.Fatal("expected a hit before the cache cap")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl != 1 {
		t.Fatalf("aged TTL = %d; want 1", ttl)
	}
	now = now.Add(2 * time.Second)
	if _, ok := cache.Get(query); ok {
		t.Fatal("expected a miss after the cache cap")
	}
}

func TestResponseCacheStats(t *testing.T) {
	var disabled *ResponseCache
	if stats := disabled.Stats(); stats.Enabled || stats.Entries != 0 {
		t.Fatalf("nil cache stats = %+v; want disabled", stats)
	}

	cache := newResponseCache(4, 300, time.Now)
	query := cacheTestQuery(1, "stats.example")
	if stored, _ := cache.Put(query, cacheTestAResponse(query, 60)); !stored {
		t.Fatal("expected response to be stored")
	}
	stats := cache.Stats()
	if !stats.Enabled || stats.Entries != 1 || stats.MaxEntries != 4 {
		t.Fatalf("cache stats = %+v; want enabled with 1/4 entries", stats)
	}
}

func TestResponseCacheConcurrentAccess(t *testing.T) {
	cache := newResponseCache(64, 300, time.Now)
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				query := cacheTestQuery(uint16(i), "concurrent.example")
				cache.Put(query, cacheTestAResponse(query, 60))
				cache.Get(query)
			}
		}(worker)
	}
	wg.Wait()
}

func cacheTestQuery(id uint16, name string) *dns.Msg {
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(name), dns.TypeA)
	query.Id = id
	return query
}

func cacheTestAResponse(query *dns.Msg, ttl uint32) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(query)
	response.Answer = append(response.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   query.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		A: net.ParseIP("192.0.2.1"),
	})
	return response
}
