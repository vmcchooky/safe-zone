package resolver

import (
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func fuzzQuery(t *testing.T, wire []byte) *dns.Msg {
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		t.Skip()
	}
	return msg
}

// FuzzResponseCache drives every ResponseCache operation with arbitrary
// query/response wire messages, extreme TTLs and a tiny entry bound. The
// cache is on the resolver hot path and its inputs come from untrusted
// clients and untrusted upstreams, so the fuzz contract is: never panic,
// never deadlock, and never hold more entries than the configured bound.
func FuzzResponseCache(f *testing.F) {
	mustPack := func(msg *dns.Msg) []byte {
		wire, err := msg.Pack()
		if err != nil {
			f.Fatalf("pack seed: %v", err)
		}
		return wire
	}
	query := func(name string) *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(name), dns.TypeA)
		return q
	}
	answer := func(name string, ttl uint32) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetReply(query(name))
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   []byte{192, 0, 2, 1},
		})
		return resp
	}
	negative := func(name string, minttl uint32) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetRcode(query(name), dns.RcodeNameError)
		resp.Ns = append(resp.Ns, &dns.SOA{
			Hdr:     dns.RR_Header{Name: "com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns:      "ns1.com.",
			Mbox:    "hostmaster.com.",
			Minttl:  minttl,
			Serial:  1,
			Refresh: 1,
			Retry:   1,
			Expire:  1,
		})
		return resp
	}

	seeds := []struct {
		q, r []byte
	}{
		{mustPack(query("example.com")), mustPack(answer("example.com", 300))},
		{mustPack(query("example.com")), mustPack(answer("example.com", 0xFFFFFFFF))},
		{mustPack(query("ttl0.example")), mustPack(answer("ttl0.example", 0))},
		{mustPack(query("nxd.example")), mustPack(negative("nxd.example", 0xFFFFFFFF))},
		{mustPack(query("nxd.example")), mustPack(negative("nxd.example", 1))},
		// Response with the wrong question: never cacheable.
		{mustPack(query("a.example")), mustPack(answer("b.example", 300))},
		// Two questions: never cacheable.
		{mustPack(func() *dns.Msg {
			q := query("multi.example")
			q.Question = append(q.Question, dns.Question{Name: "second.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
			return q
		}()), mustPack(answer("multi.example", 300))},
		{[]byte("not a dns message"), mustPack(answer("example.com", 300))},
		{mustPack(query("example.com")), []byte("not a dns message")},
	}
	for _, s := range seeds {
		f.Add(s.q, s.r, []byte{0, 1, 2, 3, 4, 5, 6, 7})
	}

	f.Fuzz(func(t *testing.T, queryWire, responseWire, ops []byte) {
		q := fuzzQuery(t, queryWire)
		r := fuzzQuery(t, responseWire)

		cache := newResponseCache(4, DNSCacheMaxTTLSeconds, time.Now)
		// One op per byte; the same operation set runs on every message pair
		// so a seed corpus entry replays deterministically under `go test`.
		for _, op := range ops {
			switch op % 8 {
			case 0:
				cache.Put(q, r)
			case 1:
				cache.Get(q)
			case 2:
				cache.GetStale(q)
			case 3:
				cache.ShouldRefresh(q)
			case 4:
				cache.BeginRefresh(q)
			case 5:
				cache.EndRefresh(q)
			case 6:
				cache.Cacheable(q)
			case 7:
				cache.Stats()
			}
		}
		if stats := cache.Stats(); stats.Entries > 4 {
			t.Fatalf("cache holds %d entries, bound is 4", stats.Entries)
		}

		// A bounded concurrent round exercises the mutex under the -race seed
		// run without introducing goroutine-ordered assertions.
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cache.Put(q, r)
				cache.Get(q)
				cache.GetStale(q)
				cache.Stats()
			}()
		}
		wg.Wait()
		if stats := cache.Stats(); stats.Entries > 4 {
			t.Fatalf("cache holds %d entries after concurrency, bound is 4", stats.Entries)
		}
	})
}
