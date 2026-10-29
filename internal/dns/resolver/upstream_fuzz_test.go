package resolver

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// FuzzUpstreamResponse feeds arbitrary wire bytes through the untrusted
// upstream reply boundary: Unpack, validateUpstreamResponse and the
// response-cache admission path. An upstream (or a man-in-the-middle) can
// send any bytes at all, so the boundary must never panic and must only
// accept replies that answer exactly the question that was asked.
func FuzzUpstreamResponse(f *testing.F) {
	fixedQuery := new(dns.Msg)
	fixedQuery.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	queryWire, err := fixedQuery.Pack()
	if err != nil {
		f.Fatalf("pack query seed: %v", err)
	}

	reply := func(mutate func(*dns.Msg)) []byte {
		msg := new(dns.Msg)
		msg.SetReply(fixedQuery)
		if mutate != nil {
			mutate(msg)
		}
		wire, err := msg.Pack()
		if err != nil {
			f.Fatalf("pack reply seed: %v", err)
		}
		return wire
	}
	seeds := [][]byte{
		reply(nil),
		reply(func(m *dns.Msg) { m.Id = 0x1234 }), // wrong id
		reply(func(m *dns.Msg) { m.Response = false }),
		reply(func(m *dns.Msg) {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   []byte{192, 0, 2, 1},
			})
		}),
		reply(func(m *dns.Msg) {
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: "evil.example.net.",
			})
		}),
		reply(func(m *dns.Msg) { m.Question[0].Name = "other.example." }),
		reply(func(m *dns.Msg) { m.Question = nil }),
		[]byte("not a dns message"),
		queryWire, // a query is not a response
	}
	for _, wire := range seeds {
		f.Add(wire)
	}

	f.Fuzz(func(t *testing.T, wire []byte) {
		msg := new(dns.Msg)
		if err := msg.Unpack(wire); err != nil {
			return
		}
		if err := validateUpstreamResponse(fixedQuery, msg); err != nil {
			return
		}

		// Whatever validation accepted must actually answer the fixed query.
		if !msg.Response || msg.Id != fixedQuery.Id {
			t.Fatalf("validation accepted a reply that is not a matching response: id=%d response=%v",
				msg.Id, msg.Response)
		}
		if len(msg.Question) != 1 ||
			!strings.EqualFold(msg.Question[0].Name, fixedQuery.Question[0].Name) {
			t.Fatalf("validation accepted a mismatched question %v", msg.Question)
		}

		// Accepted replies flow into the response cache; admission must be
		// bounded and panic-free for arbitrary record shapes.
		cache := newResponseCache(4, DNSCacheMaxTTLSeconds, nil)
		cache.Put(fixedQuery, msg)
		cache.Get(fixedQuery)
		cache.GetStale(fixedQuery)
		if stats := cache.Stats(); stats.Entries > 4 {
			t.Fatalf("cache bound exceeded: %d entries", stats.Entries)
		}
	})
}
