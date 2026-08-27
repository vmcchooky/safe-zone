package doh

import "github.com/miekg/dns"

// CacheFreshnessLifetime computes the explicit HTTP freshness lifetime of a
// DNS response as mandated by RFC 8484 section 5.1:
//
//   - the lifetime MUST be less than or equal to the smallest TTL in the
//     Answer section (equality RECOMMENDED);
//   - when the Answer section is empty and the Authority section carries an
//     SOA record, the lifetime MUST NOT exceed the SOA MINIMUM field, capped
//     by the SOA record's own TTL as specified by RFC 2308 negative caching;
//   - any other empty-answer response (e.g. SERVFAIL, REFUSED) gets a
//     freshness lifetime of zero so HTTP caches cannot apply heuristics to
//     failure states.
//
// The lifetime is safe for per-client customized responses because the DoH
// endpoint always emits "Cache-Control: private" alongside this max-age.
func CacheFreshnessLifetime(response *dns.Msg) uint32 {
	if response == nil {
		return 0
	}

	freshness := uint32(0)
	for i := range response.Answer {
		ttl := response.Answer[i].Header().Ttl
		if i == 0 || ttl < freshness {
			freshness = ttl
		}
	}
	if len(response.Answer) > 0 {
		return freshness
	}

	for _, authority := range response.Ns {
		if soa, ok := authority.(*dns.SOA); ok {
			return minUint32(soa.Hdr.Ttl, soa.Minttl)
		}
	}
	return 0
}

func minUint32(a, b uint32) uint32 {
	if b < a {
		return b
	}
	return a
}
