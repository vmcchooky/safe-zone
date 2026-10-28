package resolver

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// DefaultDNSCacheEntries bounds the in-process upstream response cache.
	// A household generates far fewer distinct questions than this; the bound
	// exists so a hostile or broken client cannot grow the cache without limit.
	DefaultDNSCacheEntries = 4096

	// DNSCacheMaxTTLSeconds caps how long one upstream response is reused even
	// when its records carry a longer TTL. Policy is re-evaluated on every
	// query, but DNS data such as a hijacked CNAME target can change; five
	// minutes keeps the network saving without pinning an answer for hours.
	DNSCacheMaxTTLSeconds = 300

	// maxDNSCacheMessageSize bounds one cached message so the entry count also
	// bounds memory. Ordinary answers are far smaller; this only excludes
	// unusually large DNSSEC or ANY replies.
	maxDNSCacheMessageSize = 8192
)

// responseCacheKey identifies one upstream response. It includes every query
// property that can change the answer (name, type, class, DNSSEC/CD/AD flags,
// whether EDNS was present, and the DO bit). Queries carrying client-specific
// EDNS options are not cached at all.
type responseCacheKey struct {
	name   string
	qtype  uint16
	qclass uint16
	do     bool
	cd     bool
	ad     bool
	rd     bool
	edns   bool
}

type responseCacheEntry struct {
	key      responseCacheKey
	message  *dns.Msg
	storedAt time.Time
	ttl      uint32
}

// ResponseCache is a bounded LRU cache for validated upstream DNS responses.
// It only stores answers that the resolver is allowed to serve to any client:
// policy, overrides, whitelist and CNAME uncloaking are still applied to the
// caller on every hit, so a cache hit can never bypass a policy change.
type ResponseCache struct {
	mu         sync.Mutex
	maxEntries int
	maxTTL     uint32
	now        func() time.Time
	entries    map[responseCacheKey]*list.Element
	lru        *list.List
}

// ResponseCacheStats is the operator-facing view of the cache. It reports
// occupancy only; hit and miss counts live in the metrics registry.
type ResponseCacheStats struct {
	Enabled    bool `json:"enabled"`
	Entries    int  `json:"entries"`
	MaxEntries int  `json:"max_entries"`
}

// Stats returns the current cache occupancy. A nil or disabled cache reports
// enabled=false rather than a partially valid object.
func (c *ResponseCache) Stats() ResponseCacheStats {
	if c == nil || c.maxEntries <= 0 {
		return ResponseCacheStats{Enabled: false}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return ResponseCacheStats{
		Enabled:    true,
		Entries:    c.lru.Len(),
		MaxEntries: c.maxEntries,
	}
}

// NewResponseCache returns a cache bounded to maxEntries, or nil when
// maxEntries <= 0. A nil cache is valid and disables caching.
func NewResponseCache(maxEntries int) *ResponseCache {
	return newResponseCache(maxEntries, DNSCacheMaxTTLSeconds, time.Now)
}

func newResponseCache(maxEntries int, maxTTL uint32, now func() time.Time) *ResponseCache {
	if maxEntries <= 0 {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	return &ResponseCache{
		maxEntries: maxEntries,
		maxTTL:     maxTTL,
		now:        now,
		entries:    make(map[responseCacheKey]*list.Element, maxEntries),
		lru:        list.New(),
	}
}

// Cacheable reports whether query can participate in the cache at all. It is
// separated from Get so hit/miss metrics do not count uncacheable traffic as a
// miss.
func (c *ResponseCache) Cacheable(query *dns.Msg) bool {
	_, ok := responseCacheKeyFor(query)
	return c != nil && c.maxEntries > 0 && ok
}

// Get returns a copy of the cached response for query with the caller's ID and
// question spelling restored, and record TTLs reduced by the entry's age.
func (c *ResponseCache) Get(query *dns.Msg) (*dns.Msg, bool) {
	if c == nil || c.maxEntries <= 0 {
		return nil, false
	}
	key, ok := responseCacheKeyFor(query)
	if !ok {
		return nil, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	element, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	entry := element.Value.(*responseCacheEntry)
	now := c.now()
	age := now.Sub(entry.storedAt)
	if age < 0 {
		age = 0
	}
	if age >= time.Duration(entry.ttl)*time.Second {
		c.lru.Remove(element)
		delete(c.entries, key)
		return nil, false
	}
	c.lru.MoveToFront(element)

	response := entry.message.Copy()
	response.Id = query.Id
	cachedName := entry.message.Question[0].Name
	response.Question[0].Name = query.Question[0].Name
	ageSeconds := uint32(age / time.Second)
	for _, section := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, rr := range section {
			// A 0x20 client expects its own spelling in the reply, while the
			// upstream answer was stored with the first caller's spelling.
			if strings.EqualFold(rr.Header().Name, cachedName) {
				rr.Header().Name = query.Question[0].Name
			}
			ageRecordTTL(rr, ageSeconds)
		}
	}
	return response, true
}

// Put stores a copy of response. It returns whether the response was stored
// and whether storing it evicted the least-recently-used entry.
func (c *ResponseCache) Put(query, response *dns.Msg) (stored, evicted bool) {
	if c == nil || c.maxEntries <= 0 || response == nil {
		return false, false
	}
	key, ok := responseCacheKeyFor(query)
	if !ok || !cacheableResponse(response) {
		return false, false
	}

	message := response.Copy()
	ttl := clampResponseTTLs(message, c.maxTTL)
	if ttl == 0 {
		return false, false
	}
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()

	if element, ok := c.entries[key]; ok {
		entry := element.Value.(*responseCacheEntry)
		entry.message = message
		entry.storedAt = now
		entry.ttl = ttl
		c.lru.MoveToFront(element)
		return true, false
	}

	element := c.lru.PushFront(&responseCacheEntry{
		key:      key,
		message:  message,
		storedAt: now,
		ttl:      ttl,
	})
	c.entries[key] = element

	if c.lru.Len() > c.maxEntries {
		oldest := c.lru.Back()
		if oldest != nil {
			c.lru.Remove(oldest)
			delete(c.entries, oldest.Value.(*responseCacheEntry).key)
			return true, true
		}
	}
	return true, false
}

func responseCacheKeyFor(query *dns.Msg) (responseCacheKey, bool) {
	if query == nil || query.Response || query.Truncated ||
		query.Opcode != dns.OpcodeQuery || len(query.Question) != 1 {
		return responseCacheKey{}, false
	}
	if query.IsTsig() != nil {
		return responseCacheKey{}, false
	}

	question := query.Question[0]
	if strings.TrimSpace(question.Name) == "" {
		return responseCacheKey{}, false
	}

	key := responseCacheKey{
		name:   strings.ToLower(dns.Fqdn(question.Name)),
		qtype:  question.Qtype,
		qclass: question.Qclass,
		cd:     query.CheckingDisabled,
		ad:     query.AuthenticatedData,
		rd:     query.RecursionDesired,
	}

	optCount := 0
	for _, rr := range query.Extra {
		opt, ok := rr.(*dns.OPT)
		if !ok {
			return responseCacheKey{}, false
		}
		optCount++
		if optCount > 1 || opt.Version() != 0 {
			return responseCacheKey{}, false
		}
		// Padding is random-length but does not influence the answer. Any
		// other option (cookie, client subnet, NSID, ...) can make the answer
		// client-specific, so that query bypasses the shared cache.
		for _, option := range opt.Option {
			if option.Option() != dns.EDNS0PADDING {
				return responseCacheKey{}, false
			}
		}
		key.do = opt.Do()
	}
	key.edns = optCount == 1
	return key, true
}

func cacheableResponse(response *dns.Msg) bool {
	if response == nil || response.Truncated || response.IsTsig() != nil ||
		len(response.Question) != 1 || response.Len() > maxDNSCacheMessageSize {
		return false
	}
	// SERVFAIL, REFUSED and friends are failure states, not answers. Caching
	// them would keep an outage alive after the upstream recovered.
	if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
		return false
	}
	for _, section := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, rr := range section {
			if opt, ok := rr.(*dns.OPT); ok && len(opt.Option) > 0 {
				// A cookie or EDE belongs to the exchange that produced it.
				return false
			}
		}
	}
	return true
}

// clampResponseTTLs caps every cacheable record at maxTTL and returns the
// lifetime of the whole message: the smallest record TTL, additionally capped
// by the SOA MINIMUM for negative answers (RFC 2308). It returns 0 when the
// response has no cacheable record or must not be cached.
func clampResponseTTLs(message *dns.Msg, maxTTL uint32) uint32 {
	ttl := uint32(0)
	found := false
	for _, section := range [][]dns.RR{message.Answer, message.Ns, message.Extra} {
		for _, rr := range section {
			switch rr.(type) {
			case *dns.OPT, *dns.TSIG:
				continue
			}
			if maxTTL > 0 && rr.Header().Ttl > maxTTL {
				rr.Header().Ttl = maxTTL
			}
			if !found || rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
				found = true
			}
		}
	}
	if !found {
		return 0
	}
	// RFC 2308 applies the SOA MINIMUM to NXDOMAIN as well as NODATA. An
	// NXDOMAIN can carry a CNAME chain in Answer, so checking only for an
	// empty Answer would let the negative entry outlive the SOA minimum.
	if message.Rcode == dns.RcodeNameError || len(message.Answer) == 0 {
		for _, rr := range message.Ns {
			if soa, ok := rr.(*dns.SOA); ok && soa.Minttl < ttl {
				ttl = soa.Minttl
			}
		}
	}

	// One whole-message lifetime is simpler to age and safer for policy than
	// independent RRset TTLs: every record expires with the entry, and the DoH
	// Cache-Control lifetime computed from the reply cannot outlive it.
	for _, section := range [][]dns.RR{message.Answer, message.Ns, message.Extra} {
		for _, rr := range section {
			switch rr.(type) {
			case *dns.OPT, *dns.TSIG:
				continue
			}
			if rr.Header().Ttl > ttl {
				rr.Header().Ttl = ttl
			}
		}
	}
	return ttl
}

func ageRecordTTL(rr dns.RR, age uint32) {
	switch rr.(type) {
	case *dns.OPT, *dns.TSIG:
		// OPT uses the TTL field for extended flags; TSIG requires zero.
		return
	}
	ttl := rr.Header().Ttl
	if age >= ttl {
		ttl = 0
	} else {
		ttl -= age
	}
	rr.Header().Ttl = ttl
}
