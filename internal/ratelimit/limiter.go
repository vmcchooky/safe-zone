package ratelimit

import (
	"container/list"
	"sync"
	"time"

	"safe-zone/internal/config"
)

// MaxKeysEnv overrides the per-limiter key cap. Lower it on a small VPS;
// raise it only if the client population genuinely exceeds the default.
const MaxKeysEnv = "SAFE_ZONE_RATELIMIT_MAX_KEYS"

// DefaultMaxKeys bounds how many distinct rate-limit keys a Limiter tracks.
// The key is the client IP, so a flood that rotates X-Forwarded-For (or
// simply a large client population) would otherwise grow the map without
// limit: eviction only ran every 5 minutes and only for keys idle for more
// than 10, so a fast rotating-key flood outran it.
const DefaultMaxKeys = 50_000

// evictionRatio is the fraction of the cap a single eviction pass leaves
// behind, so the map is trimmed in batches instead of once per insert.
const evictionRatio = 0.9

// Limiter is a per-key in-memory token bucket rate limiter.
// It is safe for concurrent use and automatically cleans up idle keys.
//
// Keys are tracked in a map for lookup and in two LRU lists for eviction,
// most recently used at the front of each:
//
//   - active:  keys holding at least one token
//   - blocked: keys that would be denied right now
//
// The split exists because a key being rate limited has, by definition, stopped
// making requests and is therefore among the least recently used. One
// strict-LRU list would delete it first and hand the client a full fresh burst,
// which an attacker can arrange by rotating decoy keys until the map is full of
// repeat traffic.
//
// The invariant the split rests on is:
//
//	inBlocked  ⇔  this key would be denied if it asked again right now
//
// It has to be evaluated *after* the token decision. Placing a key before the
// decrement leaves a client that has just spent its last token in active with
// zero tokens: unprotected, and with hits == 1 it is also the cheapest thing
// for the one-shot pass to take.
//
// Both lists are intrusive (container/list) rather than sorted snapshots: a
// snapshot-and-sort approach sorted the whole key space under the write lock,
// measured at 88-215 ms at 50k keys. Popping from the back is O(1) per key.
//
// The cost of that choice is memory: a list.Element is a separate 40-byte
// allocation per key, so a tracked key costs roughly twice what an unlinked one
// would. See SAFE_ZONE_RATELIMIT_MAX_KEYS in .env.example.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	active  *list.List
	blocked *list.List
	// oneShot counts keys currently seen exactly once, so the one-shot eviction
	// pass can be skipped in O(1) when a key space contains no one-shot keys at
	// all. Skipping it matters when the population is all repeat visitors: pass 1
	// would otherwise scan the whole active list, find nothing, and hand the same
	// list straight to pass 2. Measured at 20k keys, a worst-case trim is about
	// 3ms with the counter and 12ms without.
	//
	// The counter is not a defence. An attacker who visits each decoy twice
	// removes those keys from it, which inverts the pass rather than defeating
	// it — see evictLocked.
	oneShot uint32
	rate    float64 // tokens refilled per second
	burst   int     // max tokens (burst capacity)
	maxKeys int     // hard cap on tracked keys; <= 0 means unlimited
	done    chan struct{}
	once    sync.Once
}

type bucket struct {
	key       string
	tokens    float64
	lastCheck time.Time
	hits      int
	elem      *list.Element
	// owner is the list elem currently belongs to, or nil when the bucket is not
	// linked. Storing it makes removal self-describing: inferring the list from
	// a separate flag can disagree with reality, and container/list.Remove is a
	// silent no-op when handed the wrong list — which strands the element in
	// memory permanently.
	owner *list.List
}

// New creates a Limiter that allows ratePerMinute requests on average
// with a maximum burst of burst requests. Pass ratePerMinute <= 0 to
// create a disabled (always-allow) limiter. The key map is bounded by
// DefaultMaxKeys.
func New(ratePerMinute float64, burst int) *Limiter {
	return NewWithMaxKeys(ratePerMinute, burst, DefaultMaxKeys)
}

// NewConfigured is New with the key cap taken from SAFE_ZONE_RATELIMIT_MAX_KEYS,
// so the memory ceiling is tunable like every other rate-limit setting.
func NewConfigured(ratePerMinute float64, burst int) *Limiter {
	return NewWithMaxKeys(ratePerMinute, burst, config.Int(MaxKeysEnv, DefaultMaxKeys))
}

// NewWithMaxKeys is New with an explicit key-cap. Pass maxKeys <= 0 to
// disable the cap (not recommended on internet-facing deployments).
func NewWithMaxKeys(ratePerMinute float64, burst, maxKeys int) *Limiter {
	l := &Limiter{
		buckets: make(map[string]*bucket),
		active:  list.New(),
		blocked: list.New(),
		rate:    ratePerMinute / 60.0, // convert to per-second
		burst:   burst,
		maxKeys: maxKeys,
		done:    make(chan struct{}),
	}
	if ratePerMinute > 0 {
		go l.cleanupLoop()
	}
	return l
}

// Allow reports whether key has tokens available and consumes one if so.
// Returns true (allow) when rate <= 0 (disabled limiter).
func (l *Limiter) Allow(key string) bool {
	if l == nil || l.rate <= 0 {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		if l.maxKeys > 0 && len(l.buckets) >= l.maxKeys {
			l.evictLocked(l.trimCount())
		}
		b = &bucket{key: key, tokens: float64(l.burst), lastCheck: now}
		l.buckets[key] = b
		l.oneShot++ // a fresh key has been seen exactly once
	}
	if b.hits == 1 {
		l.oneShot-- // about to become a repeat visitor
	}
	b.hits++

	// Refill tokens based on elapsed time.
	elapsed := now.Sub(b.lastCheck).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > float64(l.burst) {
		b.tokens = float64(l.burst)
	}
	b.lastCheck = now

	if b.tokens < 1 {
		l.place(b, true)
		return false
	}
	b.tokens--
	// Placed after the decision, so inBlocked tracks whether the *next* request
	// would be denied rather than whether this one was.
	l.place(b, b.tokens < 1)
	return true
}

// trimCount is how many keys one eviction pass removes.
//
// It is always at least one. Deriving it as int(maxKeys * evictionRatio) alone
// yields 0 at maxKeys == 1, which made the excess zero, which skipped eviction
// entirely � so a cap of one behaved as no cap at all.
func (l *Limiter) trimCount() int {
	trim := int(float64(l.maxKeys) * evictionRatio)
	if trim < 1 {
		trim = 1
	}
	if trim > len(l.buckets) {
		trim = len(l.buckets)
	}
	return trim
}

// place files b under the list matching its blocked state, most recent at the
// front. Callers must hold l.mu.
func (l *Limiter) place(b *bucket, blocked bool) {
	target := l.active
	if blocked {
		target = l.blocked
	}
	if b.owner != nil {
		// Removed from the list the element is actually in, never an inferred
		// one: container/list.Remove is a silent no-op for the wrong list, which
		// would strand the element in memory permanently.
		b.owner.Remove(b.elem)
	}
	b.owner = target
	b.elem = target.PushFront(b)
}

// evictLocked removes up to n keys. Callers must hold l.mu.
//
// Three passes, in increasing order of cost to real clients:
//
//  1. From active, one-shot keys (hits == 1). Skipped in O(1) when oneShot is
//     zero, because walking a large space to discover nothing is what made
//     this pass expensive.
//  2. From active, any key, least recently used.
//  3. From blocked, least recently used. Reached only when the cap cannot be
//     met from active, so the cap always holds.
//
// What pass 1 is and is not: it is a cheap first preference, not a defence
// against a rotating-key flood. It is LRU-blind among one-shot keys, so at one
// request per decoy it removes real and fake keys alike. Worse, an attacker who
// visits each decoy twice empties the oneShot counter of its own keys, so pass 1
// then removes *only* real one-shot keys and keeps the decoys — the opposite of
// its intent. Measured at a cap of 5000 with 2500 real keys interleaved with
// 2500 decoys: at one visit per decoy, 250 of 2500 real keys survive; at two
// visits, none do. The attacker pays about 6 ms to fill the key space either
// way.
//
// What actually protects a throttled client is pass 3 being last, not pass 1.
// Real flood resistance would need a signal the client cannot forge, such as
// aggregating by prefix rather than by full address.
func (l *Limiter) evictLocked(n int) {
	if n <= 0 {
		return
	}
	removed := 0
	for _, pass := range []struct {
		from    *list.List
		oneShot bool
	}{
		{from: l.active, oneShot: true},
		{from: l.active},
		{from: l.blocked},
	} {
		if pass.oneShot && l.oneShot == 0 {
			// Nothing to find; see the note on the oneShot field.
			continue
		}
		// The walk is explicit rather than a `for e := from.Back(); ...
		// e = from.Back()` loop with a `continue`. Back() returns the
		// same element when nothing was removed, so skipping an element that
		// way spins forever on it. Capturing the previous element before
		// acting is what makes a skip advance.
		e := pass.from.Back()
		for e != nil && removed < n {
			skip := pass.oneShot && e.Value.(*bucket).hits > 1
			older := e.Prev()
			if !skip {
				// A bucket only ever lives in the list matching inBlocked, so
				// removing an element taken from pass.from is unambiguous.
				l.removeKey(e)
				removed++
			}
			e = older
		}
		if removed >= n {
			return
		}
	}
}

func (l *Limiter) removeKey(e *list.Element) {
	b := e.Value.(*bucket)
	delete(l.buckets, b.key)
	if b.hits == 1 && l.oneShot > 0 {
		l.oneShot--
	}
	if b.owner != nil {
		// Removed from the list the element is actually in. Inferring it from a
		// flag that could disagree strands the element permanently, because
		// container/list.Remove is a silent no-op for the wrong list.
		b.owner.Remove(e)
		b.owner = nil
	}
	b.elem = nil
}

// SecondsUntilNextToken returns how many seconds until the key has
// at least one token available. Returns 0 if already allowed.
func (l *Limiter) SecondsUntilNextToken(key string) float64 {
	if l == nil || l.rate <= 0 {
		return 0
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok || b.tokens >= 1 {
		return 0
	}

	deficit := 1.0 - b.tokens
	return deficit / l.rate
}

// Close stops the background cleanup goroutine. Safe to call multiple times.
func (l *Limiter) Close() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		close(l.done)
	})
}

// cleanupLoop removes idle buckets every 5 minutes to prevent memory leaks.
func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-l.done:
			return
		case <-ticker.C:
			l.cleanup()
		}
	}
}

// cleanup drops buckets idle for longer than the threshold. Each LRU list is
// already ordered by lastCheck, so each is swept from the back and stops at
// the first key still in use. Both lists are swept: a client that was
// throttled and never came back is exactly the kind of idle bucket that should
// not be retained.
func (l *Limiter) cleanup() {
	const idleThreshold = 10 * time.Minute
	cutoff := time.Now().Add(-idleThreshold)

	l.mu.Lock()
	defer l.mu.Unlock()

	for _, source := range []*list.List{l.active, l.blocked} {
		for e := source.Back(); e != nil; e = source.Back() {
			if !e.Value.(*bucket).lastCheck.Before(cutoff) {
				break
			}
			l.removeKey(e)
		}
	}
}

// Len returns the number of tracked keys. Useful for tests and diagnostics.
func (l *Limiter) Len() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
