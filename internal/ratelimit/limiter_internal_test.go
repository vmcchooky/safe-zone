package ratelimit

import (
	"container/list"
	"fmt"
	"testing"
	"time"
)

// These tests live in-package because the two-list split and the idle sweep are
// internal invariants: a key must be in exactly one list, and both lists must
// be swept. Neither is observable from the external test package, and a shim
// exported from production code purely for tests would be worse.

func (l *Limiter) listMembership(key string) (inActive, inBlocked, tracked bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		return false, false, false
	}
	for e := l.active.Front(); e != nil; e = e.Next() {
		if e.Value.(*bucket) == b {
			inActive = true
		}
	}
	for e := l.blocked.Front(); e != nil; e = e.Next() {
		if e.Value.(*bucket) == b {
			inBlocked = true
		}
	}
	return inActive, inBlocked, true
}

// The residual a single-LRU list could not fix: when every tracked key is a
// repeat visitor, the one-shot pass has nothing to drain and the strict
// least-recently-used fallback reaches the throttled client. The two-list split
// keeps throttled clients aside, spent only when the cap cannot otherwise be
// met.
//
// Measured before the split: with 50k keys all at hits>=2, a silent throttled
// client received a fresh burst after ~100k decoy requests.
func TestThrottledClientSurvivesWhenEveryKeyIsARpeatVisitor(t *testing.T) {
	const maxKeys = 20_000
	l := NewWithMaxKeys(8, 3, maxKeys) // authLimiter defaults
	defer l.Close()

	for i := range maxKeys {
		key := fmt.Sprintf("d%d", i)
		l.Allow(key)
		l.Allow(key)
	}
	if l.Len() != maxKeys {
		t.Fatalf("populated %d keys, want %d", l.Len(), maxKeys)
	}

	// The victim burns its burst, then goes silent, as a human walking away
	// from a login form would.
	for range 4 {
		l.Allow("quiet-client")
	}
	if l.Allow("quiet-client") {
		t.Fatal("precondition: the victim should be throttled")
	}

	// More repeat-visitor traffic arrives, twice over the cap.
	for i := range maxKeys * 4 {
		key := fmt.Sprintf("t%d", i)
		l.Allow(key)
		l.Allow(key)
	}

	if l.Allow("quiet-client") {
		t.Fatal("the throttled client was evicted and handed a fresh burst: its bucket must outlive unrelated traffic")
	}
}

// The cap still has to hold. A throttled client is the last thing to spend, so
// a key space made entirely of throttled clients must still be trimmed —
// otherwise the two-list split would have turned the memory ceiling into a
// suggestion.
func TestCapIsEnforcedEvenWhenEveryKeyIsThrottled(t *testing.T) {
	const maxKeys = 500
	l := NewWithMaxKeys(60, 1, maxKeys)
	defer l.Close()

	for i := range maxKeys * 4 {
		key := fmt.Sprintf("key-%d", i)
		l.Allow(key)
		l.Allow(key)
	}

	if got := l.Len(); got > maxKeys {
		t.Fatalf("tracked %d keys, want <= %d: the cap must hold even with no active keys to spend", got, maxKeys)
	}
}

// Both lists must be swept by the idle cleanup, or a client that was throttled
// and never returned would be retained forever.
func TestCleanupSweepsBlockedKeysToo(t *testing.T) {
	l := NewWithMaxKeys(60, 1, 1000)
	defer l.Close()

	l.Allow("stale-blocked")
	l.Allow("stale-blocked") // now throttled and in the blocked list
	l.Allow("idle-active")

	l.mu.Lock()
	l.buckets["stale-blocked"].lastCheck = time.Now().Add(-30 * time.Minute)
	l.buckets["idle-active"].lastCheck = time.Now().Add(-30 * time.Minute)
	l.mu.Unlock()

	l.cleanup()

	if _, _, tracked := l.listMembership("stale-blocked"); tracked {
		t.Fatal("a throttled key idle for 30 minutes survived cleanup")
	}
	if _, _, tracked := l.listMembership("idle-active"); tracked {
		t.Fatal("an active key idle for 30 minutes survived cleanup")
	}
}

// A key that crosses the blocked/active threshold must land in exactly one
// list, or the map and the lists disagree and the key leaks an element or
// becomes reachable twice.
//
// This used to assert that a refilled key sits in active. That pinned the
// placement window instead: placing before the decrement left a key that had
// just spent its last token in active with zero tokens, which is both
// unprotected and the cheapest thing for the one-shot pass to take. The
// invariant below is the one the two-list design actually rests on.
func TestKeyCrossesBetweenListsExactlyOnce(t *testing.T) {
	l := NewWithMaxKeys(600, 2, 1000) // 2 tokens, 10 per second
	defer l.Close()

	if !l.Allow("crossing") {
		t.Fatal("first request should be allowed")
	}
	inActive, inBlocked, tracked := l.listMembership("crossing")
	if !tracked {
		t.Fatal("the key vanished from the map")
	}
	if inActive && inBlocked {
		t.Fatal("the key is in both lists: it would be removable twice and leak an element")
	}
	if !inActive {
		t.Fatalf("a key that spent one of two tokens still has one, so it must be active; blocked=%v", inBlocked)
	}

	// Drain it: now the next request would be denied, so it must be blocked.
	if !l.Allow("crossing") {
		t.Fatal("second request should be allowed, one token remained")
	}
	if _, _, tracked := l.listMembership("crossing"); !tracked {
		t.Fatal("the key vanished from the map")
	}
	if l.Allow("crossing") {
		t.Fatal("third immediate request should be denied")
	}
	inActive, inBlocked, _ = l.listMembership("crossing")
	if inActive && inBlocked {
		t.Fatal("the key is in both lists after being denied")
	}
	if !inBlocked {
		t.Fatal("a key that was just denied must sit in blocked, or eviction spends it first")
	}

	// The invariant that matters, asserted over a sequence that crosses the
	// threshold repeatedly: inBlocked must agree with whether the next request
	// would be denied.
	for range 12 {
		before := l.tokensOf("crossing")
		denied := !l.Allow("crossing")
		_, inBlocked, tracked := l.listMembership("crossing")
		if !tracked {
			t.Fatal("the key vanished from the map")
		}
		// tokens is what the next request will draw from.
		willDeny := l.tokensOf("crossing") < 1
		if inBlocked != willDeny {
			t.Fatalf("invariant broken: blocked=%v but next request would be denied=%v (denied this call=%v, tokens before=%.2f)",
				inBlocked, willDeny, denied, before)
		}
		time.Sleep(120 * time.Millisecond)
	}
}

// The protection needs a burst of at least two, and that is a property of the
// configuration rather than of the code.
//
// With burst == 1 a successful call leaves zero tokens, so by the invariant
// above the key is blocked the instant it succeeds. Every tracked key then sits
// in blocked, the two cheap passes have nothing to take, and eviction falls
// through to strict least-recently-used on blocked — which is the behaviour the
// split exists to avoid.
//
// No configured limiter uses a burst of one (the floor across core-api and
// dns-resolver is 3), so this is pinned rather than defended against. The
// assertion is written so that a regression — the victim surviving — fails
// rather than being skipped, which is what makes this a guard and not a note.
func TestBurstOfOneDefeatsTheBlockedProtection(t *testing.T) {
	const maxKeys = 2_000
	l := NewWithMaxKeys(8, 1, maxKeys)
	defer l.Close()

	for i := range maxKeys {
		key := fmt.Sprintf("d%d", i)
		l.Allow(key)
		l.Allow(key)
	}
	victim := "victim"
	l.Allow(victim)

	// Precondition, not a skip: with burst 1 the victim has no token left, so
	// it must be filed as blocked. If that ever stops being true, the
	// scenario below no longer describes this limit.
	if _, inBlocked, _ := l.listMembership(victim); !inBlocked {
		t.Fatal("precondition: a key that spent its only token must be filed as blocked")
	}

	for i := range 6_000 {
		key := fmt.Sprintf("t%d", i)
		l.Allow(key)
		l.Allow(key)
	}

	// The limit: the victim is evicted. If a future change makes the two-list
	// split protect this case too, that is an improvement, not a failure, so
	// the assertion states what is true today rather than hard-coding the
	// eviction.
	if _, _, tracked := l.listMembership(victim); !tracked {
		t.Log("confirmed: burst=1 leaves the whole key space blocked, so eviction has no cheap fodder")
		return
	}
	t.Fatal("burst=1 no longer defeats the blocked-list protection; the note in .env.example and the limiter comment must be updated")
}

func (l *Limiter) tokensOf(key string) float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		return -1
	}
	return b.tokens
}

// The map and the two lists must agree exactly: a key in a list but not the
// map would be removable without freeing its bucket, and one in the map but in
// no list would be unfindable for cleanup. The per-bucket owner pointer is
// checked too, because container/list.Remove is a silent no-op against the
// wrong list — which strands the element in memory with nothing to report it.
func TestMapAndListsStayConsistent(t *testing.T) {
	l := NewWithMaxKeys(60, 1, 200)
	defer l.Close()

	for i := range 400 {
		key := fmt.Sprintf("k%d", i)
		l.Allow(key)
		l.Allow(key)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	seen := make(map[string]int, len(l.buckets))
	for _, source := range []*list.List{l.active, l.blocked} {
		for e := source.Front(); e != nil; e = e.Next() {
			b := e.Value.(*bucket)
			if seen[b.key] != 0 {
				t.Fatalf("key %q appears in more than one list", b.key)
			}
			seen[b.key]++

			if b.owner != source {
				t.Fatalf("key %q: owner points at %p but the element is in %p", b.key, b.owner, source)
			}
			if b.elem != e {
				t.Fatalf("key %q: bucket.elem is not the element holding it", b.key)
			}
			if _, ok := l.buckets[b.key]; !ok {
				t.Fatalf("key %q is in a list but not in the map", b.key)
			}
		}
	}
	if len(seen) != len(l.buckets) {
		t.Fatalf("%d keys in lists but %d in the map", len(seen), len(l.buckets))
	}

	oneShot := 0
	for key, b := range l.buckets {
		if seen[key] != 1 {
			t.Fatalf("key %q is in the map but in %d lists", key, seen[key])
		}
		if b.owner == nil {
			t.Fatalf("key %q is tracked but has no owning list", key)
		}
		if b.hits == 1 {
			oneShot++
		}
	}
	if int(l.oneShot) != oneShot {
		t.Fatalf("oneShot counter = %d but %d tracked keys have hits == 1; pass 1 would skip wrongly", l.oneShot, oneShot)
	}
}
