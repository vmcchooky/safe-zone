package feed

import (
	"strconv"
	"strings"
	"testing"
)

// SAFE_ZONE_FEED_MAX_DISTINCT_DOMAINS=0 is documented as "restore the previous
// unbounded behaviour". It did the exact opposite: the dedup set reported every
// unseen domain as already seen and the admission planner marked every domain
// unclassifiable, so the sync exited 0, recorded success, and ingested nothing.
//
// These tests pin the documented meaning rather than the implementation, so a future
// refactor cannot reintroduce the collision between "no room left" and "no limit".
func TestZeroMaxDistinctDomainsMeansUnbounded(t *testing.T) {
	t.Setenv(envMaxDistinctFeedDomains, "0")

	if got := resolvedFeedDomainLimit(); got != unboundedFeedDomains {
		t.Fatalf("resolvedFeedDomainLimit() = %d, want unboundedFeedDomains (%d)", got, unboundedFeedDomains)
	}
}

func TestZeroMaxDistinctDomainsStillIngestsDomains(t *testing.T) {
	t.Setenv(envMaxDistinctFeedDomains, "0")

	var got []string
	err := ParseEach(strings.NewReader("first.test\nsecond.test\nthird.test\n"), func(domain string) error {
		got = append(got, domain)
		return nil
	}, nil)
	if err != nil {
		t.Fatalf("ParseEach: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("ParseEach accepted %d of 3 domains with an unbounded cap, got %v", len(got), got)
	}
}

func TestZeroMaxDistinctDomainsDoesNotMarkEverythingUnclassifiable(t *testing.T) {
	t.Setenv(envMaxDistinctFeedDomains, "0")

	plan, err := PlanAdmission(strings.NewReader("first.test\nsecond.test\n"), AdmissionShadow)
	if err != nil {
		t.Fatalf("PlanAdmission: %v", err)
	}
	if plan.UnclassifiableDomains != 0 {
		t.Fatalf("PlanAdmission marked %d domains unclassifiable under an unbounded cap",
			plan.UnclassifiableDomains)
	}
}

// The cap must still work when it is a real number, or the fix would have traded a
// silent no-op for an unbounded set.
func TestPositiveMaxDistinctDomainsStillBoundsTheSet(t *testing.T) {
	set := newBoundedSeenSet(3)

	for _, d := range []string{"a.test", "b.test", "c.test"} {
		if set.mark(d) {
			t.Fatalf("mark(%q) reported a duplicate below the cap", d)
		}
	}
	if !set.mark("d.test") {
		t.Fatal("mark beyond the cap must report the domain as already seen")
	}
	if set.overflowed == 0 {
		t.Fatal("the overflow must be counted so the operator can see the degradation")
	}
}

// A bounded set still deduplicates; that behaviour is unrelated to the cap.
func TestBoundedSeenSetStillDeduplicates(t *testing.T) {
	set := newBoundedSeenSet(16)
	if set.mark("repeat.test") {
		t.Fatal("first sighting must not be a duplicate")
	}
	if !set.mark("repeat.test") {
		t.Fatal("second sighting must be a duplicate")
	}
}

// An unbounded set deduplicates but never reports a capacity duplicate.
func TestUnboundedSeenSetDeduplicatesWithoutACapacityLimit(t *testing.T) {
	set := newBoundedSeenSet(unboundedFeedDomains)

	for _, d := range []string{"a.test", "b.test", "a.test", "b.test"} {
		_ = d
	}
	if set.mark("a.test") {
		t.Fatal("first sighting must not be a duplicate")
	}
	if set.mark("b.test") {
		t.Fatal("first sighting of a second domain must not be a duplicate")
	}
	if !set.mark("a.test") {
		t.Fatal("second sighting must still be a duplicate")
	}
	// Far more than any configured cap. An unbounded set must never report a
	// capacity duplicate, which is exactly what a resolved 0 used to do.
	for i := 0; i < 5000; i++ {
		domain := strings.Repeat("x", i%11) + strconv.Itoa(i) + ".test"
		if set.mark(domain) {
			t.Fatalf("an unbounded set reported a capacity duplicate for %q", domain)
		}
	}
}
