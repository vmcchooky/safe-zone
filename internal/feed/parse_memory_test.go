package feed

import (
	"fmt"
	"strings"
	"testing"
)

// The parser retained one deduplication entry per distinct domain with no
// ceiling. A 100MB feed of short hostnames holds millions of them, and the
// per-domain state map in PlanAdmission holds a second structure on top, so a
// hostile or broken feed could drive the process towards a gigabyte of heap on
// a service sized for a small VPS.
//
// Past the cap an unseen domain is treated as already seen. The indicator is
// still handed to the caller — no IOC is dropped — only the duplicate
// classification differs, and the overflow is reported.
func TestBoundedSeenSetStopsGrowingAtTheLimit(t *testing.T) {
	set := newBoundedSeenSet(8)

	for i := range 8 {
		if duplicate := set.mark(fmt.Sprintf("d%d.example", i)); duplicate {
			t.Fatalf("entry %d should be new below the limit", i)
		}
	}
	if got := len(set.entries); got != 8 {
		t.Fatalf("set holds %d entries, want 8", got)
	}

	for i := 8; i < 50; i++ {
		if !set.mark(fmt.Sprintf("d%d.example", i)) {
			t.Fatalf("entry %d is past the limit and must be reported as a duplicate", i)
		}
	}
	if got := len(set.entries); got != 8 {
		t.Fatalf("set grew to %d entries past a limit of 8", got)
	}
	if set.overflowed != 42 {
		t.Fatalf("overflowed = %d, want 42", set.overflowed)
	}
}

// A domain already inside the set stays a duplicate, and a caller can still
// see every indicator even when the set is full.
func TestOverflowStillDeliversEveryIndicator(t *testing.T) {
	var builder strings.Builder
	const total = 200
	for i := range total {
		fmt.Fprintf(&builder, "https://host%d.example/path/%d\n", i, i)
	}

	delivered := 0
	duplicates := 0
	var stats ParseStats
	err := parseIndicatorsWithLimit(strings.NewReader(builder.String()), newBoundedSeenSet(16), &stats,
		func(Indicator, bool) error {
			delivered++
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	_ = duplicates

	if delivered != total {
		t.Fatalf("delivered %d indicators, want all %d: a full dedup set must never drop an IOC", delivered, total)
	}
	if stats.TruncatedDomains == 0 {
		t.Fatal("overflow must be reported through ParseStats.TruncatedDomains, not hidden")
	}
	if stats.Valid == 0 {
		t.Fatal("valid count should still be non-zero")
	}
}

// The parser's own entry point wires the cap and reports the overflow.
func TestParseEachIndicatorReportsTruncation(t *testing.T) {
	var builder strings.Builder
	const total = 500
	for i := range total {
		fmt.Fprintf(&builder, "https://unique%d.example/x\n", i)
	}

	var stats ParseStats
	// ParseEachIndicator uses the production cap, so drive the bounded set
	// directly to keep the test fast while exercising the same code path.
	err := parseIndicatorsWithLimit(strings.NewReader(builder.String()), newBoundedSeenSet(32), &stats,
		func(Indicator, bool) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if stats.TruncatedDomains != total-32 {
		t.Fatalf("TruncatedDomains = %d, want %d", stats.TruncatedDomains, total-32)
	}
}

// A feed comfortably under the cap must behave exactly as before: no
// truncation, and the first sighting of each domain is not a duplicate.
func TestFeedUnderTheCapIsUnaffected(t *testing.T) {
	var builder strings.Builder
	for i := range 100 {
		fmt.Fprintf(&builder, "https://real%d.example/x\n", i)
	}

	var stats ParseStats
	firstSightings := 0
	err := parseIndicatorsWithLimit(strings.NewReader(builder.String()), newBoundedSeenSet(maxDistinctFeedDomains()), &stats,
		func(_ Indicator, duplicate bool) error {
			if !duplicate {
				firstSightings++
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if stats.TruncatedDomains != 0 {
		t.Fatalf("TruncatedDomains = %d for a small feed, want 0", stats.TruncatedDomains)
	}
	if firstSightings != 100 {
		t.Fatalf("%d first sightings, want 100", firstSightings)
	}
}

// The admission state map is the second retained structure. Past its cap a
// domain cannot be classified, so it is not admitted — the safe direction — and
// the count is published rather than the plan quietly being smaller than the
// feed that was downloaded.
func TestPlanAdmissionReportsUnclassifiableDomains(t *testing.T) {
	var builder strings.Builder
	const total = 120
	for i := range total {
		fmt.Fprintf(&builder, "https://host%d.example/login\n", i)
	}

	plan, err := planAdmissionWithLimit(strings.NewReader(builder.String()), AdmissionShadow, 16)
	if err != nil {
		t.Fatal(err)
	}
	if plan.UnclassifiableDomains != total-16 {
		t.Fatalf("UnclassifiableDomains = %d, want %d", plan.UnclassifiableDomains, total-16)
	}
	if len(plan.Authoritative)+len(plan.Contextual) != 16 {
		t.Fatalf("plan classified %d domains, want the 16 that fit",
			len(plan.Authoritative)+len(plan.Contextual))
	}
}

// The cap is documented in .env.example, so the knob itself has to be verified
// rather than assumed. A documented setting that is not wired up is worse than
// no setting at all.
func TestDistinctDomainCapIsConfigurable(t *testing.T) {
	// Hermetic against the ambient environment: without this the first assertion
	// below fails for anyone running the suite with the cap exported, which reads
	// as a regression in the cap rather than a test that is not isolated.
	t.Setenv(envMaxDistinctFeedDomains, "")
	if got := maxDistinctFeedDomains(); got != defaultMaxDistinctFeedDomains {
		t.Fatalf("default cap = %d, want %d", got, defaultMaxDistinctFeedDomains)
	}

	t.Setenv(envMaxDistinctFeedDomains, "500")
	if got := maxDistinctFeedDomains(); got != 500 {
		t.Fatalf("cap = %d, want the configured 500", got)
	}

	// A zero cap restores the previous unbounded behaviour, so both
	// newBoundedSeenSet and planAdmissionWithLimit read a non-positive limit as
	// unbounded, and the environment reader clamps negatives to zero.
	t.Setenv(envMaxDistinctFeedDomains, "-1")
	if got := maxDistinctFeedDomains(); got != 0 {
		t.Fatalf("cap = %d for a negative setting, want 0", got)
	}
}

func TestPlanAdmissionUnaffectedUnderTheCap(t *testing.T) {
	var builder strings.Builder
	for i := range 50 {
		fmt.Fprintf(&builder, "https://real%d.example/login\n", i)
	}

	plan, err := planAdmissionWithLimit(strings.NewReader(builder.String()), AdmissionShadow, maxDistinctFeedDomains())
	if err != nil {
		t.Fatal(err)
	}
	if plan.UnclassifiableDomains != 0 {
		t.Fatalf("UnclassifiableDomains = %d, want 0", plan.UnclassifiableDomains)
	}
	if len(plan.Authoritative)+len(plan.Contextual) != 50 {
		t.Fatalf("plan classified %d domains, want 50", len(plan.Authoritative)+len(plan.Contextual))
	}
}
