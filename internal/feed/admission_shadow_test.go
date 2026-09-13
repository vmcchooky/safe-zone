package feed

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Shadow fixture: hosts-format lines, a singleton path-scoped URL host
// (contextual), a corroborated URL host (authoritative) and a shared root
// that must never load.
const shadowParityFixture = `# comment
0.0.0.0 hosts-block.test
0.0.0.0 sub.hosts-block.test
127.0.0.1 localhost
https://only-url.test/login
https://twice.test/first
https://twice.test/second
https://github.io/tenant
plain-domain.test
`

func legacyLoadedSet(t *testing.T, src string) map[string]bool {
	t.Helper()
	set := map[string]bool{}
	var stats ParseStats
	err := ParseEach(strings.NewReader(src), func(domain string) error {
		if admitFeedDomain(domain, nil) {
			set[domain] = true
		}
		return nil
	}, &stats)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func shadowLoadedSet(t *testing.T, src string) map[string]bool {
	t.Helper()
	plan, err := PlanAdmission(strings.NewReader(src), AdmissionShadow)
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, d := range append(append([]string{}, plan.Authoritative...), plan.Contextual...) {
		if admitFeedDomain(d, nil) {
			set[d] = true
		}
	}
	return set
}

// PR-08b/M7: flipping a sync from Legacy to Shadow must not change the
// loaded runtime set — Shadow only adds measurement. Both modes share the
// ParseEachIndicator pipeline, so their post-PSL sets are identical.
func TestLegacyShadowLoadedSetParity(t *testing.T) {
	legacy := legacyLoadedSet(t, shadowParityFixture)
	shadow := shadowLoadedSet(t, shadowParityFixture)
	if len(legacy) == 0 {
		t.Fatal("precondition: legacy fixture must load members")
	}
	if len(legacy) != len(shadow) {
		t.Fatalf("loaded-set parity violated: legacy %d != shadow %d", len(legacy), len(shadow))
	}
	for d := range legacy {
		if !shadow[d] {
			t.Fatalf("legacy member %q missing from shadow set", d)
		}
	}
	if shadow["github.io"] {
		t.Fatal("shared root must never load in either mode")
	}
	if !shadow["only-url.test"] {
		t.Fatal("shadow must still load the contextual singleton (measurement, not filter)")
	}
}

// PR-08b/M7: SummarizeShadowGap counts what Filter would drop without
// touching stats counters or the loaded set.
func TestSummarizeShadowGap(t *testing.T) {
	diff := SummarizeShadowGap([]string{"b.test", "github.io", "a.test"})
	if diff.ContextualLoaded != 2 {
		t.Fatalf("expected 2 contextual loaded, got %+v", diff)
	}
	if diff.ContextualPSLRefused != 1 {
		t.Fatalf("expected 1 PSL refusal, got %+v", diff)
	}
	if !sort.StringsAreSorted(diff.Sample) || len(diff.Sample) != 2 {
		t.Fatalf("expected sorted 2-sample, got %v", diff.Sample)
	}
	many := make([]string, 0, 60)
	for i := 0; i < 60; i++ {
		many = append(many, "host.test")
	}
	if got := SummarizeShadowGap(many); len(got.Sample) != shadowSampleCap {
		t.Fatalf("expected sample capped at %d, got %d", shadowSampleCap, len(got.Sample))
	}
}

// PR-08b/M7: a Shadow dry-run report carries the Filter gap for operators.
func TestSyncShadowReportCarriesDiff(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(path, []byte("https://single.test/login\nhttps://repeated.test/a\nhttps://repeated.test/b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Sync(context.Background(), SyncOptions{
		Source:        path,
		FileRoot:      dir,
		DryRun:        true,
		AdmissionMode: AdmissionShadow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Shadow == nil {
		t.Fatal("expected shadow diff in report")
	}
	if report.Shadow.ContextualLoaded != 1 {
		t.Fatalf("expected 1 contextual gap member, got %+v", report.Shadow)
	}
	if len(report.Shadow.Sample) != 1 || report.Shadow.Sample[0] != "single.test" {
		t.Fatalf("expected [single.test] sample, got %v", report.Shadow.Sample)
	}
}
