package analysis

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

// The normalize fast path must be output-identical to the full path for
// every input: it may only skip work, never change results.
func TestNormalizeBrandRecordFastPathEquivalent(t *testing.T) {
	tokens := []string{
		"", "google", "Google", " GOOGLE ", "google.com", "Google.COM ",
		"a", "A", "momo", "MOMO.VN", "shopee.com", "  x  ", "a-b.c",
		"exämple", "EXÄMPLE", "under_score", "with space", "tab\there",
		"multi  space", "trailing ", " leading", "MiXeD123",
	}
	rng := rand.New(rand.NewSource(42))
	var cases []Brand
	for _, n := range tokens {
		for _, d := range tokens {
			cases = append(cases, Brand{Name: n, OfficialDomain: d})
		}
	}
	// Randomized alt lists with dups, empties, case mixes.
	alts := []string{"", "a.com", "A.COM", " a.com ", "b.com", "B.COM", "a.com", "  ", "c-d.com"}
	for i := 0; i < 300; i++ {
		n := rng.Intn(5)
		list := make([]string, 0, n)
		for j := 0; j < n; j++ {
			list = append(list, alts[rng.Intn(len(alts))])
		}
		cases = append(cases, Brand{
			Name:           tokens[rng.Intn(len(tokens))],
			OfficialDomain: tokens[rng.Intn(len(tokens))],
			AltDomains:     list,
		})
	}

	for i, tc := range cases {
		// Differential: fast path must equal the slow path on every input.
		if got, want := normalizeBrandRecord(tc), normalizeBrandRecordSlow(tc); !reflect.DeepEqual(got, want) {
			t.Fatalf("case %d (%q): fast/slow diverge: %+v vs %+v", i, tc.Name, got, want)
		}
		once := normalizeBrandRecord(tc)
		twice := normalizeBrandRecord(once)
		if !reflect.DeepEqual(once, twice) {
			t.Fatalf("case %d (%q): not idempotent: %+v vs %+v", i, tc.Name, once, twice)
		}
		// Clean outputs (no whitespace anywhere) must satisfy the
		// detector, proving the fast path actually engages. Records
		// with interior spaces intentionally take the slow path.
		hasSpace := false
		for _, s := range append([]string{once.Name, once.OfficialDomain}, once.AltDomains...) {
			if strings.ContainsAny(s, " \t\n\r") {
				hasSpace = true
				break
			}
		}
		if !hasSpace && !isNormalizedBrandRecord(once) {
			t.Fatalf("case %d: clean output must satisfy the detector: %+v", i, once)
		}
		// Domain labels must stay valid hostnames whenever the input was.
		for _, alt := range once.AltDomains {
			if alt == "" || strings.TrimSpace(alt) != alt {
				t.Fatalf("case %d: bad alt %q", i, alt)
			}
		}
	}
}

// Fixed vectors pinning exact outputs (including dedup/drop semantics).
func TestNormalizeBrandRecordVectors(t *testing.T) {
	got := normalizeBrandRecord(Brand{
		Name:           " Google ",
		OfficialDomain: "GOOGLE.COM",
		AltDomains:     []string{"Google.COM ", "google.com", "", "  ", "x.com", "X.COM"},
	})
	want := Brand{
		Name:           "google",
		OfficialDomain: "google.com",
		AltDomains:     []string{"google.com", "x.com"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if !isNormalizedBrandRecord(want) {
		t.Fatal("want-vector must satisfy the detector")
	}
	already := Brand{Name: "momo", OfficialDomain: "momo.vn", AltDomains: []string{"a.vn", "b.vn"}}
	if !isNormalizedBrandRecord(already) {
		t.Fatal("clean record must take the fast path")
	}
	if out := normalizeBrandRecord(already); !reflect.DeepEqual(out, already) {
		t.Fatalf("fast path changed output: %+v", out)
	}
}
