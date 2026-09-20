package analysis

import (
	"testing"

	"safe-zone/internal/config"
)

// Detection extras extend lexical spoof checking without entering the
// ML-frozen default seed or the DB seed.
func TestDetectionBrandsExtendDefaults(t *testing.T) {
	base := DefaultTrustedBrands()
	extended := DetectionBrands(base)
	if len(extended) != len(base)+2 {
		t.Fatalf("extended brands = %d; want %d", len(extended), len(base)+2)
	}
	names := map[string]string{}
	for _, b := range extended {
		names[b.Name] = b.OfficialDomain
	}
	if names["allegro"] != "allegro.pl" || names["spotify"] != "spotify.com" {
		t.Fatalf("missing detection extras: %v", names)
	}
	// Operator-managed names win: no duplicates.
	withExisting := append(append([]Brand(nil), base...),
		Brand{Name: "Allegro", OfficialDomain: "custom.example"})
	merged := DetectionBrands(withExisting)
	count := 0
	for _, b := range merged {
		if b.Name == "allegro" {
			count++
			if b.OfficialDomain != "custom.example" {
				t.Fatalf("operator brand must win, got %+v", b)
			}
		}
	}
	if count != 1 {
		t.Fatalf("allegro appears %d times; want 1", count)
	}
}

func TestDetectionBrandsDriveLexicalVerdicts(t *testing.T) {
	a := NewAnalyzerWithBrandStore(config.DefaultAnalysisConfig(), NewMemoryBrandStore(DefaultTrustedBrands()))
	// Campaign/impersonation shapes move from SAFE into SUSPICIOUS routing
	// (ML/enrichment eligible) without reaching MALICIOUS on lexical alone.
	for domain, want := range map[string]int{
		"ahshyallegrolokalnie.pl-835347547.click":          55,
		"allegro.pl-oferta64457.click":                     55,
		"allegrolokalnie.pl-oferta019262910002726170.shop": 65,
		"pl.spotify-original.com":                          50,
	} {
		r := a.Analyze(domain)
		if r.Verdict != VerdictSuspicious || r.Score != want {
			t.Errorf("Analyze(%q) = %s %d; want SUSPICIOUS %d (%q)", domain, r.Verdict, r.Score, want, r.Reasons)
		}
	}
}
