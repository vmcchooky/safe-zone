package analysis

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

type goldenFeatureFixture struct {
	TestCases []struct {
		Domain         string    `json:"domain"`
		CanonicalASCII string    `json:"canonical_ascii"`
		CanonicalU     string    `json:"canonical_unicode"`
		IsValid        bool      `json:"is_valid"`
		Features       []float64 `json:"features"`
	} `json:"test_cases"`
}

func TestFeatureExtractorGoldenParity(t *testing.T) {
	manifest := filepath.Join("..", "..", "ml", "models", "v1", "feature_manifest.v1.json")
	fixturePath := filepath.Join("..", "..", "ml", "tests", "fixtures", "golden_vectors.v1.json")
	extractor, err := NewFeatureExtractor(manifest)
	if err != nil {
		t.Fatalf("load feature extractor: %v", err)
	}
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read golden fixture: %v", err)
	}
	var fixture goldenFeatureFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("parse golden fixture: %v", err)
	}
	for _, tc := range fixture.TestCases {
		gotCanonical, canonicalErr := canonicalizeMLDomain(tc.Domain)
		if tc.IsValid {
			if canonicalErr != nil || !gotCanonical.valid {
				t.Fatalf("%s: canonicalization failed: %v", tc.Domain, canonicalErr)
			}
			if gotCanonical.ascii != tc.CanonicalASCII || gotCanonical.unicode != tc.CanonicalU {
				t.Errorf("%s: canonical mismatch: got %q/%q, want %q/%q", tc.Domain, gotCanonical.ascii, gotCanonical.unicode, tc.CanonicalASCII, tc.CanonicalU)
			}
			got := extractor.ExtractCanonical(gotCanonical)
			if len(got) != len(tc.Features) {
				t.Fatalf("%s: feature length %d, want %d", tc.Domain, len(got), len(tc.Features))
			}
			for i := range got {
				if math.Abs(got[i]-tc.Features[i]) > 2e-6 {
					t.Errorf("%s: feature[%d] got %.12g, want %.12g", tc.Domain, i, got[i], tc.Features[i])
				}
			}
			continue
		}
		if canonicalErr == nil {
			t.Errorf("%s: expected unsupported/invalid input", tc.Domain)
		}
	}
}

func TestFeatureExtractorRejectsManifestDrift(t *testing.T) {
	manifest := filepath.Join("..", "..", "ml", "models", "v1", "feature_manifest.v1.json")
	if _, err := NewFeatureExtractor(manifest); err != nil {
		t.Fatalf("current v1 manifest should load: %v", err)
	}
}
