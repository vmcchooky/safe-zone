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

func TestTFIDFInputWithoutPublicSuffix(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{domain: "example.com", want: "example"},
		{domain: "login.example.gov.vn", want: "login.example"},
		{domain: "a.b.example.co.uk", want: "a.b.example"},
		{domain: "ec2-54-208-233-16.compute-1.amazonaws.com", want: ""},
	}
	for _, tc := range tests {
		canonical, err := canonicalizeMLDomain(tc.domain)
		if err != nil {
			t.Fatalf("canonicalize %s: %v", tc.domain, err)
		}
		if got := tfidfInput(canonical, tfidfInputWithoutSuffix); got != tc.want {
			t.Errorf("tfidf input for %s got %q, want %q", tc.domain, got, tc.want)
		}
	}
}

func TestFeatureExtractorV2SuffixInvariantTFIDF(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "ml", "models", "v1", "feature_manifest.v1.json")
	extractor, err := NewFeatureExtractor(manifestPath)
	if err != nil {
		t.Fatalf("load v1 feature extractor: %v", err)
	}
	extractor.manifest.ContractVersion = featureManifestVersionV2
	extractor.manifest.TFIDFConfig.InputView = tfidfInputWithoutSuffix
	if err := validateFeatureManifest(extractor.manifest); err != nil {
		t.Fatalf("valid v2 manifest rejected: %v", err)
	}

	com, err := extractor.Extract("login.example.com")
	if err != nil {
		t.Fatalf("extract .com: %v", err)
	}
	netFeatures, err := extractor.Extract("login.example.net")
	if err != nil {
		t.Fatalf("extract .net: %v", err)
	}
	for index := handcraftedFeatureCount; index < totalFeatureCount; index++ {
		if math.Abs(com[index]-netFeatures[index]) > 1e-12 {
			t.Fatalf("suffix leaked into TF-IDF feature %d: .com=%g .net=%g", index, com[index], netFeatures[index])
		}
	}

	invalid := extractor.manifest
	invalid.TFIDFConfig.InputView = ""
	if err := validateFeatureManifest(invalid); err == nil {
		t.Fatal("v2 manifest without explicit suffix-stripped input view should be rejected")
	}
}

func TestFeatureExtractorV3SnapshotExtensions(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "ml", "models", "v1", "feature_manifest.v1.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest FeatureManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.ContractVersion = featureManifestVersionV3
	manifest.TFIDFConfig.InputView = tfidfInputWithoutSuffix
	manifest.SnapshotPolicy = SnapshotPolicy{
		BaseFiles: map[string]string{
			"brands": "brands.v1.json", "keywords": "keywords.v1.json",
			"tld_risk": "tld_risk.v1.json", "shared_hosting": "shared_hosting.v1.json",
			"homoglyphs": "homoglyphs.v1.json", "keyboard_adjacency": "keyboard_adjacency.v1.json",
		},
		KeywordExtensions:       []string{"xbet", "casino", "slot"},
		BrandExtensions:         []Brand{{Name: "spotify", OfficialDomain: "spotify.com", AltDomains: []string{"spotifycdn.com"}}},
		SharedHostingExtensions: []string{"weebly.com", "weeblysite.com", "godaddysites.com"},
	}
	tempManifest := filepath.Join(t.TempDir(), "feature_manifest.json")
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tempManifest, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	extractor, err := NewFeatureExtractor(tempManifest)
	if err != nil {
		t.Fatalf("load v3 extractor: %v", err)
	}

	spotify, err := extractor.Extract("pl.spotify-original.com")
	if err != nil {
		t.Fatal(err)
	}
	if spotify[20] != 1 {
		t.Fatalf("expected Spotify compound main-label feature, got %g", spotify[20])
	}
	xbet, err := extractor.Extract("1xbet-xoso.com")
	if err != nil {
		t.Fatal(err)
	}
	if xbet[15] < 1 {
		t.Fatalf("expected v3 risk keyword feature, got %g", xbet[15])
	}
	sharedHosting, err := extractor.Extract("tenant.weebly.com")
	if err != nil {
		t.Fatal(err)
	}
	if sharedHosting[16] != 1 {
		t.Fatalf("expected v3 shared-hosting feature, got %g", sharedHosting[16])
	}
}
