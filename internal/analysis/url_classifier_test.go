package analysis

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

type urlGoldenFixture struct {
	ProbabilityAbsoluteTolerance float64 `json:"probability_absolute_tolerance"`
	FeatureAbsoluteTolerance     float64 `json:"feature_absolute_tolerance"`
	Vectors                      []struct {
		CaseID        string    `json:"case_id"`
		RequestedURL  string    `json:"requested_url"`
		ExpectedHost  string    `json:"expected_host"`
		RedirectChain []string  `json:"redirect_chain"`
		FeatureText   string    `json:"feature_text"`
		Handcrafted   []float64 `json:"handcrafted"`
		RawMargin     float64   `json:"raw_margin"`
		Probability   float64   `json:"probability"`
		Action        string    `json:"action"`
		ErrorClass    string    `json:"error_class"`
	} `json:"vectors"`
}

func TestURLBundleClassifierGoldenParity(t *testing.T) {
	bundleDir := filepath.Join("..", "..", "ml", "models", "url-v1")
	classifier, err := NewURLBundleClassifier(bundleDir)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(bundleDir, "golden_vectors.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture urlGoldenFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, vector := range fixture.Vectors {
		t.Run(vector.CaseID, func(t *testing.T) {
			context := URLContext{
				RequestedURL:  vector.RequestedURL,
				ExpectedHost:  vector.ExpectedHost,
				RedirectChain: vector.RedirectChain,
			}
			text, handcrafted, featureErr := classifier.extract(context)
			decision, classifyErr := classifier.ClassifyURL(context)
			if vector.ErrorClass != "" {
				if featureErr == nil || classifyErr == nil {
					t.Fatal("expected invalid URL context error")
				}
				return
			}
			if featureErr != nil || classifyErr != nil {
				t.Fatalf("unexpected errors: feature=%v classify=%v", featureErr, classifyErr)
			}
			if text != vector.FeatureText {
				t.Fatalf("feature text mismatch\nwant: %q\ngot:  %q", vector.FeatureText, text)
			}
			if len(handcrafted) != len(vector.Handcrafted) {
				t.Fatalf("feature length mismatch: %d != %d", len(handcrafted), len(vector.Handcrafted))
			}
			for index := range handcrafted {
				if math.Abs(handcrafted[index]-vector.Handcrafted[index]) > fixture.FeatureAbsoluteTolerance {
					t.Fatalf("feature %d mismatch: %.17g != %.17g", index, handcrafted[index], vector.Handcrafted[index])
				}
			}
			if math.Abs(decision.RawMargin-vector.RawMargin) > fixture.ProbabilityAbsoluteTolerance {
				t.Fatalf("raw margin mismatch: %.17g != %.17g", decision.RawMargin, vector.RawMargin)
			}
			if math.Abs(decision.Probability-vector.Probability) > fixture.ProbabilityAbsoluteTolerance {
				t.Fatalf("probability mismatch: %.17g != %.17g", decision.Probability, vector.Probability)
			}
			if decision.Action != vector.Action {
				t.Fatalf("action mismatch: %s != %s", decision.Action, vector.Action)
			}
		})
	}
}

func TestURLBundleRejectsTamperedModel(t *testing.T) {
	source := filepath.Join("..", "..", "ml", "models", "url-v1")
	destination := t.TempDir()
	for _, name := range []string{"url_model.v1.json", "golden_vectors.v1.json", "SHA256SUMS"} {
		data, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			t.Fatal(err)
		}
		if name == "url_model.v1.json" {
			data = append(data, byte(' '))
		}
		if err := os.WriteFile(filepath.Join(destination, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := NewURLBundleClassifier(destination); err == nil {
		t.Fatal("expected tampered URL bundle to fail checksum verification")
	}
}
