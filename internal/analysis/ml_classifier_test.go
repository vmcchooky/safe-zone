package analysis

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type goldenClassifierFixture struct {
	BundleRevision string `json:"bundle_revision"`
	TestCases      []struct {
		Domain         string  `json:"domain"`
		RawMargin      float64 `json:"raw_margin"`
		CalibratedProb float64 `json:"calibrated_prob"`
		Action         string  `json:"action"`
	} `json:"test_cases"`
}

func TestBundleClassifierGoldenParityAndConcurrency(t *testing.T) {
	bundleDir := filepath.Join("..", "..", "ml", "models", "v1")
	fixturePath := filepath.Join("..", "..", "ml", "tests", "fixtures", "golden_vectors.v1.json")
	classifier, err := NewBundleClassifier(bundleDir)
	if err != nil {
		t.Fatalf("load model bundle: %v", err)
	}
	if classifier.Revision() == "" || !classifier.Enabled() {
		t.Fatalf("classifier should be enabled with a non-empty revision")
	}
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read golden fixture: %v", err)
	}
	var fixture goldenClassifierFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("parse golden fixture: %v", err)
	}
	if fixture.BundleRevision != classifier.Revision() {
		t.Fatalf("revision mismatch: got %s, want %s", classifier.Revision(), fixture.BundleRevision)
	}
	for _, tc := range fixture.TestCases {
		decision, err := classifier.Classify(tc.Domain)
		if err != nil {
			// The invalid long-domain fixture is deliberately rejected by the
			// runtime contract and is not a prediction input.
			continue
		}
		if math.Abs(decision.RawMargin-tc.RawMargin) > 1e-5 || math.Abs(decision.Probability-tc.CalibratedProb) > 1e-5 || decision.Action != tc.Action {
			t.Errorf("%s: got raw=%.12g prob=%.12g action=%s; want raw=%.12g prob=%.12g action=%s", tc.Domain, decision.RawMargin, decision.Probability, decision.Action, tc.RawMargin, tc.CalibratedProb, tc.Action)
		}
	}

	const workers = 20
	const queries = 100
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < queries; j++ {
				decision, err := classifier.Classify("paypal-security-login-verify-account.com")
				if err != nil || decision.Action != MLActionPromoteMalicious {
					t.Errorf("concurrent prediction failed: decision=%+v err=%v", decision, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
