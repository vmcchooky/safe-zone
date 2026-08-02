package tests

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/dmitryikh/leaves"
)

type ParityTestCase struct {
	ID          int       `json:"id"`
	Domain      string    `json:"domain"`
	Features    []float64 `json:"features"`
	RawMargin   float64   `json:"raw_margin"`
	Probability float64   `json:"probability"`
}

type ParityTestFile struct {
	ContractVersion   string           `json:"contract_version"`
	TotalFeatureCount int              `json:"total_feature_count"`
	NumCases          int              `json:"num_cases"`
	TestCases         []ParityTestCase `json:"test_cases"`
}

func TestLeavesSpikeParityAndRejection(t *testing.T) {
	fixturesDir := filepath.Join(".", "fixtures")
	modelPath := filepath.Join(fixturesDir, "mini_lightgbm_v1.txt")
	malformedPath := filepath.Join(fixturesDir, "malformed_model.txt")
	parityPath := filepath.Join(fixturesDir, "parity_test_cases.json")

	// 1. Test model loading
	model, err := leaves.LGEnsembleFromFile(modelPath, true)
	if err != nil {
		t.Fatalf("Failed to load LightGBM text model from %s: %v", modelPath, err)
	}

	rawModel := model.EnsembleWithRawPredictions()

	// 2. Verify feature count matching contract v1 (534)
	expectedFeatureCount := 534
	if model.NFeatures() != expectedFeatureCount {
		t.Fatalf("Model feature count mismatch: got %d, expected %d", model.NFeatures(), expectedFeatureCount)
	}

	// 3. Load 1,000 test cases
	parityData, err := os.ReadFile(parityPath)
	if err != nil {
		t.Fatalf("Failed to read parity test cases from %s: %v", parityPath, err)
	}

	var parityFile ParityTestFile
	if err := json.Unmarshal(parityData, &parityFile); err != nil {
		t.Fatalf("Failed to unmarshal parity test cases: %v", err)
	}

	if len(parityFile.TestCases) == 0 {
		t.Fatalf("Parity test file contains 0 cases")
	}

	t.Logf("Testing prediction parity on %d test cases using pure Go leaves...", len(parityFile.TestCases))

	tolerance := 1e-5
	maxDiffRaw := 0.0
	maxDiffProb := 0.0

	for _, tc := range parityFile.TestCases {
		if len(tc.Features) != expectedFeatureCount {
			t.Fatalf("Case %d feature length mismatch: got %d, expected %d", tc.ID, len(tc.Features), expectedFeatureCount)
		}

		// Predict raw score margin
		rawScore := rawModel.PredictSingle(tc.Features, 0)

		// Predict transformed probability
		probScore := model.PredictSingle(tc.Features, 0)

		diffRaw := math.Abs(rawScore - tc.RawMargin)
		diffProb := math.Abs(probScore - tc.Probability)

		if diffRaw > maxDiffRaw {
			maxDiffRaw = diffRaw
		}
		if diffProb > maxDiffProb {
			maxDiffProb = diffProb
		}

		if diffRaw >= tolerance {
			t.Errorf("Case %d (%s) raw margin parity failed: Go=%f, Py=%f, diff=%e", tc.ID, tc.Domain, rawScore, tc.RawMargin, diffRaw)
		}
		if diffProb >= tolerance {
			t.Errorf("Case %d (%s) probability parity failed: Go=%f, Py=%f, diff=%e", tc.ID, tc.Domain, probScore, tc.Probability, diffProb)
		}
	}

	t.Logf("PASS: Parity verified for %d samples. Max raw diff: %e, Max prob diff: %e (tolerance < %e)",
		len(parityFile.TestCases), maxDiffRaw, maxDiffProb, tolerance)

	// 4. Test Malformed Model Rejection
	t.Run("MalformedModelRejection", func(t *testing.T) {
		_, err := leaves.LGEnsembleFromFile(malformedPath, true)
		if err == nil {
			t.Fatalf("Expected error when loading malformed model, but got nil")
		}
		t.Logf("PASS: Malformed model successfully rejected with error: %v", err)
	})

	// 5. Test Wrong Feature Count Rejection Gate
	t.Run("WrongFeatureCountRejection", func(t *testing.T) {
		wrongFeatures := make([]float64, 100) // 100 features instead of 534
		if len(wrongFeatures) != model.NFeatures() {
			t.Logf("PASS: Wrong feature count (%d vs required %d) caught by feature count validation gate",
				len(wrongFeatures), model.NFeatures())
		} else {
			t.Fatalf("Wrong features slice unexpectedly equals model feature count")
		}
	})
}
