package tests

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/dmitryikh/leaves"
)

type BundleHashes struct {
	Model       string `json:"model"`
	Manifest    string `json:"manifest"`
	Calibration string `json:"calibration"`
	Policy      string `json:"policy"`
}

type CalibrationParams struct {
	A float64 `json:"A"`
	B float64 `json:"B"`
}

type CalibrationConfig struct {
	CalibrationVersion string            `json:"calibration_version"`
	Method             string            `json:"method"`
	Parameters         CalibrationParams `json:"parameters"`
}

type PolicyConfig struct {
	PolicyVersion  string  `json:"policy_version"`
	OperatingMode  string  `json:"operating_mode"`
	BlockThreshold float64 `json:"block_threshold"`
}

type GoldenTestCase struct {
	ID               int       `json:"id"`
	Domain           string    `json:"domain"`
	CanonicalASCII   string    `json:"canonical_ascii"`
	CanonicalUnicode string    `json:"canonical_unicode"`
	IsValid          bool      `json:"is_valid"`
	RawMargin        float64   `json:"raw_margin"`
	UncalibratedProb float64   `json:"uncalibrated_prob"`
	CalibratedProb   float64   `json:"calibrated_prob"`
	Action           string    `json:"action"`
	Features         []float64 `json:"features"`
}

type GoldenFixture struct {
	FixtureVersion    string           `json:"fixture_version"`
	BundleRevision    string           `json:"bundle_revision"`
	TotalFeatureCount int              `json:"total_feature_count"`
	NumCases          int              `json:"num_cases"`
	BundleHashes      BundleHashes     `json:"bundle_hashes"`
	TestCases         []GoldenTestCase `json:"test_cases"`
}

type ModelBundleLoader struct {
	ModelPath  string
	BundleDir  string
	Model      *leaves.Ensemble
	RawModel   *leaves.Ensemble
	Revision   string
	Params     CalibrationParams
	Policy     PolicyConfig
	TotalFeats int
}

func computeFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	canonical := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	hash := sha256.Sum256(canonical)
	return hex.EncodeToString(hash[:]), nil
}

func LoadModelBundle(bundleDir string) (*ModelBundleLoader, error) {
	modelPath := filepath.Join(bundleDir, "domain_threat_lgbm.txt")
	manifestPath := filepath.Join(bundleDir, "feature_manifest.v1.json")
	calibPath := filepath.Join(bundleDir, "calibration.json")
	policyPath := filepath.Join(bundleDir, "policy.json")
	reportPath := filepath.Join(bundleDir, "model_report.json")
	checksumPath := filepath.Join(bundleDir, "SHA256SUMS")

	// 1. Verify file existence
	requiredFiles := []string{modelPath, manifestPath, calibPath, policyPath, reportPath, checksumPath}
	for _, f := range requiredFiles {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			return nil, fmt.Errorf("bundle file missing: %s", f)
		}
	}

	// 2. Verify SHA256SUMS file checksums
	checksumBytes, err := os.ReadFile(checksumPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read SHA256SUMS: %v", err)
	}

	lines := strings.Split(string(checksumBytes), "\n")
	expectedHashes := make(map[string]string)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 2 {
			expectedHashes[parts[1]] = parts[0]
		}
	}

	for _, fname := range []string{"domain_threat_lgbm.txt", "feature_manifest.v1.json", "calibration.json", "policy.json", "model_report.json"} {
		expectedHash, exists := expectedHashes[fname]
		if !exists {
			return nil, fmt.Errorf("SHA256SUMS missing entry for %s", fname)
		}
		actualHash, err := computeFileSHA256(filepath.Join(bundleDir, fname))
		if err != nil {
			return nil, fmt.Errorf("failed to compute hash for %s: %v", fname, err)
		}
		if actualHash != expectedHash {
			return nil, fmt.Errorf("SHA256 mismatch for %s: got %s, expected %s", fname, actualHash, expectedHash)
		}
	}

	// 3. Compute deterministic bundle revision
	modelHash, _ := computeFileSHA256(modelPath)
	manifestHash, _ := computeFileSHA256(manifestPath)
	calibHash, _ := computeFileSHA256(calibPath)
	policyHash, _ := computeFileSHA256(policyPath)

	revSrc := fmt.Sprintf("%s:%s:%s:%s", modelHash, manifestHash, calibHash, policyHash)
	revHasher := sha256.New()
	revHasher.Write([]byte(revSrc))
	revision := hex.EncodeToString(revHasher.Sum(nil))

	// 4. Read Calibration and Policy
	calibBytes, err := os.ReadFile(calibPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read calibration.json: %v", err)
	}
	var calibCfg CalibrationConfig
	if err := json.Unmarshal(calibBytes, &calibCfg); err != nil {
		return nil, fmt.Errorf("failed to parse calibration.json: %v", err)
	}

	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy.json: %v", err)
	}
	var policyCfg PolicyConfig
	if err := json.Unmarshal(policyBytes, &policyCfg); err != nil {
		return nil, fmt.Errorf("failed to parse policy.json: %v", err)
	}

	if policyCfg.BlockThreshold <= 0.0 || policyCfg.BlockThreshold >= 1.0 {
		return nil, fmt.Errorf("invalid policy block_threshold: %f (must be between 0 and 1)", policyCfg.BlockThreshold)
	}

	// 5. Load LightGBM model
	model, err := leaves.LGEnsembleFromFile(modelPath, true)
	if err != nil {
		return nil, fmt.Errorf("failed to load LightGBM model: %v", err)
	}
	rawModel := model.EnsembleWithRawPredictions()

	return &ModelBundleLoader{
		ModelPath:  modelPath,
		BundleDir:  bundleDir,
		Model:      model,
		RawModel:   rawModel,
		Revision:   revision,
		Params:     calibCfg.Parameters,
		Policy:     policyCfg,
		TotalFeats: model.NFeatures(),
	}, nil
}

func (m *ModelBundleLoader) PredictCalibrated(features []float64) (float64, float64, string, error) {
	if len(features) != m.TotalFeats {
		return 0, 0, "", fmt.Errorf("feature length mismatch: got %d, expected %d", len(features), m.TotalFeats)
	}

	rawMargin := m.RawModel.PredictSingle(features, 0)
	// Platt Sigmoid calibration: P = 1 / (1 + exp(A * z + B))
	calibratedProb := 1.0 / (1.0 + math.Exp(m.Params.A*rawMargin+m.Params.B))

	action := "abstain"
	if calibratedProb >= m.Policy.BlockThreshold {
		action = "promote_malicious"
	}

	return rawMargin, calibratedProb, action, nil
}

func TestPhase3ModelBundleAndParity(t *testing.T) {
	bundleDir := filepath.Join("..", "models", "v1")
	fixturePath := filepath.Join("fixtures", "golden_vectors.v1.json")

	// 1. Test Model Bundle Loading & Checksum Validation
	loader, err := LoadModelBundle(bundleDir)
	if err != nil {
		t.Fatalf("Failed to load model bundle from %s: %v", bundleDir, err)
	}

	expectedFeatureCount := 534
	if loader.TotalFeats != expectedFeatureCount {
		t.Fatalf("Loader feature count mismatch: got %d, expected %d", loader.TotalFeats, expectedFeatureCount)
	}

	t.Logf("Model bundle loaded successfully! Revision: %s, Features: %d, Threshold: %.2f",
		loader.Revision, loader.TotalFeats, loader.Policy.BlockThreshold)

	// 2. Load Golden Parity Test Fixtures
	fixtureData, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read golden vectors fixture from %s: %v", fixturePath, err)
	}

	var fixture GoldenFixture
	if err := json.Unmarshal(fixtureData, &fixture); err != nil {
		t.Fatalf("Failed to parse golden vectors fixture: %v", err)
	}

	if fixture.BundleRevision != loader.Revision {
		t.Fatalf("Bundle revision mismatch between fixture (%s) and loaded loader (%s)",
			fixture.BundleRevision, loader.Revision)
	}

	t.Logf("Running parity verification on %d golden test cases...", len(fixture.TestCases))

	tolerance := 1e-5
	maxDiffRaw := 0.0
	maxDiffCalib := 0.0

	for _, tc := range fixture.TestCases {
		rawMargin, calibProb, action, err := loader.PredictCalibrated(tc.Features)
		if err != nil {
			t.Fatalf("Case %d (%s) prediction failed: %v", tc.ID, tc.Domain, err)
		}

		diffRaw := math.Abs(rawMargin - tc.RawMargin)
		diffCalib := math.Abs(calibProb - tc.CalibratedProb)

		if diffRaw > maxDiffRaw {
			maxDiffRaw = diffRaw
		}
		if diffCalib > maxDiffCalib {
			maxDiffCalib = diffCalib
		}

		if diffRaw >= tolerance {
			t.Errorf("Case %d (%s) raw margin mismatch: Go=%f, Py=%f, diff=%e",
				tc.ID, tc.Domain, rawMargin, tc.RawMargin, diffRaw)
		}
		if diffCalib >= tolerance {
			t.Errorf("Case %d (%s) calibrated probability mismatch: Go=%f, Py=%f, diff=%e",
				tc.ID, tc.Domain, calibProb, tc.CalibratedProb, diffCalib)
		}
		if action != tc.Action {
			t.Errorf("Case %d (%s) policy action mismatch: Go=%s, Py=%s",
				tc.ID, tc.Domain, action, tc.Action)
		}
	}

	t.Logf("PASS: Parity verified for %d golden test cases! Max raw diff: %e, Max calibrated diff: %e (tolerance < %e)",
		len(fixture.TestCases), maxDiffRaw, maxDiffCalib, tolerance)

	// 3. Test Bundle Rejection Gates
	t.Run("RejectionGate_MissingFile", func(t *testing.T) {
		_, err := LoadModelBundle(filepath.Join("..", "models", "non_existent"))
		if err == nil {
			t.Fatalf("Expected error loading missing bundle directory, got nil")
		}
		t.Logf("PASS: Missing bundle directory rejected correctly: %v", err)
	})

	t.Run("RejectionGate_FeatureCountMismatch", func(t *testing.T) {
		wrongFeatures := make([]float64, 100)
		_, _, _, err := loader.PredictCalibrated(wrongFeatures)
		if err == nil {
			t.Fatalf("Expected error predicting with 100 features (required 534), got nil")
		}
		t.Logf("PASS: Feature count mismatch gate rejected correctly: %v", err)
	})

	// 4. Test Thread-Safety / Concurrent Prediction
	t.Run("ThreadSafety_ConcurrentInference", func(t *testing.T) {
		numGoroutines := 20
		numQueriesPerGoroutine := 100
		var wg sync.WaitGroup

		sampleFeatures := fixture.TestCases[0].Features
		expectedRaw := fixture.TestCases[0].RawMargin
		expectedCalib := fixture.TestCases[0].CalibratedProb

		wg.Add(numGoroutines)
		for g := 0; g < numGoroutines; g++ {
			go func(routineID int) {
				defer wg.Done()
				for q := 0; q < numQueriesPerGoroutine; q++ {
					raw, calib, _, err := loader.PredictCalibrated(sampleFeatures)
					if err != nil {
						t.Errorf("Routine %d query %d error: %v", routineID, q, err)
						return
					}
					if math.Abs(raw-expectedRaw) >= tolerance {
						t.Errorf("Routine %d query %d raw score race condition detected", routineID, q)
					}
					if math.Abs(calib-expectedCalib) >= tolerance {
						t.Errorf("Routine %d query %d calib score race condition detected", routineID, q)
					}
				}
			}(g)
		}
		wg.Wait()
		t.Logf("PASS: Verified thread-safety across %d concurrent goroutines (%d queries total)",
			numGoroutines, numGoroutines*numQueriesPerGoroutine)
	})
}
