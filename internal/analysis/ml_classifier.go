package analysis

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dmitryikh/leaves"
)

type MLMode string

const (
	MLModeDisabled MLMode = "disabled"
	MLModeShadow   MLMode = "shadow"
	MLModeEnforce  MLMode = "enforce"
)

const (
	MLActionAbstain          = "abstain"
	MLActionPromoteMalicious = "promote_malicious"
)

type MLDecision struct {
	Probability  float64 `json:"probability"`
	Action       string  `json:"action"`
	ModelVersion string  `json:"model_version,omitempty"`
	Revision     string  `json:"revision,omitempty"`
	RawMargin    float64 `json:"-"`
}

type DomainClassifier interface {
	Enabled() bool
	Revision() string
	Classify(domain string) (MLDecision, error)
}

type ClassifierMetadata interface {
	ModelVersion() string
	BlockThreshold() float64
}

type calibrationConfig struct {
	CalibrationVersion string `json:"calibration_version"`
	Method             string `json:"method"`
	Parameters         struct {
		A float64 `json:"A"`
		B float64 `json:"B"`
	} `json:"parameters"`
}

type policyConfig struct {
	PolicyVersion  string  `json:"policy_version"`
	OperatingMode  string  `json:"operating_mode"`
	BlockThreshold float64 `json:"block_threshold"`
}

type bundleChecksums struct {
	model       string
	manifest    string
	calibration string
	policy      string
	report      string
}

// BundleClassifier owns immutable model, feature contract and policy data.
// It does not mutate any prediction state and is safe for concurrent calls.
type BundleClassifier struct {
	model        *leaves.Ensemble
	features     *FeatureExtractor
	revision     string
	modelVersion string
	threshold    float64
	calibrationA float64
	calibrationB float64
}

func NewBundleClassifier(bundleDir string) (*BundleClassifier, error) {
	return NewBundleClassifierWithThreshold(bundleDir, nil)
}

func NewBundleClassifierWithThreshold(bundleDir string, thresholdOverride *float64) (*BundleClassifier, error) {
	bundleDir = strings.TrimSpace(bundleDir)
	if bundleDir == "" {
		return nil, errors.New("ML bundle directory is empty")
	}
	paths := map[string]string{}
	for _, name := range []string{"domain_threat_lgbm.txt", "feature_manifest.v1.json", "calibration.json", "policy.json", "model_report.json", "SHA256SUMS"} {
		path := filepath.Join(bundleDir, name)
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			return nil, fmt.Errorf("bundle file missing: %s", name)
		}
		paths[name] = path
	}

	checksums, err := readAndVerifyBundleChecksums(paths)
	if err != nil {
		return nil, err
	}
	manifestData, err := os.ReadFile(paths["feature_manifest.v1.json"])
	if err != nil {
		return nil, fmt.Errorf("read feature manifest: %w", err)
	}
	var manifest FeatureManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("parse feature manifest: %w", err)
	}
	if err := validateFeatureManifest(manifest); err != nil {
		return nil, err
	}

	calibrationData, err := os.ReadFile(paths["calibration.json"])
	if err != nil {
		return nil, fmt.Errorf("read calibration: %w", err)
	}
	var calibration calibrationConfig
	if err := json.Unmarshal(calibrationData, &calibration); err != nil {
		return nil, fmt.Errorf("parse calibration: %w", err)
	}
	if calibration.CalibrationVersion != "1.0.0" || calibration.Method != "platt_sigmoid" ||
		math.IsNaN(calibration.Parameters.A) || math.IsInf(calibration.Parameters.A, 0) ||
		math.IsNaN(calibration.Parameters.B) || math.IsInf(calibration.Parameters.B, 0) {
		return nil, errors.New("unsupported or invalid calibration contract")
	}

	policyData, err := os.ReadFile(paths["policy.json"])
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	var policy policyConfig
	if err := json.Unmarshal(policyData, &policy); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if policy.PolicyVersion != "1.0.0" || policy.BlockThreshold <= 0 || policy.BlockThreshold >= 1 ||
		math.IsNaN(policy.BlockThreshold) || math.IsInf(policy.BlockThreshold, 0) {
		return nil, errors.New("unsupported or invalid policy contract")
	}
	threshold := policy.BlockThreshold
	if thresholdOverride != nil {
		if *thresholdOverride <= 0 || *thresholdOverride >= 1 || math.IsNaN(*thresholdOverride) || math.IsInf(*thresholdOverride, 0) {
			return nil, fmt.Errorf("invalid ML block threshold override: %v", *thresholdOverride)
		}
		threshold = *thresholdOverride
	}

	model, err := leaves.LGEnsembleFromFile(paths["domain_threat_lgbm.txt"], true)
	if err != nil {
		return nil, fmt.Errorf("load LightGBM model: %w", err)
	}
	if model.NFeatures() != totalFeatureCount {
		return nil, fmt.Errorf("model feature count %d, expected %d", model.NFeatures(), totalFeatureCount)
	}
	modelVersion := manifest.ContractVersion
	if report, readErr := os.ReadFile(paths["model_report.json"]); readErr == nil {
		var metadata struct {
			ModelVersion string `json:"model_version"`
		}
		if json.Unmarshal(report, &metadata) == nil && metadata.ModelVersion != "" {
			modelVersion = metadata.ModelVersion
		}
	}

	revisionSource := fmt.Sprintf("%s:%s:%s:%s", checksums.model, checksums.manifest, checksums.calibration, checksums.policy)
	if thresholdOverride != nil {
		revisionSource += ":threshold=" + strconv.FormatFloat(threshold, 'g', -1, 64)
	}
	revisionSum := sha256.Sum256([]byte(revisionSource))

	features, err := NewFeatureExtractor(paths["feature_manifest.v1.json"])
	if err != nil {
		return nil, err
	}
	return &BundleClassifier{
		model:        model.EnsembleWithRawPredictions(),
		features:     features,
		revision:     hex.EncodeToString(revisionSum[:]),
		modelVersion: modelVersion,
		threshold:    threshold,
		calibrationA: calibration.Parameters.A,
		calibrationB: calibration.Parameters.B,
	}, nil
}

// LoadModelBundle is an explicit alias used by integration code and tests.
func LoadModelBundle(bundleDir string) (*BundleClassifier, error) {
	return NewBundleClassifier(bundleDir)
}

func (c *BundleClassifier) Enabled() bool { return c != nil && c.model != nil && c.features != nil }

func (c *BundleClassifier) Revision() string {
	if c == nil {
		return ""
	}
	return c.revision
}

func (c *BundleClassifier) ModelVersion() string {
	if c == nil {
		return ""
	}
	return c.modelVersion
}

func (c *BundleClassifier) BlockThreshold() float64 {
	if c == nil {
		return 0
	}
	return c.threshold
}

func (c *BundleClassifier) Classify(domain string) (decision MLDecision, err error) {
	decision.Action = MLActionAbstain
	if !c.Enabled() {
		return decision, errors.New("ML classifier is disabled")
	}
	decision.ModelVersion = c.modelVersion
	decision.Revision = c.revision
	features, err := c.features.Extract(domain)
	if err != nil {
		return decision, err
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("ML prediction panic: %v", recovered)
			decision.Action = MLActionAbstain
		}
	}()
	decision.RawMargin = c.model.PredictSingle(features, 0)
	if math.IsNaN(decision.RawMargin) || math.IsInf(decision.RawMargin, 0) {
		return decision, errors.New("ML raw margin is not finite")
	}
	decision.Probability = plattProbability(c.calibrationA, c.calibrationB, decision.RawMargin)
	if math.IsNaN(decision.Probability) || math.IsInf(decision.Probability, 0) || decision.Probability < 0 || decision.Probability > 1 {
		return decision, errors.New("ML calibrated probability is invalid")
	}
	if decision.Probability >= c.threshold {
		decision.Action = MLActionPromoteMalicious
	}
	return decision, nil
}

func plattProbability(a, b, rawMargin float64) float64 {
	value := a*rawMargin + b
	if value >= 0 {
		return 1 / (1 + math.Exp(value))
	}
	expValue := math.Exp(-value)
	return expValue / (1 + expValue)
}

func readAndVerifyBundleChecksums(paths map[string]string) (bundleChecksums, error) {
	data, err := os.ReadFile(paths["SHA256SUMS"])
	if err != nil {
		return bundleChecksums{}, fmt.Errorf("read SHA256SUMS: %w", err)
	}
	expected := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 || len(fields[0]) != sha256.Size*2 {
			return bundleChecksums{}, errors.New("malformed SHA256SUMS entry")
		}
		expected[fields[1]] = strings.ToLower(fields[0])
	}
	if err := scanner.Err(); err != nil {
		return bundleChecksums{}, fmt.Errorf("read SHA256SUMS: %w", err)
	}
	var result bundleChecksums
	for name, destination := range map[string]*string{
		"domain_threat_lgbm.txt":   &result.model,
		"feature_manifest.v1.json": &result.manifest,
		"calibration.json":         &result.calibration,
		"policy.json":              &result.policy,
		"model_report.json":        &result.report,
	} {
		expectedHash, ok := expected[name]
		if !ok {
			return bundleChecksums{}, fmt.Errorf("SHA256SUMS missing entry for %s", name)
		}
		actual, err := hashFile(paths[name])
		if err != nil {
			return bundleChecksums{}, fmt.Errorf("hash %s: %w", name, err)
		}
		if !strings.EqualFold(actual, expectedHash) {
			return bundleChecksums{}, fmt.Errorf("SHA256 mismatch for %s", name)
		}
		*destination = actual
	}
	return result, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- paths come from the fixed, validated bundle file set.
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	canonical := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	hash := sha256.Sum256(canonical)
	return hex.EncodeToString(hash[:]), nil
}

var _ DomainClassifier = (*BundleClassifier)(nil)
