package main

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
	"safe-zone/internal/risk"
	"safe-zone/internal/safefile"
)

const reportSchemaVersion = "1.0.0"

type replayCase struct {
	CaseID     string
	Domain     string
	HumanLabel string
}

type recordingClassifier struct {
	classifier *analysis.BundleClassifier
	decisions  map[string]analysis.MLDecision
	calls      int
}

func newRecordingClassifier(bundleDir string) (*recordingClassifier, error) {
	classifier, err := analysis.NewBundleClassifier(bundleDir)
	if err != nil {
		return nil, err
	}
	return &recordingClassifier{
		classifier: classifier,
		decisions:  make(map[string]analysis.MLDecision),
	}, nil
}

func (c *recordingClassifier) Enabled() bool { return c != nil && c.classifier.Enabled() }
func (c *recordingClassifier) Revision() string {
	if c == nil {
		return ""
	}
	return c.classifier.Revision()
}
func (c *recordingClassifier) ModelVersion() string {
	if c == nil {
		return ""
	}
	return c.classifier.ModelVersion()
}
func (c *recordingClassifier) BlockThreshold() float64 {
	if c == nil {
		return 0
	}
	return c.classifier.BlockThreshold()
}
func (c *recordingClassifier) Classify(domain string) (analysis.MLDecision, error) {
	decision, err := c.classifier.Classify(domain)
	if err == nil {
		c.decisions[domain] = decision
	}
	c.calls++
	return decision, err
}

type paritySummary struct {
	Compared        int      `json:"compared"`
	MismatchCount   int      `json:"mismatch_count"`
	MaxAbsDelta     float64  `json:"max_abs_delta"`
	Tolerance       float64  `json:"tolerance"`
	MismatchCaseIDs []string `json:"mismatch_case_ids"`
}

type falsePositiveSummary struct {
	BenignCases      int      `json:"benign_cases"`
	WouldBlock       int      `json:"would_block"`
	FalsePositives   int      `json:"false_positives"`
	FPR              *float64 `json:"fpr,omitempty"`
	FalsePositiveIDs []string `json:"false_positive_case_ids"`
}

type responseParitySummary struct {
	Compared        int      `json:"compared"`
	MismatchCount   int      `json:"mismatch_count"`
	MismatchCaseIDs []string `json:"mismatch_case_ids"`
}

type replayReport struct {
	SchemaVersion      string                `json:"schema_version"`
	GeneratedAt        string                `json:"generated_at"`
	Mode               analysis.MLMode       `json:"mode"`
	Rounds             int                   `json:"rounds"`
	Cases              int                   `json:"cases"`
	RequestsPerService int                   `json:"requests_per_service"`
	LabelsSHA256       string                `json:"labels_sha256"`
	SourceCommit       string                `json:"source_commit"`
	BundleSHA256SHash  string                `json:"bundle_sha256s_sha256"`
	ModelVersion       string                `json:"model_version"`
	ModelRevision      string                `json:"model_revision"`
	ModelThreshold     float64               `json:"model_threshold"`
	LabelCounts        map[string]int        `json:"label_counts"`
	Canary             risk.MLCanaryStatus   `json:"canary"`
	OfflineProbability paritySummary         `json:"offline_probability_parity"`
	RuntimeProbability paritySummary         `json:"runtime_probability_parity"`
	ResponseParity     responseParitySummary `json:"response_parity"`
	OfflineFP          falsePositiveSummary  `json:"offline_model_false_positive"`
	RuntimeFP          falsePositiveSummary  `json:"runtime_candidate_false_positive"`
	CoreStatus         risk.MLStatus         `json:"core_ml_status"`
	DNSStatus          risk.MLStatus         `json:"dns_ml_status"`
}

func main() {
	var (
		labelsPath    string
		bundleDir     string
		outputPath    string
		sourceCommit  string
		canaryPercent int
		canarySeed    string
		rounds        int
		tolerance     float64
	)
	flag.StringVar(&labelsPath, "labels", "", "reviewed labels.csv to replay")
	flag.StringVar(&bundleDir, "bundle", "", "immutable model bundle directory")
	flag.StringVar(&outputPath, "output", "", "optional JSON report path")
	flag.StringVar(&sourceCommit, "source-commit", "", "exact 40-character Git commit under evaluation")
	flag.IntVar(&canaryPercent, "canary-percent", 5, "bounded canary percentage to observe in shadow")
	flag.StringVar(&canarySeed, "canary-seed", "", "immutable canary selector seed")
	flag.IntVar(&rounds, "rounds", 3, "number of clean replay rounds per service")
	flag.Float64Var(&tolerance, "tolerance", 1e-12, "maximum probability parity delta")
	flag.Parse()

	if err := run(labelsPath, bundleDir, outputPath, sourceCommit, canaryPercent, canarySeed, rounds, tolerance); err != nil {
		fmt.Fprintln(os.Stderr, "ml replay failed:", err)
		os.Exit(1)
	}
}

func run(labelsPath, bundleDir, outputPath, sourceCommit string, canaryPercent int, canarySeed string, rounds int, tolerance float64) error {
	if strings.TrimSpace(labelsPath) == "" || strings.TrimSpace(bundleDir) == "" {
		return errors.New("--labels and --bundle are required")
	}
	if strings.TrimSpace(canarySeed) == "" {
		return errors.New("--canary-seed is required")
	}
	if !validCommit(sourceCommit) {
		return errors.New("--source-commit must be an exact 40-character hexadecimal Git commit")
	}
	if canaryPercent < 1 || canaryPercent > 100 {
		return errors.New("--canary-percent must be between 1 and 100")
	}
	if rounds < 1 || rounds > 100 {
		return errors.New("--rounds must be between 1 and 100")
	}
	if tolerance < 0 || math.IsNaN(tolerance) || math.IsInf(tolerance, 0) {
		return errors.New("--tolerance must be a finite non-negative number")
	}

	cases, labelsHash, err := readCases(labelsPath)
	if err != nil {
		return err
	}
	bundleHash, err := readBundleChecksumHash(bundleDir)
	if err != nil {
		return err
	}
	offlineCore, err := newRecordingClassifier(bundleDir)
	if err != nil {
		return fmt.Errorf("load offline core classifier: %w", err)
	}
	offlineDNS, err := newRecordingClassifier(bundleDir)
	if err != nil {
		return fmt.Errorf("load offline DNS classifier: %w", err)
	}
	runtimeCore, err := newRecordingClassifier(bundleDir)
	if err != nil {
		return fmt.Errorf("load runtime core classifier: %w", err)
	}
	runtimeDNS, err := newRecordingClassifier(bundleDir)
	if err != nil {
		return fmt.Errorf("load runtime DNS classifier: %w", err)
	}

	canary := risk.MLCanaryConfig{Percent: canaryPercent, Seed: canarySeed}
	coreService := newReplayService(runtimeCore, canary)
	dnsService := newReplayService(runtimeDNS, canary)
	defer func() { _ = coreService.Close() }()
	defer func() { _ = dnsService.Close() }()

	labelCounts := make(map[string]int)
	for _, item := range cases {
		labelCounts[item.HumanLabel]++
		if _, err := offlineCore.Classify(item.Domain); err != nil {
			return fmt.Errorf("offline core classify %s: %w", item.CaseID, err)
		}
		if _, err := offlineDNS.Classify(item.Domain); err != nil {
			return fmt.Errorf("offline DNS classify %s: %w", item.CaseID, err)
		}
	}

	responseParity := responseParitySummary{}
	for round := 0; round < rounds; round++ {
		for _, item := range cases {
			coreResult := coreService.Analyze(context.Background(), item.Domain, risk.ClientInfo{}).Result
			dnsResult := dnsService.Policy(context.Background(), item.Domain, risk.ClientInfo{}).Result
			responseParity.Compared++
			if !equalResult(coreResult, dnsResult) {
				responseParity.MismatchCaseIDs = appendUnique(responseParity.MismatchCaseIDs, item.CaseID)
			}
		}
	}
	responseParity.MismatchCount = len(responseParity.MismatchCaseIDs)

	offlineParity := compareDecisions(cases, offlineCore.decisions, offlineDNS.decisions, tolerance)
	runtimeParity := compareDecisions(cases, runtimeCore.decisions, runtimeDNS.decisions, tolerance)
	offlineFP := calculateFalsePositives(cases, offlineCore.decisions)
	runtimeFP := calculateFalsePositives(cases, runtimeCore.decisions)
	coreStatus := coreService.MLStatus()
	dnsStatus := dnsService.MLStatus()
	if coreStatus.EnforcePromotions != 0 || dnsStatus.EnforcePromotions != 0 {
		return errors.New("shadow replay observed an enforce promotion")
	}

	report := replayReport{
		SchemaVersion:      reportSchemaVersion,
		GeneratedAt:        time.Now().UTC().Format(time.RFC3339Nano),
		Mode:               analysis.MLModeShadow,
		Rounds:             rounds,
		Cases:              len(cases),
		RequestsPerService: len(cases) * rounds,
		LabelsSHA256:       labelsHash,
		SourceCommit:       strings.ToLower(sourceCommit),
		BundleSHA256SHash:  bundleHash,
		ModelVersion:       offlineCore.ModelVersion(),
		ModelRevision:      offlineCore.Revision(),
		ModelThreshold:     offlineCore.BlockThreshold(),
		LabelCounts:        labelCounts,
		Canary:             coreStatus.Canary,
		OfflineProbability: offlineParity,
		RuntimeProbability: runtimeParity,
		ResponseParity:     responseParity,
		OfflineFP:          offlineFP,
		RuntimeFP:          runtimeFP,
		CoreStatus:         coreStatus,
		DNSStatus:          dnsStatus,
	}

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if outputPath != "" {
		if err := os.WriteFile(outputPath, encoded, 0o600); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
	}
	_, err = os.Stdout.Write(encoded)
	return err
}

func validCommit(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') && (character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}

func readBundleChecksumHash(bundleDir string) (string, error) {
	data, err := safefile.ReadFileWithin(bundleDir, "SHA256SUMS")
	if err != nil {
		return "", fmt.Errorf("read bundle SHA256SUMS: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func newReplayService(classifier analysis.DomainClassifier, canary risk.MLCanaryConfig) *risk.Service {
	return risk.NewService(risk.Options{
		AIProvider:          "",
		AnalysisConfig:      config.DefaultAnalysisConfig(),
		MLClassifier:        classifier,
		MLMode:              analysis.MLModeShadow,
		MLCanary:            canary,
		TTLAllowed:          time.Hour,
		TTLSuspicious:       time.Hour,
		TTLBlocked:          time.Hour,
		ConfigReloadEnabled: false,
		EnrichEnabled:       false,
		DisableAdblockSync:  true,
	})
}

func readCases(path string) ([]replayCase, string, error) {
	data, err := safefile.ReadFileWithin(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return nil, "", fmt.Errorf("read labels: %w", err)
	}
	reader := csv.NewReader(strings.NewReader(string(data)))
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, "", fmt.Errorf("parse labels: %w", err)
	}
	if len(rows) < 2 {
		return nil, "", errors.New("labels CSV has no cases")
	}
	header := make(map[string]int, len(rows[0]))
	for index, name := range rows[0] {
		header[strings.TrimSpace(name)] = index
	}
	for _, required := range []string{"case_id", "domain", "human_label"} {
		if _, ok := header[required]; !ok {
			return nil, "", fmt.Errorf("labels CSV missing %s", required)
		}
	}
	cases := make([]replayCase, 0, len(rows)-1)
	seen := make(map[string]struct{}, len(rows)-1)
	for rowIndex, row := range rows[1:] {
		value := func(name string) string {
			index := header[name]
			if index >= len(row) {
				return ""
			}
			return strings.TrimSpace(row[index])
		}
		item := replayCase{CaseID: value("case_id"), Domain: value("domain"), HumanLabel: strings.ToLower(value("human_label"))}
		if item.CaseID == "" || item.Domain == "" {
			return nil, "", fmt.Errorf("labels row %d has empty case_id or domain", rowIndex+2)
		}
		if _, ok := seen[item.CaseID]; ok {
			return nil, "", fmt.Errorf("duplicate case_id %s", item.CaseID)
		}
		seen[item.CaseID] = struct{}{}
		cases = append(cases, item)
	}
	sum := sha256.Sum256(data)
	return cases, hex.EncodeToString(sum[:]), nil
}

func compareDecisions(cases []replayCase, left, right map[string]analysis.MLDecision, tolerance float64) paritySummary {
	summary := paritySummary{Tolerance: tolerance}
	for _, item := range cases {
		leftDecision, leftOK := left[item.Domain]
		rightDecision, rightOK := right[item.Domain]
		if !leftOK && !rightOK {
			continue
		}
		summary.Compared++
		if !leftOK || !rightOK {
			summary.MismatchCaseIDs = append(summary.MismatchCaseIDs, item.CaseID)
			continue
		}
		delta := math.Abs(leftDecision.Probability - rightDecision.Probability)
		if delta > summary.MaxAbsDelta {
			summary.MaxAbsDelta = delta
		}
		if delta > tolerance || leftDecision.Action != rightDecision.Action || leftDecision.Revision != rightDecision.Revision {
			summary.MismatchCaseIDs = append(summary.MismatchCaseIDs, item.CaseID)
		}
	}
	sort.Strings(summary.MismatchCaseIDs)
	summary.MismatchCount = len(summary.MismatchCaseIDs)
	return summary
}

func calculateFalsePositives(cases []replayCase, decisions map[string]analysis.MLDecision) falsePositiveSummary {
	summary := falsePositiveSummary{}
	for _, item := range cases {
		if item.HumanLabel != "benign" {
			continue
		}
		decision, ok := decisions[item.Domain]
		if !ok {
			continue
		}
		summary.BenignCases++
		if decision.Action != analysis.MLActionPromoteMalicious {
			continue
		}
		summary.WouldBlock++
		summary.FalsePositives++
		summary.FalsePositiveIDs = append(summary.FalsePositiveIDs, item.CaseID)
	}
	if summary.BenignCases > 0 {
		fpr := float64(summary.FalsePositives) / float64(summary.BenignCases)
		summary.FPR = &fpr
	}
	return summary
}

func equalResult(left, right analysis.Result) bool {
	if left.Domain != right.Domain || left.Verdict != right.Verdict || left.Score != right.Score || left.Confidence != right.Confidence || left.Category != right.Category {
		return false
	}
	if len(left.Reasons) != len(right.Reasons) {
		return false
	}
	for index := range left.Reasons {
		if left.Reasons[index] != right.Reasons[index] {
			return false
		}
	}
	return true
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
