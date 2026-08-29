package main

import (
	"bufio"
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
	"safe-zone/internal/feed"
	"safe-zone/internal/risk"
)

const reportSchemaVersion = "1.0.0"

type fileRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type predictionRef struct {
	fileRef
	ModelSHA256 string  `json:"model_sha256"`
	Threshold   float64 `json:"threshold"`
}

type sourceConfig struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	SourceURL   string `json:"source_url"`
	CollectedAt string `json:"collected_at"`
}

type protocol struct {
	SchemaVersion   string             `json:"schema_version"`
	AsOf            string             `json:"as_of"`
	FeedTTLHours    int                `json:"feed_ttl_hours"`
	StaleAfterHours int                `json:"stale_after_hours"`
	WhitelistState  string             `json:"whitelist_state"`
	AdmissionMode   feed.AdmissionMode `json:"admission_mode,omitempty"`
	Labels          fileRef            `json:"labels"`
	Predictions     predictionRef      `json:"model_predictions"`
	ExpectedLabels  map[string]int     `json:"expected_labels"`
	Sources         []sourceConfig     `json:"sources"`
}

type evaluationCase struct {
	CaseID     string
	Domain     string
	HumanLabel string
}

type prediction struct {
	CaseID      string  `json:"case_id"`
	Domain      string  `json:"domain"`
	HumanLabel  string  `json:"human_label"`
	Probability float64 `json:"probability"`
	WouldBlock  bool    `json:"would_block"`
}

type loadedSource struct {
	config    sourceConfig
	domains   map[string]struct{}
	stats     feed.ParseStats
	admission *feed.AdmissionStats
	age       time.Duration
	stale     bool
	expired   bool
}

type sourceReport struct {
	Name                       string               `json:"name"`
	SourceURL                  string               `json:"source_url"`
	SHA256                     string               `json:"sha256"`
	CollectedAt                string               `json:"collected_at"`
	AgeSeconds                 int64                `json:"age_seconds"`
	Stale                      bool                 `json:"stale"`
	Expired                    bool                 `json:"expired"`
	ParseStats                 feed.ParseStats      `json:"parse_stats"`
	Admission                  *feed.AdmissionStats `json:"admission,omitempty"`
	MatchedMalicious           int                  `json:"matched_malicious"`
	MatchedBenign              int                  `json:"matched_benign"`
	FeedOnlyRecoveredMalicious int                  `json:"feed_only_recovered_malicious"`
	ExactMatches               int                  `json:"exact_matches"`
	SuffixMatches              int                  `json:"suffix_matches"`
}

type coverageSummary struct {
	Cases              int `json:"cases"`
	ModelWouldBlock    int `json:"model_would_block"`
	FeedMatch          int `json:"feed_match"`
	CombinedWouldBlock int `json:"combined_would_block"`
	ModelAndFeed       int `json:"model_and_feed"`
	FeedOnly           int `json:"feed_only"`
	Neither            int `json:"neither"`
	TrustedBrandBypass int `json:"trusted_brand_bypass"`
	ExactFeedMatch     int `json:"exact_feed_match"`
	SuffixFeedMatch    int `json:"suffix_feed_match"`
}

type report struct {
	SchemaVersion                string                     `json:"schema_version"`
	AsOf                         string                     `json:"as_of"`
	ProtocolSHA256               string                     `json:"protocol_sha256"`
	Inputs                       map[string]string          `json:"input_integrity"`
	Policy                       map[string]any             `json:"policy"`
	Sources                      []sourceReport             `json:"sources"`
	Coverage                     map[string]coverageSummary `json:"coverage"`
	RecoveryRate                 float64                    `json:"malicious_feed_recovery_rate_of_model_false_negatives"`
	ResidualMalicious            int                        `json:"residual_malicious"`
	CombinedBenignFalsePositives int                        `json:"combined_benign_false_positives"`
	InvalidLabelRows             int                        `json:"invalid_label_rows"`
	Finding                      string                     `json:"finding"`
	Decision                     string                     `json:"decision"`
}

func main() {
	configPath := flag.String("config", "", "checksum-pinned threat-context evaluation protocol")
	outputPath := flag.String("output", "", "optional aggregate JSON report path")
	allowInvalidLabels := flag.Bool("allow-invalid-labels", false, "continue evaluation despite non-binary labels (they are counted in the report)")
	flag.Parse()
	if err := run(*configPath, *outputPath, *allowInvalidLabels); err != nil {
		fmt.Fprintln(os.Stderr, "threat context evaluation failed:", err)
		os.Exit(1)
	}
}

func run(configPath, outputPath string, allowInvalidLabels bool) error {
	if strings.TrimSpace(configPath) == "" {
		return errors.New("--config is required")
	}
	configData, configHash, err := readAndHash(configPath)
	if err != nil {
		return fmt.Errorf("read protocol: %w", err)
	}
	var cfg protocol
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return fmt.Errorf("parse protocol: %w", err)
	}
	if err := validateProtocol(cfg); err != nil {
		return err
	}
	asOf, _ := time.Parse(time.RFC3339, cfg.AsOf)

	cases, invalidLabelRows, labelsHash, err := readCases(cfg.Labels.Path)
	if err != nil {
		return err
	}
	if invalidLabelRows > 0 && !allowInvalidLabels {
		// A checksum-pinned labels file with non-binary labels silently
		// shrinks the evaluation set; fail loudly unless the operator
		// explicitly tolerates it.
		return fmt.Errorf("labels CSV contains %d rows with a non-binary human_label (benign/malicious expected); re-pin the reviewed CSV or pass --allow-invalid-labels", invalidLabelRows)
	}
	if !equalHash(labelsHash, cfg.Labels.SHA256) {
		return errors.New("labels SHA-256 mismatch")
	}
	if err := validateLabelCounts(cases, cfg.ExpectedLabels); err != nil {
		return err
	}
	predictions, predictionsHash, err := readPredictions(cfg.Predictions, cases)
	if err != nil {
		return err
	}

	sources := make([]loadedSource, 0, len(cfg.Sources))
	for _, source := range cfg.Sources {
		loaded, err := loadSource(source, cfg.AdmissionMode, asOf, time.Duration(cfg.StaleAfterHours)*time.Hour, time.Duration(cfg.FeedTTLHours)*time.Hour)
		if err != nil {
			return err
		}
		sources = append(sources, loaded)
	}

	rep := evaluate(cfg, configHash, labelsHash, predictionsHash, cases, predictions, sources)
	rep.InvalidLabelRows = invalidLabelRows
	encoded, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if outputPath != "" {
		if err := os.MkdirAll(filepath.Dir(outputPath), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(outputPath, encoded, 0o600); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
	}
	_, err = os.Stdout.Write(encoded)
	return err
}

func validateProtocol(cfg protocol) error {
	if cfg.SchemaVersion != reportSchemaVersion {
		return fmt.Errorf("unsupported protocol schema %q", cfg.SchemaVersion)
	}
	if _, err := time.Parse(time.RFC3339, cfg.AsOf); err != nil {
		return errors.New("protocol as_of must be RFC3339")
	}
	if cfg.FeedTTLHours <= 0 || cfg.StaleAfterHours <= 0 || cfg.StaleAfterHours > cfg.FeedTTLHours {
		return errors.New("protocol requires 0 < stale_after_hours <= feed_ttl_hours")
	}
	if len(cfg.Sources) == 0 {
		return errors.New("protocol requires at least one feed source")
	}
	if strings.TrimSpace(cfg.WhitelistState) == "" {
		return errors.New("protocol must declare the evaluated whitelist state")
	}
	if cfg.Predictions.Threshold <= 0 || cfg.Predictions.Threshold >= 1 {
		return errors.New("model prediction threshold must be between zero and one")
	}
	if _, err := feed.NormalizeAdmissionMode(string(cfg.AdmissionMode)); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(cfg.Sources))
	for _, source := range cfg.Sources {
		name := strings.TrimSpace(source.Name)
		if name == "" || strings.TrimSpace(source.Path) == "" || strings.TrimSpace(source.SHA256) == "" {
			return errors.New("every source requires name, path and SHA-256")
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("duplicate source name %q", name)
		}
		seen[name] = struct{}{}
	}
	return nil
}

func readCases(path string) ([]evaluationCase, int, string, error) {
	data, hash, err := readAndHash(path)
	if err != nil {
		return nil, 0, "", fmt.Errorf("read labels: %w", err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
	if err != nil || len(rows) < 2 {
		return nil, 0, "", errors.New("labels CSV is empty or invalid")
	}
	header := headerIndex(rows[0])
	for _, required := range []string{"case_id", "domain", "human_label", "reviewer_id"} {
		if _, ok := header[required]; !ok {
			return nil, 0, "", fmt.Errorf("labels CSV missing %s", required)
		}
	}
	var cases []evaluationCase
	invalidLabelRows := 0
	seen := make(map[string]struct{})
	for rowIndex, row := range rows[1:] {
		label := strings.ToLower(csvValue(row, header["human_label"]))
		if label != "benign" && label != "malicious" {
			invalidLabelRows++
			continue
		}
		caseID := csvValue(row, header["case_id"])
		domain, normalizeErr := analysis.NormalizeDomain(csvValue(row, header["domain"]))
		if caseID == "" || normalizeErr != nil || csvValue(row, header["reviewer_id"]) == "" {
			return nil, 0, "", fmt.Errorf("invalid reviewed binary label at row %d", rowIndex+2)
		}
		if _, ok := seen[caseID]; ok {
			return nil, 0, "", fmt.Errorf("duplicate case_id %q", caseID)
		}
		seen[caseID] = struct{}{}
		cases = append(cases, evaluationCase{CaseID: caseID, Domain: domain, HumanLabel: label})
	}
	return cases, invalidLabelRows, hash, nil
}

func readPredictions(ref predictionRef, cases []evaluationCase) (map[string]prediction, string, error) {
	data, hash, err := readAndHash(ref.Path)
	if err != nil {
		return nil, "", fmt.Errorf("read model predictions: %w", err)
	}
	if !equalHash(hash, ref.SHA256) {
		return nil, "", errors.New("model predictions SHA-256 mismatch")
	}
	wanted := make(map[string]evaluationCase, len(cases))
	for _, item := range cases {
		wanted[item.CaseID] = item
	}
	result := make(map[string]prediction, len(cases))
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		var row prediction
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return nil, "", fmt.Errorf("parse model prediction: %w", err)
		}
		item, ok := wanted[row.CaseID]
		domain, normalizeErr := analysis.NormalizeDomain(row.Domain)
		if !ok || normalizeErr != nil || domain != item.Domain || strings.ToLower(row.HumanLabel) != item.HumanLabel {
			return nil, "", fmt.Errorf("model prediction does not match signed case %q", row.CaseID)
		}
		if math.IsNaN(row.Probability) || math.IsInf(row.Probability, 0) || row.Probability < 0 || row.Probability > 1 {
			return nil, "", fmt.Errorf("invalid probability for %q", row.CaseID)
		}
		if row.WouldBlock != (row.Probability >= ref.Threshold) {
			return nil, "", fmt.Errorf("threshold action mismatch for %q", row.CaseID)
		}
		if _, duplicate := result[row.CaseID]; duplicate {
			return nil, "", fmt.Errorf("duplicate model prediction %q", row.CaseID)
		}
		result[row.CaseID] = row
	}
	if err := scanner.Err(); err != nil {
		return nil, "", err
	}
	if len(result) != len(cases) {
		return nil, "", fmt.Errorf("model predictions cover %d/%d binary cases", len(result), len(cases))
	}
	return result, hash, nil
}

func loadSource(cfg sourceConfig, admissionMode feed.AdmissionMode, asOf time.Time, staleAfter, ttl time.Duration) (loadedSource, error) {
	data, hash, err := readAndHash(cfg.Path)
	if err != nil {
		return loadedSource{}, fmt.Errorf("read source %s: %w", cfg.Name, err)
	}
	if !equalHash(hash, cfg.SHA256) {
		return loadedSource{}, fmt.Errorf("source %s SHA-256 mismatch", cfg.Name)
	}
	collectedAt, err := time.Parse(time.RFC3339, cfg.CollectedAt)
	if err != nil {
		return loadedSource{}, fmt.Errorf("source %s collected_at must be RFC3339", cfg.Name)
	}
	age := asOf.Sub(collectedAt)
	if age < 0 {
		return loadedSource{}, fmt.Errorf("source %s was collected after as_of", cfg.Name)
	}
	mode, _ := feed.NormalizeAdmissionMode(string(admissionMode))
	plan, err := feed.PlanAdmission(strings.NewReader(string(data)), mode)
	if err != nil {
		return loadedSource{}, fmt.Errorf("parse source %s: %w", cfg.Name, err)
	}
	selected := plan.Authoritative
	if mode == feed.AdmissionShadow {
		selected = append(selected, plan.Contextual...)
	}
	domains := make(map[string]struct{}, len(selected))
	for _, domain := range selected {
		domains[domain] = struct{}{}
	}
	return loadedSource{config: cfg, domains: domains, stats: plan.ParseStats, admission: &plan.Stats, age: age, stale: age > staleAfter, expired: age > ttl}, nil
}

func evaluate(cfg protocol, protocolHash, labelsHash, predictionsHash string, cases []evaluationCase, predictions map[string]prediction, sources []loadedSource) report {
	coverage := map[string]coverageSummary{"malicious": {}, "benign": {}}
	sourceReports := make([]sourceReport, len(sources))
	for index, source := range sources {
		sourceReports[index] = sourceReport{Name: source.config.Name, SourceURL: source.config.SourceURL, SHA256: source.config.SHA256, CollectedAt: source.config.CollectedAt, AgeSeconds: int64(source.age / time.Second), Stale: source.stale, Expired: source.expired, ParseStats: source.stats, Admission: source.admission}
	}

	for _, item := range cases {
		prediction := predictions[item.CaseID]
		summary := coverage[item.HumanLabel]
		summary.Cases++
		if prediction.WouldBlock {
			summary.ModelWouldBlock++
		}
		bypassed := analysis.IsTrustedBrandSuffix(item.Domain, analysis.DefaultTrustedBrands())
		if bypassed {
			summary.TrustedBrandBypass++
		}
		feedMatched, exactMatched := false, false
		for index, source := range sources {
			if source.expired || bypassed {
				continue
			}
			candidate, exact := matchSource(item.Domain, source.domains)
			if candidate == "" {
				continue
			}
			feedMatched = true
			exactMatched = exactMatched || exact
			if item.HumanLabel == "malicious" {
				sourceReports[index].MatchedMalicious++
				if !prediction.WouldBlock {
					sourceReports[index].FeedOnlyRecoveredMalicious++
				}
			} else {
				sourceReports[index].MatchedBenign++
			}
			if exact {
				sourceReports[index].ExactMatches++
			} else {
				sourceReports[index].SuffixMatches++
			}
		}
		if feedMatched {
			summary.FeedMatch++
			if exactMatched {
				summary.ExactFeedMatch++
			} else {
				summary.SuffixFeedMatch++
			}
		}
		switch {
		case prediction.WouldBlock && feedMatched:
			summary.ModelAndFeed++
			summary.CombinedWouldBlock++
		case prediction.WouldBlock:
			summary.CombinedWouldBlock++
		case feedMatched:
			summary.FeedOnly++
			summary.CombinedWouldBlock++
		default:
			summary.Neither++
		}
		coverage[item.HumanLabel] = summary
	}

	malicious := coverage["malicious"]
	modelFalseNegatives := malicious.Cases - malicious.ModelWouldBlock
	recoveryRate := 0.0
	if modelFalseNegatives > 0 {
		recoveryRate = float64(malicious.FeedOnly) / float64(modelFalseNegatives)
	}
	benign := coverage["benign"]
	finding := "INCREMENTAL_CONTEXT_COVERAGE"
	if malicious.FeedOnly == 0 && benign.FeedOnly > 0 {
		finding = "NO_INCREMENTAL_MALICIOUS_RECALL_WITH_BENIGN_COLLISION"
	} else if malicious.FeedOnly == 0 {
		finding = "NO_INCREMENTAL_CONTEXT_COVERAGE"
	}
	sort.Slice(sourceReports, func(i, j int) bool { return sourceReports[i].Name < sourceReports[j].Name })
	return report{
		SchemaVersion:                reportSchemaVersion,
		AsOf:                         cfg.AsOf,
		ProtocolSHA256:               protocolHash,
		Inputs:                       map[string]string{"labels_sha256": labelsHash, "model_predictions_sha256": predictionsHash, "model_sha256": cfg.Predictions.ModelSHA256},
		Policy:                       map[string]any{"feed_ttl_hours": cfg.FeedTTLHours, "stale_after_hours": cfg.StaleAfterHours, "matching": "exact_then_parent_suffix", "feed_parser_semantics": "URL scope preserved before admission", "admission_mode": cfg.AdmissionMode, "trusted_brand_policy": "analysis.DefaultTrustedBrands", "whitelist_state": cfg.WhitelistState, "source_attribution_counts_are_non_exclusive": true},
		Sources:                      sourceReports,
		Coverage:                     coverage,
		RecoveryRate:                 recoveryRate,
		ResidualMalicious:            malicious.Neither,
		CombinedBenignFalsePositives: benign.CombinedWouldBlock,
		Finding:                      finding,
		Decision:                     "MEASUREMENT_ONLY_MODEL_REMAINS_NO_GO",
	}
}

func matchSource(domain string, domains map[string]struct{}) (string, bool) {
	for index, candidate := range risk.ThreatFeedCandidates(domain) {
		if _, ok := domains[candidate]; ok {
			return candidate, index == 0
		}
	}
	return "", false
}

func validateLabelCounts(cases []evaluationCase, expected map[string]int) error {
	counts := map[string]int{"malicious": 0, "benign": 0}
	for _, item := range cases {
		counts[item.HumanLabel]++
	}
	for _, label := range []string{"malicious", "benign"} {
		if expected[label] <= 0 || counts[label] != expected[label] {
			return fmt.Errorf("%s labels count %d does not match expected %d", label, counts[label], expected[label])
		}
	}
	return nil
}

func headerIndex(row []string) map[string]int {
	result := make(map[string]int, len(row))
	for index, value := range row {
		result[strings.TrimSpace(value)] = index
	}
	return result
}

func csvValue(row []string, index int) string {
	if index < 0 || index >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[index])
}

func readAndHash(path string) ([]byte, string, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), nil
}

func equalHash(left, right string) bool {
	return strings.EqualFold(strings.TrimSpace(left), strings.TrimSpace(right))
}
