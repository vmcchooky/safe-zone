package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
	"safe-zone/internal/safefile"
)

const (
	exportSchemaVersion = "safe-zone.ml-targeted-benign-candidates.v1"
	maxResponseBytes    = 4 << 20
	queuePageSize       = 100
)

type queueReport struct {
	ID               int64  `json:"id"`
	Domain           string `json:"domain"`
	Status           string `json:"status"`
	ReviewReason     string `json:"review_reason"`
	ReviewedBy       string `json:"reviewed_by"`
	ReviewedAt       string `json:"reviewed_at"`
	ResolutionAction string `json:"resolution_action"`
}

type queueCounts struct {
	Pending  int `json:"pending"`
	Resolved int `json:"resolved"`
	Rejected int `json:"rejected"`
}

type queueResponse struct {
	Reports []queueReport `json:"reports"`
	Total   int           `json:"total"`
	Counts  queueCounts   `json:"counts"`
}

type brandResponse struct {
	Items []analysis.Brand `json:"items"`
}

type runtimeStatus struct {
	AnalysisConfig struct {
		Revision string `json:"revision"`
	} `json:"analysis_config_reload"`
	ML struct {
		Mode           analysis.MLMode `json:"ml_mode"`
		Enabled        bool            `json:"ml_enabled"`
		ModelVersion   string          `json:"ml_model_version"`
		Revision       string          `json:"ml_revision"`
		BlockThreshold float64         `json:"ml_block_threshold"`
		State          string          `json:"ml_state"`
	} `json:"ml"`
}

type apiSnapshot struct {
	Reports          []queueReport
	Counts           queueCounts
	Total            int
	AnalysisConfig   config.AnalysisConfig
	ConfigRevision   string
	Brands           []analysis.Brand
	RuntimeMLMode    analysis.MLMode
	RuntimeMLState   string
	RuntimeModel     string
	RuntimeRevision  string
	RuntimeThreshold float64
}

type domainAnalyzer interface {
	Analyze(string) analysis.Result
}

type domainClassifier interface {
	Classify(string) (analysis.MLDecision, error)
}

type candidateRow struct {
	CaseID                  string
	Domain                  string
	SourceReportIDs         string
	ReviewedBy              string
	ReviewedAt              string
	LexicalVerdict          analysis.Verdict
	LexicalScore            int
	LexicalConfidence       float64
	ModelRevision           string
	ModelThreshold          float64
	ShadowProbability       float64
	DeterministicWouldBlock bool
}

type selectionStats struct {
	SourceReports            int            `json:"source_reports"`
	EligibleAllowReports     int            `json:"eligible_allow_reports"`
	UniqueEligibleDomains    int            `json:"unique_eligible_domains"`
	DuplicateReports         int            `json:"duplicate_reports"`
	InvalidProvenanceReports int            `json:"invalid_provenance_reports"`
	InvalidDomainReports     int            `json:"invalid_domain_reports"`
	ExcludedLexicalVerdicts  map[string]int `json:"excluded_lexical_verdicts"`
	CandidateDomains         int            `json:"candidate_domains"`
	WouldBlock               int            `json:"would_block"`
	WouldPass                int            `json:"would_pass"`
	ObservedFPR              *float64       `json:"observed_fpr,omitempty"`
}

type exportManifest struct {
	SchemaVersion          string          `json:"schema_version"`
	GeneratedAt            string          `json:"generated_at"`
	Status                 string          `json:"status"`
	SourceCommit           string          `json:"source_commit"`
	SourceEndpoint         string          `json:"source_endpoint"`
	QueueCounts            queueCounts     `json:"queue_counts"`
	QueueResolvedTotal     int             `json:"queue_resolved_total"`
	AnalysisConfigRevision string          `json:"analysis_config_revision"`
	AnalysisConfigSHA256   string          `json:"analysis_config_sha256"`
	TrustedBrandsSHA256    string          `json:"trusted_brands_sha256"`
	BundleSHA256SHash      string          `json:"bundle_sha256s_sha256"`
	ModelVersion           string          `json:"model_version"`
	ModelRevision          string          `json:"model_revision"`
	ModelThreshold         float64         `json:"model_threshold"`
	RuntimeMode            analysis.MLMode `json:"runtime_mode"`
	MinimumCandidates      int             `json:"minimum_candidates"`
	LabelsSHA256           string          `json:"labels_sha256,omitempty"`
	Statistics             selectionStats  `json:"statistics"`
	Privacy                []string        `json:"privacy_guarantees"`
}

type runResult struct {
	OutputDir  string
	Manifest   exportManifest
	LabelsPath string
}

type reportGroup struct {
	Domain       string
	ReportIDs    []int64
	Reviewers    map[string]struct{}
	LatestReview string
}

func main() {
	var (
		apiURL        string
		apiKeyFile    string
		bundleDir     string
		outputDir     string
		sourceCommit  string
		minCandidates int
		timeout       time.Duration
		maxReports    int
	)
	flag.StringVar(&apiURL, "api-url", "http://127.0.0.1:8080", "Core API base URL")
	flag.StringVar(&apiKeyFile, "admin-api-key-file", "", "file containing the admin API key")
	flag.StringVar(&bundleDir, "bundle", "", "verified model bundle directory")
	flag.StringVar(&outputDir, "output", "", "new private output directory")
	flag.StringVar(&sourceCommit, "source-commit", "", "exact 40-character Git commit under evaluation")
	flag.IntVar(&minCandidates, "min-candidates", 25, "minimum targeted benign ML candidates required")
	flag.DurationVar(&timeout, "timeout", 30*time.Second, "overall read-only API timeout")
	flag.IntVar(&maxReports, "max-reports", 10000, "maximum resolved queue records accepted")
	flag.Parse()

	result, err := run(context.Background(), runOptions{
		APIURL:        apiURL,
		APIKeyFile:    apiKeyFile,
		BundleDir:     bundleDir,
		OutputDir:     outputDir,
		SourceCommit:  sourceCommit,
		MinCandidates: minCandidates,
		Timeout:       timeout,
		MaxReports:    maxReports,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "targeted benign candidate export failed:", err)
		os.Exit(1)
	}
	fmt.Printf("manifest: %s\n", filepath.Join(result.OutputDir, "manifest.json"))
	if result.LabelsPath != "" {
		fmt.Printf("labels: %s\n", result.LabelsPath)
	}
	fmt.Printf("status=%s candidates=%d minimum=%d would_block=%d\n",
		result.Manifest.Status,
		result.Manifest.Statistics.CandidateDomains,
		result.Manifest.MinimumCandidates,
		result.Manifest.Statistics.WouldBlock,
	)
	if result.Manifest.Status != "ready" {
		os.Exit(2)
	}
}

type runOptions struct {
	APIURL        string
	APIKeyFile    string
	BundleDir     string
	OutputDir     string
	SourceCommit  string
	MinCandidates int
	Timeout       time.Duration
	MaxReports    int
}

func run(parent context.Context, options runOptions) (runResult, error) {
	if !validCommit(options.SourceCommit) {
		return runResult{}, errors.New("--source-commit must be an exact 40-character hexadecimal Git commit")
	}
	if strings.TrimSpace(options.BundleDir) == "" || strings.TrimSpace(options.OutputDir) == "" {
		return runResult{}, errors.New("--bundle and --output are required")
	}
	if options.MinCandidates < 1 || options.MinCandidates > 100000 {
		return runResult{}, errors.New("--min-candidates must be between 1 and 100000")
	}
	if options.MaxReports < 1 || options.MaxReports > 1000000 {
		return runResult{}, errors.New("--max-reports must be between 1 and 1000000")
	}
	if options.Timeout <= 0 || options.Timeout > 10*time.Minute {
		return runResult{}, errors.New("--timeout must be greater than zero and at most 10m")
	}

	baseURL, err := validateBaseURL(options.APIURL)
	if err != nil {
		return runResult{}, err
	}
	apiKey, err := readAdminAPIKey(options.APIKeyFile)
	if err != nil {
		return runResult{}, err
	}
	if len(apiKey) < 16 {
		return runResult{}, errors.New("admin API key is empty or invalid")
	}

	ctx, cancel := context.WithTimeout(parent, options.Timeout)
	defer cancel()
	client := &http.Client{
		Timeout: options.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirects are disabled for authenticated queue export")
		},
	}
	snapshot, err := fetchAPISnapshot(ctx, client, baseURL, apiKey, options.MaxReports)
	if err != nil {
		return runResult{}, err
	}

	classifier, err := analysis.NewBundleClassifier(options.BundleDir)
	if err != nil {
		return runResult{}, fmt.Errorf("load verified model bundle: %w", err)
	}
	if snapshot.RuntimeMLMode != analysis.MLModeShadow || snapshot.RuntimeMLState != "ready" {
		return runResult{}, fmt.Errorf("runtime must be shadow/ready, got %s/%s", snapshot.RuntimeMLMode, snapshot.RuntimeMLState)
	}
	if classifier.Revision() != snapshot.RuntimeRevision || classifier.ModelVersion() != snapshot.RuntimeModel || classifier.BlockThreshold() != snapshot.RuntimeThreshold {
		return runResult{}, fmt.Errorf("runtime and local bundle do not match: runtime revision=%s version=%s threshold=%g, local revision=%s version=%s threshold=%g",
			snapshot.RuntimeRevision, snapshot.RuntimeModel, snapshot.RuntimeThreshold,
			classifier.Revision(), classifier.ModelVersion(), classifier.BlockThreshold())
	}

	brandStore := analysis.NewMemoryBrandStore(snapshot.Brands)
	analyzer := analysis.NewAnalyzerWithBrandStore(snapshot.AnalysisConfig, brandStore)
	rows, stats, err := selectCandidates(snapshot.Reports, analyzer, classifier, classifier.Revision(), classifier.BlockThreshold())
	if err != nil {
		return runResult{}, err
	}

	configBytes, err := json.Marshal(snapshot.AnalysisConfig.Clone())
	if err != nil {
		return runResult{}, fmt.Errorf("encode analysis config provenance: %w", err)
	}
	brands := append([]analysis.Brand(nil), snapshot.Brands...)
	sort.Slice(brands, func(i, j int) bool {
		if brands[i].Name == brands[j].Name {
			return brands[i].OfficialDomain < brands[j].OfficialDomain
		}
		return brands[i].Name < brands[j].Name
	})
	brandBytes, err := json.Marshal(brands)
	if err != nil {
		return runResult{}, fmt.Errorf("encode trusted brand provenance: %w", err)
	}
	bundleHash, err := hashBundleManifest(options.BundleDir)
	if err != nil {
		return runResult{}, err
	}

	status := "ready"
	if stats.SourceReports == 0 {
		status = "empty_queue"
	} else if stats.CandidateDomains < options.MinCandidates {
		status = "insufficient_candidates"
	}
	manifest := exportManifest{
		SchemaVersion:          exportSchemaVersion,
		GeneratedAt:            time.Now().UTC().Format(time.RFC3339Nano),
		Status:                 status,
		SourceCommit:           strings.ToLower(options.SourceCommit),
		SourceEndpoint:         baseURL + "/v1/reports?status=resolved",
		QueueCounts:            snapshot.Counts,
		QueueResolvedTotal:     snapshot.Total,
		AnalysisConfigRevision: snapshot.ConfigRevision,
		AnalysisConfigSHA256:   hashBytes(configBytes),
		TrustedBrandsSHA256:    hashBytes(brandBytes),
		BundleSHA256SHash:      bundleHash,
		ModelVersion:           classifier.ModelVersion(),
		ModelRevision:          classifier.Revision(),
		ModelThreshold:         classifier.BlockThreshold(),
		RuntimeMode:            snapshot.RuntimeMLMode,
		MinimumCandidates:      options.MinCandidates,
		Statistics:             stats,
		Privacy: []string{
			"contact is never exported",
			"report note is never exported",
			"review reason is validated but never exported",
			"only resolved allow decisions with reviewer provenance are eligible",
		},
	}

	labels, err := encodeLabels(rows)
	if err != nil {
		return runResult{}, err
	}
	if len(rows) > 0 {
		manifest.LabelsSHA256 = hashBytes(labels)
	}
	result, err := writeExport(options.OutputDir, manifest, labels, len(rows) > 0)
	if err != nil {
		return runResult{}, err
	}
	return result, nil
}

func readAdminAPIKey(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		value := strings.TrimSpace(os.Getenv("SAFE_ZONE_ADMIN_API_KEY"))
		if value == "" {
			return "", errors.New("--admin-api-key-file or SAFE_ZONE_ADMIN_API_KEY is required")
		}
		return value, nil
	}
	keyData, err := safefile.ReadFileWithin(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return "", fmt.Errorf("read admin API key: %w", err)
	}
	return strings.TrimSpace(string(keyData)), nil
}

func validateBaseURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("--api-url must be an absolute HTTP(S) URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("--api-url must use http or https")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("--api-url must not contain credentials, query, or fragment")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return strings.TrimRight(parsed.String(), "/"), nil
}

func fetchAPISnapshot(ctx context.Context, client *http.Client, baseURL, apiKey string, maxReports int) (apiSnapshot, error) {
	startStatus, err := fetchStatus(ctx, client, baseURL, apiKey)
	if err != nil {
		return apiSnapshot{}, err
	}
	if startStatus.ML.Mode != analysis.MLModeShadow || !startStatus.ML.Enabled || startStatus.ML.State != "ready" {
		return apiSnapshot{}, fmt.Errorf("runtime ML must be shadow/ready/enabled, got mode=%s state=%s enabled=%t", startStatus.ML.Mode, startStatus.ML.State, startStatus.ML.Enabled)
	}

	var cfg config.AnalysisConfig
	if err := getJSON(ctx, client, baseURL+"/v1/config/analysis", apiKey, &cfg); err != nil {
		return apiSnapshot{}, fmt.Errorf("fetch runtime analysis config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return apiSnapshot{}, fmt.Errorf("validate runtime analysis config: %w", err)
	}
	if got := analysisConfigRevision(cfg); got != startStatus.AnalysisConfig.Revision {
		return apiSnapshot{}, fmt.Errorf("analysis config revision mismatch: status=%s fetched=%s", startStatus.AnalysisConfig.Revision, got)
	}

	var brandPayload brandResponse
	if err := getJSON(ctx, client, baseURL+"/v1/brands", apiKey, &brandPayload); err != nil {
		return apiSnapshot{}, fmt.Errorf("fetch trusted brands: %w", err)
	}
	if brandPayload.Items == nil {
		brandPayload.Items = []analysis.Brand{}
	}

	reports, total, counts, err := fetchResolvedReports(ctx, client, baseURL, apiKey, maxReports)
	if err != nil {
		return apiSnapshot{}, err
	}
	endStatus, err := fetchStatus(ctx, client, baseURL, apiKey)
	if err != nil {
		return apiSnapshot{}, err
	}
	if startStatus.AnalysisConfig.Revision != endStatus.AnalysisConfig.Revision ||
		startStatus.ML.Mode != endStatus.ML.Mode || startStatus.ML.State != endStatus.ML.State ||
		startStatus.ML.Revision != endStatus.ML.Revision || startStatus.ML.ModelVersion != endStatus.ML.ModelVersion ||
		startStatus.ML.BlockThreshold != endStatus.ML.BlockThreshold {
		return apiSnapshot{}, errors.New("runtime contract changed during export; retry against a stable snapshot")
	}

	return apiSnapshot{
		Reports:          reports,
		Counts:           counts,
		Total:            total,
		AnalysisConfig:   cfg,
		ConfigRevision:   startStatus.AnalysisConfig.Revision,
		Brands:           brandPayload.Items,
		RuntimeMLMode:    startStatus.ML.Mode,
		RuntimeMLState:   startStatus.ML.State,
		RuntimeModel:     startStatus.ML.ModelVersion,
		RuntimeRevision:  startStatus.ML.Revision,
		RuntimeThreshold: startStatus.ML.BlockThreshold,
	}, nil
}

func fetchStatus(ctx context.Context, client *http.Client, baseURL, apiKey string) (runtimeStatus, error) {
	var status runtimeStatus
	if err := getJSON(ctx, client, baseURL+"/v1/status", apiKey, &status); err != nil {
		return runtimeStatus{}, fmt.Errorf("fetch runtime status: %w", err)
	}
	return status, nil
}

func fetchResolvedReports(ctx context.Context, client *http.Client, baseURL, apiKey string, maxReports int) ([]queueReport, int, queueCounts, error) {
	reports := make([]queueReport, 0)
	seenIDs := make(map[int64]struct{})
	expectedTotal := -1
	var expectedCounts queueCounts
	for offset := 0; ; offset += queuePageSize {
		endpoint := fmt.Sprintf("%s/v1/reports?status=resolved&limit=%d&offset=%d", baseURL, queuePageSize, offset)
		var page queueResponse
		if err := getJSON(ctx, client, endpoint, apiKey, &page); err != nil {
			return nil, 0, queueCounts{}, fmt.Errorf("fetch resolved false-positive queue: %w", err)
		}
		if expectedTotal < 0 {
			expectedTotal = page.Total
			expectedCounts = page.Counts
			if expectedTotal > maxReports {
				return nil, 0, queueCounts{}, fmt.Errorf("resolved queue contains %d records, exceeds --max-reports=%d", expectedTotal, maxReports)
			}
		} else if page.Total != expectedTotal || page.Counts != expectedCounts {
			return nil, 0, queueCounts{}, errors.New("false-positive queue changed during pagination; retry")
		}
		for _, report := range page.Reports {
			if _, exists := seenIDs[report.ID]; exists {
				return nil, 0, queueCounts{}, fmt.Errorf("duplicate report ID %d across queue pages", report.ID)
			}
			seenIDs[report.ID] = struct{}{}
			reports = append(reports, report)
		}
		if len(reports) >= expectedTotal {
			break
		}
		if len(page.Reports) == 0 {
			return nil, 0, queueCounts{}, fmt.Errorf("queue pagination ended at %d of %d records", len(reports), expectedTotal)
		}
	}
	if len(reports) != expectedTotal {
		return nil, 0, queueCounts{}, fmt.Errorf("queue snapshot returned %d records, expected %d", len(reports), expectedTotal)
	}
	return reports, expectedTotal, expectedCounts, nil
}

func getJSON(ctx context.Context, client *http.Client, endpoint, apiKey string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	limited := io.LimitReader(resp.Body, maxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(body) > maxResponseBytes {
		return errors.New("API response exceeds 4 MiB limit")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode API response: %w", err)
	}
	return nil
}

func selectCandidates(reports []queueReport, analyzer domainAnalyzer, classifier domainClassifier, modelRevision string, threshold float64) ([]candidateRow, selectionStats, error) {
	stats := selectionStats{SourceReports: len(reports), ExcludedLexicalVerdicts: make(map[string]int)}
	groups := make(map[string]*reportGroup)
	for _, report := range reports {
		if report.ID <= 0 || strings.TrimSpace(report.Status) != "resolved" || strings.TrimSpace(report.ResolutionAction) != "allow" ||
			strings.TrimSpace(report.ReviewedBy) == "" || strings.TrimSpace(report.ReviewedAt) == "" || len(strings.TrimSpace(report.ReviewReason)) < 8 {
			stats.InvalidProvenanceReports++
			continue
		}
		normalized, err := analysis.NormalizeDomain(report.Domain)
		if err != nil {
			stats.InvalidDomainReports++
			continue
		}
		stats.EligibleAllowReports++
		group := groups[normalized]
		if group == nil {
			group = &reportGroup{Domain: normalized, Reviewers: make(map[string]struct{})}
			groups[normalized] = group
		} else {
			stats.DuplicateReports++
		}
		group.ReportIDs = append(group.ReportIDs, report.ID)
		group.Reviewers[strings.TrimSpace(report.ReviewedBy)] = struct{}{}
		if strings.TrimSpace(report.ReviewedAt) > group.LatestReview {
			group.LatestReview = strings.TrimSpace(report.ReviewedAt)
		}
	}
	stats.UniqueEligibleDomains = len(groups)

	domains := make([]string, 0, len(groups))
	for domain := range groups {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	rows := make([]candidateRow, 0, len(domains))
	seenCaseIDs := make(map[string]struct{})
	for _, domain := range domains {
		lexical := analyzer.Analyze(domain)
		if lexical.Verdict != analysis.VerdictSuspicious {
			stats.ExcludedLexicalVerdicts[string(lexical.Verdict)]++
			continue
		}
		decision, err := classifier.Classify(domain)
		if err != nil {
			return nil, stats, fmt.Errorf("classify targeted candidate %s: %w", domain, err)
		}
		group := groups[domain]
		sort.Slice(group.ReportIDs, func(i, j int) bool { return group.ReportIDs[i] < group.ReportIDs[j] })
		reviewers := make([]string, 0, len(group.Reviewers))
		for reviewer := range group.Reviewers {
			reviewers = append(reviewers, reviewer)
		}
		sort.Strings(reviewers)
		caseID := candidateCaseID(domain)
		if _, exists := seenCaseIDs[caseID]; exists {
			return nil, stats, fmt.Errorf("candidate case ID collision for %s", domain)
		}
		seenCaseIDs[caseID] = struct{}{}
		wouldBlock := decision.Action == analysis.MLActionPromoteMalicious
		if wouldBlock {
			stats.WouldBlock++
		} else {
			stats.WouldPass++
		}
		rows = append(rows, candidateRow{
			CaseID:                  caseID,
			Domain:                  domain,
			SourceReportIDs:         joinInt64(group.ReportIDs),
			ReviewedBy:              strings.Join(reviewers, ";"),
			ReviewedAt:              group.LatestReview,
			LexicalVerdict:          lexical.Verdict,
			LexicalScore:            lexical.Score,
			LexicalConfidence:       lexical.Confidence,
			ModelRevision:           modelRevision,
			ModelThreshold:          threshold,
			ShadowProbability:       decision.Probability,
			DeterministicWouldBlock: wouldBlock,
		})
	}
	stats.CandidateDomains = len(rows)
	if len(rows) > 0 {
		fpr := float64(stats.WouldBlock) / float64(len(rows))
		stats.ObservedFPR = &fpr
	}
	return rows, stats, nil
}

func encodeLabels(rows []candidateRow) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	header := []string{
		"case_id", "domain", "human_label", "source", "source_report_ids", "reviewed_by", "reviewed_at",
		"lexical_verdict", "lexical_score", "lexical_confidence", "model_revision", "model_threshold",
		"shadow_probability", "deterministic_would_block",
	}
	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("write labels header: %w", err)
	}
	for _, row := range rows {
		record := []string{
			row.CaseID,
			row.Domain,
			"benign",
			"false_positive_queue",
			row.SourceReportIDs,
			row.ReviewedBy,
			row.ReviewedAt,
			string(row.LexicalVerdict),
			strconv.Itoa(row.LexicalScore),
			strconv.FormatFloat(row.LexicalConfidence, 'g', -1, 64),
			row.ModelRevision,
			strconv.FormatFloat(row.ModelThreshold, 'g', -1, 64),
			strconv.FormatFloat(row.ShadowProbability, 'g', -1, 64),
			strconv.FormatBool(row.DeterministicWouldBlock),
		}
		if err := writer.Write(record); err != nil {
			return nil, fmt.Errorf("write candidate %s: %w", row.CaseID, err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("encode targeted labels: %w", err)
	}
	return buffer.Bytes(), nil
}

func writeExport(outputDir string, manifest exportManifest, labels []byte, writeLabels bool) (runResult, error) {
	target, err := filepath.Abs(strings.TrimSpace(outputDir))
	if err != nil || strings.TrimSpace(outputDir) == "" {
		return runResult{}, errors.New("invalid --output directory")
	}
	if info, statErr := os.Stat(target); statErr == nil {
		return runResult{}, fmt.Errorf("output directory already exists: %s (%s)", target, info.Mode())
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return runResult{}, fmt.Errorf("inspect output directory: %w", statErr)
	}
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return runResult{}, fmt.Errorf("create output parent: %w", err)
	}
	staging, err := os.MkdirTemp(parent, ".ml-fp-candidates-")
	if err != nil {
		return runResult{}, fmt.Errorf("create staging output: %w", err)
	}
	defer func() { _ = os.RemoveAll(staging) }()

	labelsPath := ""
	if writeLabels {
		labelsPath = filepath.Join(staging, "labels.csv")
		if err := os.WriteFile(labelsPath, labels, 0o600); err != nil {
			return runResult{}, fmt.Errorf("write labels: %w", err)
		}
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return runResult{}, fmt.Errorf("encode manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(filepath.Join(staging, "manifest.json"), manifestBytes, 0o600); err != nil {
		return runResult{}, fmt.Errorf("write manifest: %w", err)
	}
	if err := os.Rename(staging, target); err != nil {
		return runResult{}, fmt.Errorf("activate output directory: %w", err)
	}
	result := runResult{OutputDir: target, Manifest: manifest}
	if writeLabels {
		result.LabelsPath = filepath.Join(target, "labels.csv")
	}
	return result, nil
}

func analysisConfigRevision(cfg config.AnalysisConfig) string {
	encoded, _ := json.Marshal(cfg.Clone())
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:8])
}

func hashBundleManifest(bundleDir string) (string, error) {
	data, err := safefile.ReadFileWithin(bundleDir, "SHA256SUMS")
	if err != nil {
		return "", fmt.Errorf("read bundle SHA256SUMS: %w", err)
	}
	return hashBytes(data), nil
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func candidateCaseID(domain string) string {
	sum := sha256.Sum256([]byte(domain))
	return "fpq-" + hex.EncodeToString(sum[:8])
}

func joinInt64(values []int64) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = strconv.FormatInt(value, 10)
	}
	return strings.Join(parts, ";")
}

func validCommit(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 40 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
