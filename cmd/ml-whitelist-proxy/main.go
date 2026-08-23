package main

import (
	"bufio"
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
	"math"
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
	reportSchemaVersion = "safe-zone.ml-whitelist-proxy-replay.v1"
	maxResponseBytes    = 4 << 20
)

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

type brandResponse struct {
	Items []analysis.Brand `json:"items"`
}

type dataManifest struct {
	ManifestVersion int         `json:"manifest_version"`
	PipelineGitSHA  string      `json:"pipeline_git_sha"`
	GeneratedAt     string      `json:"generated_at"`
	RawSources      []rawSource `json:"raw_sources"`
}

type rawSource struct {
	LogicalName   string `json:"logical_name"`
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	Bytes         int64  `json:"bytes"`
	RetrievedAt   string `json:"retrieved_at"`
	TrustTier     string `json:"trust_tier"`
	TermsReviewID string `json:"terms_review_id"`
}

type apiSnapshot struct {
	Config         config.AnalysisConfig
	ConfigRevision string
	Brands         []analysis.Brand
	Status         runtimeStatus
}

type candidateRow struct {
	CaseID            string
	Domain            string
	LexicalScore      int
	LexicalConfidence float64
	LexicalReasons    string
	Probability       float64
	Threshold         float64
	WouldBlock        bool
	NearThreshold     bool
}

type domainAnalyzer interface {
	Analyze(string) analysis.Result
}

type domainClassifier interface {
	Classify(string) (analysis.MLDecision, error)
	BlockThreshold() float64
}

type sourceProvenance struct {
	LogicalName        string `json:"logical_name"`
	Path               string `json:"path"`
	SHA256             string `json:"sha256"`
	Bytes              int64  `json:"bytes"`
	RetrievedAt        string `json:"retrieved_at"`
	TrustTier          string `json:"trust_tier"`
	TermsReviewID      string `json:"terms_review_id"`
	DataManifest       string `json:"data_manifest"`
	DataManifestSHA256 string `json:"data_manifest_sha256"`
	PipelineGitSHA     string `json:"pipeline_git_sha"`
	ManifestGenerated  string `json:"manifest_generated_at"`
}

type statistics struct {
	SourceLines                   int      `json:"source_lines"`
	BlankLines                    int      `json:"blank_lines"`
	InvalidDomains                int      `json:"invalid_domains"`
	DuplicateDomains              int      `json:"duplicate_domains"`
	UniqueProxyBenignDomains      int      `json:"unique_proxy_benign_domains"`
	LexicalSafe                   int      `json:"lexical_safe"`
	LexicalSuspicious             int      `json:"lexical_suspicious"`
	LexicalMalicious              int      `json:"lexical_malicious"`
	MLCandidateDomains            int      `json:"ml_candidate_domains"`
	WouldBlock                    int      `json:"would_block"`
	WouldPass                     int      `json:"would_pass"`
	NearThreshold                 int      `json:"near_threshold"`
	WhitelistProxyFPR             *float64 `json:"whitelist_proxy_fpr,omitempty"`
	CandidateConditionalBlockRate *float64 `json:"candidate_conditional_block_rate,omitempty"`
}

type outputFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Rows   int    `json:"rows"`
}

type replayManifest struct {
	SchemaVersion          string           `json:"schema_version"`
	GeneratedAt            string           `json:"generated_at"`
	SourceCommit           string           `json:"source_commit"`
	EvaluationKind         string           `json:"evaluation_kind"`
	Source                 sourceProvenance `json:"source"`
	AnalysisConfigRevision string           `json:"analysis_config_revision"`
	AnalysisConfigSHA256   string           `json:"analysis_config_sha256"`
	TrustedBrandsSHA256    string           `json:"trusted_brands_sha256"`
	BundleSHA256SHash      string           `json:"bundle_sha256s_sha256"`
	ModelVersion           string           `json:"model_version"`
	ModelRevision          string           `json:"model_revision"`
	ModelThreshold         float64          `json:"model_threshold"`
	NearThresholdMargin    float64          `json:"near_threshold_margin"`
	RuntimeMode            analysis.MLMode  `json:"runtime_mode"`
	RuntimeState           string           `json:"runtime_state"`
	Statistics             statistics       `json:"statistics"`
	Outputs                []outputFile     `json:"outputs"`
	Safeguards             []string         `json:"safeguards"`
	Limitations            []string         `json:"limitations"`
}

type runOptions struct {
	APIURL            string
	APIKeyFile        string
	BundleDir         string
	SourcePath        string
	DataManifestPath  string
	SourceLogicalName string
	OutputDir         string
	SourceCommit      string
	NearMargin        float64
	Timeout           time.Duration
	MaxDomains        int
}

func main() {
	var options runOptions
	flag.StringVar(&options.APIURL, "api-url", "http://127.0.0.1:8080", "Core API base URL")
	flag.StringVar(&options.APIKeyFile, "admin-api-key-file", "", "file containing the admin API key")
	flag.StringVar(&options.BundleDir, "bundle", "", "verified model bundle directory")
	flag.StringVar(&options.SourcePath, "source", "", "newline-delimited whitelist snapshot")
	flag.StringVar(&options.DataManifestPath, "data-manifest", "", "data provenance manifest")
	flag.StringVar(&options.SourceLogicalName, "source-logical-name", "", "raw_sources logical_name")
	flag.StringVar(&options.OutputDir, "output", "", "new private output directory")
	flag.StringVar(&options.SourceCommit, "source-commit", "", "exact 40-character Git commit under evaluation")
	flag.Float64Var(&options.NearMargin, "near-threshold-margin", 0.05, "absolute probability margin around the model threshold")
	flag.DurationVar(&options.Timeout, "timeout", 10*time.Minute, "overall read-only API and evaluation timeout")
	flag.IntVar(&options.MaxDomains, "max-domains", 1000000, "maximum unique normalized domains accepted")
	flag.Parse()

	manifestPath, manifest, err := run(context.Background(), options)
	if err != nil {
		fmt.Fprintln(os.Stderr, "whitelist proxy replay failed:", err)
		os.Exit(1)
	}
	fmt.Printf("manifest: %s\n", manifestPath)
	fmt.Printf("domains=%d candidates=%d would_block=%d near_threshold=%d whitelist_proxy_fpr=%s\n",
		manifest.Statistics.UniqueProxyBenignDomains,
		manifest.Statistics.MLCandidateDomains,
		manifest.Statistics.WouldBlock,
		manifest.Statistics.NearThreshold,
		formatOptionalRate(manifest.Statistics.WhitelistProxyFPR),
	)
}

func run(parent context.Context, options runOptions) (string, replayManifest, error) {
	if !validCommit(options.SourceCommit) {
		return "", replayManifest{}, errors.New("--source-commit must be an exact 40-character hexadecimal Git commit")
	}
	if strings.TrimSpace(options.BundleDir) == "" || strings.TrimSpace(options.SourcePath) == "" ||
		strings.TrimSpace(options.DataManifestPath) == "" || strings.TrimSpace(options.SourceLogicalName) == "" ||
		strings.TrimSpace(options.OutputDir) == "" {
		return "", replayManifest{}, errors.New("--bundle, --source, --data-manifest, --source-logical-name, and --output are required")
	}
	if options.NearMargin <= 0 || options.NearMargin >= 1 || math.IsNaN(options.NearMargin) || math.IsInf(options.NearMargin, 0) {
		return "", replayManifest{}, errors.New("--near-threshold-margin must be between zero and one")
	}
	if options.Timeout <= 0 || options.Timeout > 30*time.Minute {
		return "", replayManifest{}, errors.New("--timeout must be greater than zero and at most 30m")
	}
	if options.MaxDomains < 1 || options.MaxDomains > 10000000 {
		return "", replayManifest{}, errors.New("--max-domains must be between 1 and 10000000")
	}

	baseURL, err := validateBaseURL(options.APIURL)
	if err != nil {
		return "", replayManifest{}, err
	}
	apiKey, err := readAdminAPIKey(options.APIKeyFile)
	if err != nil {
		return "", replayManifest{}, err
	}
	if len(apiKey) < 16 {
		return "", replayManifest{}, errors.New("admin API key is empty or invalid")
	}

	ctx, cancel := context.WithTimeout(parent, options.Timeout)
	defer cancel()
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirects are disabled for authenticated snapshot reads")
		},
	}
	snapshot, err := fetchAPISnapshot(ctx, client, baseURL, apiKey)
	if err != nil {
		return "", replayManifest{}, err
	}

	classifier, err := analysis.NewBundleClassifier(options.BundleDir)
	if err != nil {
		return "", replayManifest{}, fmt.Errorf("load verified model bundle: %w", err)
	}
	if classifier.Revision() != snapshot.Status.ML.Revision || classifier.ModelVersion() != snapshot.Status.ML.ModelVersion ||
		classifier.BlockThreshold() != snapshot.Status.ML.BlockThreshold {
		return "", replayManifest{}, fmt.Errorf("runtime and local bundle do not match: runtime revision=%s version=%s threshold=%g, local revision=%s version=%s threshold=%g",
			snapshot.Status.ML.Revision, snapshot.Status.ML.ModelVersion, snapshot.Status.ML.BlockThreshold,
			classifier.Revision(), classifier.ModelVersion(), classifier.BlockThreshold())
	}

	provenance, expectedHash, expectedBytes, err := loadSourceProvenance(options.DataManifestPath, options.SourceLogicalName, options.SourcePath)
	if err != nil {
		return "", replayManifest{}, err
	}
	analyzer := analysis.NewAnalyzerWithBrandStore(snapshot.Config, analysis.NewMemoryBrandStore(snapshot.Brands))
	rows, stats, actualHash, actualBytes, err := evaluateSource(ctx, options.SourcePath, analyzer, classifier, options.NearMargin, options.MaxDomains)
	if err != nil {
		return "", replayManifest{}, err
	}
	if actualHash != expectedHash || actualBytes != expectedBytes {
		return "", replayManifest{}, fmt.Errorf("source provenance mismatch: expected sha256=%s bytes=%d, got sha256=%s bytes=%d",
			expectedHash, expectedBytes, actualHash, actualBytes)
	}

	endStatus, err := fetchStatus(ctx, client, baseURL, apiKey)
	if err != nil {
		return "", replayManifest{}, err
	}
	if !sameRuntimeContract(snapshot.Status, endStatus) {
		return "", replayManifest{}, errors.New("runtime contract changed during evaluation; retry against a stable snapshot")
	}

	configBytes, err := json.Marshal(snapshot.Config.Clone())
	if err != nil {
		return "", replayManifest{}, fmt.Errorf("encode analysis config provenance: %w", err)
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
		return "", replayManifest{}, fmt.Errorf("encode trusted brand provenance: %w", err)
	}
	bundleHash, err := hashBundleManifest(options.BundleDir)
	if err != nil {
		return "", replayManifest{}, err
	}

	manifest := replayManifest{
		SchemaVersion:          reportSchemaVersion,
		GeneratedAt:            time.Now().UTC().Format(time.RFC3339Nano),
		SourceCommit:           strings.ToLower(strings.TrimSpace(options.SourceCommit)),
		EvaluationKind:         "counterfactual_without_runtime_whitelist",
		Source:                 provenance,
		AnalysisConfigRevision: snapshot.ConfigRevision,
		AnalysisConfigSHA256:   hashBytes(configBytes),
		TrustedBrandsSHA256:    hashBytes(brandBytes),
		BundleSHA256SHash:      bundleHash,
		ModelVersion:           classifier.ModelVersion(),
		ModelRevision:          classifier.Revision(),
		ModelThreshold:         classifier.BlockThreshold(),
		NearThresholdMargin:    options.NearMargin,
		RuntimeMode:            snapshot.Status.ML.Mode,
		RuntimeState:           snapshot.Status.ML.State,
		Statistics:             stats,
		Safeguards: []string{
			"runtime whitelist was not changed or bypassed",
			"runtime mode was required to remain shadow/ready/enabled",
			"no DNS, HTTP, or browser request was made to a source domain",
			"no false-positive report or allow decision was created",
			"source, data manifest, model bundle, config, and trusted brands were checksum-pinned",
		},
		Limitations: []string{
			"whitelist membership is a benign proxy, not a current safety guarantee or human adjudication",
			"a would-block row is a review candidate, not a confirmed false positive",
			"source terms review is inherited from the provenance manifest and may still be pending",
			"the source combines collected and procedurally generated candidates described by the repository provenance documentation",
		},
	}
	manifestPath, finalManifest, err := writeReport(options.OutputDir, manifest, rows)
	if err != nil {
		return "", replayManifest{}, err
	}
	return manifestPath, finalManifest, nil
}

func loadSourceProvenance(manifestPath, logicalName, sourcePath string) (sourceProvenance, string, int64, error) {
	manifestData, err := safefile.ReadFileWithin(filepath.Dir(manifestPath), filepath.Base(manifestPath))
	if err != nil {
		return sourceProvenance{}, "", 0, fmt.Errorf("read data manifest: %w", err)
	}
	var manifest dataManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return sourceProvenance{}, "", 0, fmt.Errorf("parse data manifest: %w", err)
	}
	if manifest.ManifestVersion != 1 {
		return sourceProvenance{}, "", 0, fmt.Errorf("unsupported data manifest version %d", manifest.ManifestVersion)
	}
	var matched *rawSource
	for i := range manifest.RawSources {
		if manifest.RawSources[i].LogicalName == logicalName {
			if matched != nil {
				return sourceProvenance{}, "", 0, fmt.Errorf("duplicate raw source logical_name %q", logicalName)
			}
			matched = &manifest.RawSources[i]
		}
	}
	if matched == nil {
		return sourceProvenance{}, "", 0, fmt.Errorf("raw source %q not found in data manifest", logicalName)
	}
	if len(matched.SHA256) != sha256.Size*2 {
		return sourceProvenance{}, "", 0, errors.New("raw source manifest contains an invalid SHA-256")
	}
	if _, err := hex.DecodeString(matched.SHA256); err != nil || matched.Bytes < 1 {
		return sourceProvenance{}, "", 0, errors.New("raw source manifest contains invalid checksum or byte size")
	}
	manifestDir, err := filepath.Abs(filepath.Dir(manifestPath))
	if err != nil {
		return sourceProvenance{}, "", 0, fmt.Errorf("resolve data manifest directory: %w", err)
	}
	root := filepath.Clean(filepath.Join(manifestDir, "..", ".."))
	expectedPath, err := filepath.Abs(filepath.Join(root, filepath.FromSlash(matched.Path)))
	if err != nil {
		return sourceProvenance{}, "", 0, fmt.Errorf("resolve manifest source path: %w", err)
	}
	actualPath, err := filepath.Abs(sourcePath)
	if err != nil {
		return sourceProvenance{}, "", 0, fmt.Errorf("resolve source path: %w", err)
	}
	if !strings.EqualFold(filepath.Clean(expectedPath), filepath.Clean(actualPath)) {
		return sourceProvenance{}, "", 0, fmt.Errorf("source path does not match manifest: expected %s, got %s", expectedPath, actualPath)
	}
	return sourceProvenance{
		LogicalName:        matched.LogicalName,
		Path:               filepath.ToSlash(matched.Path),
		SHA256:             strings.ToLower(matched.SHA256),
		Bytes:              matched.Bytes,
		RetrievedAt:        matched.RetrievedAt,
		TrustTier:          matched.TrustTier,
		TermsReviewID:      matched.TermsReviewID,
		DataManifest:       filepath.ToSlash(filepath.Clean(manifestPath)),
		DataManifestSHA256: hashBytes(manifestData),
		PipelineGitSHA:     manifest.PipelineGitSHA,
		ManifestGenerated:  manifest.GeneratedAt,
	}, strings.ToLower(matched.SHA256), matched.Bytes, nil
}

func evaluateSource(ctx context.Context, sourcePath string, analyzer domainAnalyzer, classifier domainClassifier, nearMargin float64, maxDomains int) ([]candidateRow, statistics, string, int64, error) {
	file, err := safefile.OpenWithin(filepath.Dir(sourcePath), filepath.Base(sourcePath))
	if err != nil {
		return nil, statistics{}, "", 0, fmt.Errorf("open source snapshot: %w", err)
	}
	defer func() { _ = file.Close() }()
	hasher := sha256.New()
	counting := &countingWriter{writer: hasher}
	scanner := bufio.NewScanner(io.TeeReader(file, counting))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	seen := make(map[string]struct{}, 700000)
	rows := make([]candidateRow, 0, 4096)
	stats := statistics{}
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, stats, "", counting.bytes, err
		}
		stats.SourceLines++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			stats.BlankLines++
			continue
		}
		domain, err := analysis.NormalizeDomain(raw)
		if err != nil {
			stats.InvalidDomains++
			continue
		}
		if _, exists := seen[domain]; exists {
			stats.DuplicateDomains++
			continue
		}
		seen[domain] = struct{}{}
		if len(seen) > maxDomains {
			return nil, stats, "", counting.bytes, fmt.Errorf("source exceeds --max-domains=%d", maxDomains)
		}
		lexical := analyzer.Analyze(domain)
		switch lexical.Verdict {
		case analysis.VerdictSafe:
			stats.LexicalSafe++
		case analysis.VerdictSuspicious:
			stats.LexicalSuspicious++
		case analysis.VerdictMalicious:
			stats.LexicalMalicious++
		default:
			stats.InvalidDomains++
			continue
		}
		if lexical.Verdict != analysis.VerdictSuspicious {
			continue
		}
		decision, err := classifier.Classify(domain)
		if err != nil {
			return nil, stats, "", counting.bytes, fmt.Errorf("classify %s: %w", domain, err)
		}
		wouldBlock := decision.Action == analysis.MLActionPromoteMalicious
		near := math.Abs(decision.Probability-classifier.BlockThreshold()) <= nearMargin
		if wouldBlock {
			stats.WouldBlock++
		} else {
			stats.WouldPass++
		}
		if near {
			stats.NearThreshold++
		}
		rows = append(rows, candidateRow{
			CaseID:            caseID(domain),
			Domain:            domain,
			LexicalScore:      lexical.Score,
			LexicalConfidence: lexical.Confidence,
			LexicalReasons:    strings.Join(lexical.Reasons, ";"),
			Probability:       decision.Probability,
			Threshold:         classifier.BlockThreshold(),
			WouldBlock:        wouldBlock,
			NearThreshold:     near,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, stats, "", counting.bytes, fmt.Errorf("scan source snapshot: %w", err)
	}
	stats.UniqueProxyBenignDomains = len(seen)
	stats.MLCandidateDomains = len(rows)
	if stats.UniqueProxyBenignDomains > 0 {
		rate := float64(stats.WouldBlock) / float64(stats.UniqueProxyBenignDomains)
		stats.WhitelistProxyFPR = &rate
	}
	if stats.MLCandidateDomains > 0 {
		rate := float64(stats.WouldBlock) / float64(stats.MLCandidateDomains)
		stats.CandidateConditionalBlockRate = &rate
	}
	return rows, stats, hex.EncodeToString(hasher.Sum(nil)), counting.bytes, nil
}

type countingWriter struct {
	writer io.Writer
	bytes  int64
}

func (w *countingWriter) Write(data []byte) (int, error) {
	n, err := w.writer.Write(data)
	w.bytes += int64(n)
	return n, err
}

func fetchAPISnapshot(ctx context.Context, client *http.Client, baseURL, apiKey string) (apiSnapshot, error) {
	start, err := fetchStatus(ctx, client, baseURL, apiKey)
	if err != nil {
		return apiSnapshot{}, err
	}
	if start.ML.Mode != analysis.MLModeShadow || !start.ML.Enabled || start.ML.State != "ready" {
		return apiSnapshot{}, fmt.Errorf("runtime ML must be shadow/ready/enabled, got mode=%s state=%s enabled=%t", start.ML.Mode, start.ML.State, start.ML.Enabled)
	}
	var cfg config.AnalysisConfig
	if err := getJSON(ctx, client, baseURL+"/v1/config/analysis", apiKey, &cfg); err != nil {
		return apiSnapshot{}, fmt.Errorf("fetch runtime analysis config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return apiSnapshot{}, fmt.Errorf("validate runtime analysis config: %w", err)
	}
	if revision := analysisConfigRevision(cfg); revision != start.AnalysisConfig.Revision {
		return apiSnapshot{}, fmt.Errorf("analysis config revision mismatch: status=%s fetched=%s", start.AnalysisConfig.Revision, revision)
	}
	var payload brandResponse
	if err := getJSON(ctx, client, baseURL+"/v1/brands", apiKey, &payload); err != nil {
		return apiSnapshot{}, fmt.Errorf("fetch trusted brands: %w", err)
	}
	if payload.Items == nil {
		payload.Items = []analysis.Brand{}
	}
	end, err := fetchStatus(ctx, client, baseURL, apiKey)
	if err != nil {
		return apiSnapshot{}, err
	}
	if !sameRuntimeContract(start, end) {
		return apiSnapshot{}, errors.New("runtime contract changed while acquiring snapshot")
	}
	return apiSnapshot{Config: cfg, ConfigRevision: start.AnalysisConfig.Revision, Brands: payload.Items, Status: start}, nil
}

func sameRuntimeContract(left, right runtimeStatus) bool {
	return left.AnalysisConfig.Revision == right.AnalysisConfig.Revision &&
		left.ML.Mode == right.ML.Mode && left.ML.Enabled == right.ML.Enabled && left.ML.State == right.ML.State &&
		left.ML.ModelVersion == right.ML.ModelVersion && left.ML.Revision == right.ML.Revision &&
		left.ML.BlockThreshold == right.ML.BlockThreshold
}

func fetchStatus(ctx context.Context, client *http.Client, baseURL, apiKey string) (runtimeStatus, error) {
	var status runtimeStatus
	if err := getJSON(ctx, client, baseURL+"/v1/status", apiKey, &status); err != nil {
		return runtimeStatus{}, fmt.Errorf("fetch runtime status: %w", err)
	}
	return status, nil
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
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

func writeReport(outputDir string, manifest replayManifest, rows []candidateRow) (string, replayManifest, error) {
	target, err := filepath.Abs(strings.TrimSpace(outputDir))
	if err != nil || strings.TrimSpace(outputDir) == "" {
		return "", replayManifest{}, errors.New("invalid --output directory")
	}
	if _, err := os.Stat(target); err == nil {
		return "", replayManifest{}, fmt.Errorf("output directory already exists: %s", target)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", replayManifest{}, fmt.Errorf("inspect output directory: %w", err)
	}
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", replayManifest{}, fmt.Errorf("create output parent: %w", err)
	}
	staging, err := os.MkdirTemp(parent, ".ml-whitelist-proxy-")
	if err != nil {
		return "", replayManifest{}, fmt.Errorf("create staging output: %w", err)
	}
	defer func() { _ = os.RemoveAll(staging) }()

	definitions := []struct {
		name   string
		filter func(candidateRow) bool
	}{
		{name: "candidates.csv", filter: func(candidateRow) bool { return true }},
		{name: "would-block.csv", filter: func(row candidateRow) bool { return row.WouldBlock }},
		{name: "near-threshold.csv", filter: func(row candidateRow) bool { return row.NearThreshold }},
	}
	for _, definition := range definitions {
		data, count, err := encodeRows(rows, definition.filter)
		if err != nil {
			return "", replayManifest{}, err
		}
		if err := os.WriteFile(filepath.Join(staging, definition.name), data, 0o600); err != nil {
			return "", replayManifest{}, fmt.Errorf("write %s: %w", definition.name, err)
		}
		manifest.Outputs = append(manifest.Outputs, outputFile{Path: definition.name, SHA256: hashBytes(data), Rows: count})
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", replayManifest{}, fmt.Errorf("encode report manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(filepath.Join(staging, "manifest.json"), manifestBytes, 0o600); err != nil {
		return "", replayManifest{}, fmt.Errorf("write report manifest: %w", err)
	}
	if err := os.Rename(staging, target); err != nil {
		return "", replayManifest{}, fmt.Errorf("activate output directory: %w", err)
	}
	return filepath.Join(target, "manifest.json"), manifest, nil
}

func encodeRows(rows []candidateRow, include func(candidateRow) bool) ([]byte, int, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	header := []string{"case_id", "domain", "proxy_label", "lexical_score", "lexical_confidence", "lexical_reasons", "model_probability", "model_threshold", "would_block", "near_threshold"}
	if err := writer.Write(header); err != nil {
		return nil, 0, err
	}
	count := 0
	for _, row := range rows {
		if !include(row) {
			continue
		}
		record := []string{
			row.CaseID, row.Domain, "benign_proxy", strconv.Itoa(row.LexicalScore),
			strconv.FormatFloat(row.LexicalConfidence, 'g', -1, 64), row.LexicalReasons,
			strconv.FormatFloat(row.Probability, 'g', -1, 64), strconv.FormatFloat(row.Threshold, 'g', -1, 64),
			strconv.FormatBool(row.WouldBlock), strconv.FormatBool(row.NearThreshold),
		}
		if err := writer.Write(record); err != nil {
			return nil, 0, err
		}
		count++
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, 0, err
	}
	return buffer.Bytes(), count, nil
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
	data, err := safefile.ReadFileWithin(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return "", fmt.Errorf("read admin API key: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
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

func caseID(domain string) string {
	sum := sha256.Sum256([]byte(domain))
	return "wlp-" + hex.EncodeToString(sum[:8])
}

func validCommit(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 40 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func formatOptionalRate(value *float64) string {
	if value == nil {
		return "n/a"
	}
	return strconv.FormatFloat(*value, 'g', -1, 64)
}
