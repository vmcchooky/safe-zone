package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
)

type fakeAnalyzer map[string]analysis.Result

func (f fakeAnalyzer) Analyze(domain string) analysis.Result { return f[domain] }

type fakeClassifier map[string]analysis.MLDecision

func (f fakeClassifier) Classify(domain string) (analysis.MLDecision, error) { return f[domain], nil }

func TestSelectCandidatesFiltersDeduplicatesAndKeepsProvenance(t *testing.T) {
	reports := []queueReport{
		{ID: 2, Domain: "Login-Safe.Example", Status: "resolved", ReviewReason: "verified legitimate", ReviewedBy: "reviewer-b", ReviewedAt: "2026-08-23 10:00:00", ResolutionAction: "allow"},
		{ID: 1, Domain: "login-safe.example.", Status: "resolved", ReviewReason: "verified legitimate", ReviewedBy: "reviewer-a", ReviewedAt: "2026-08-23 09:00:00", ResolutionAction: "allow"},
		{ID: 3, Domain: "ordinary.example", Status: "resolved", ReviewReason: "verified legitimate", ReviewedBy: "reviewer-a", ReviewedAt: "2026-08-23 09:00:00", ResolutionAction: "allow"},
		{ID: 4, Domain: "ignored.example", Status: "resolved", ReviewReason: "verified legitimate", ReviewedBy: "reviewer-a", ReviewedAt: "2026-08-23 09:00:00", ResolutionAction: "resolve"},
		{ID: 5, Domain: "missing-review.example", Status: "resolved", ReviewReason: "", ReviewedBy: "", ReviewedAt: "", ResolutionAction: "allow"},
	}
	analyzer := fakeAnalyzer{
		"login-safe.example": {Domain: "login-safe.example", Verdict: analysis.VerdictSuspicious, Score: 55, Confidence: 0.55},
		"ordinary.example":   {Domain: "ordinary.example", Verdict: analysis.VerdictSafe, Score: 0, Confidence: 1},
	}
	classifier := fakeClassifier{
		"login-safe.example": {Probability: 0.91, Action: analysis.MLActionPromoteMalicious},
	}

	rows, stats, err := selectCandidates(reports, analyzer, classifier, "revision-1", 0.85)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one candidate, got %d", len(rows))
	}
	row := rows[0]
	if row.Domain != "login-safe.example" || row.SourceReportIDs != "1;2" || row.ReviewedBy != "reviewer-a;reviewer-b" {
		t.Fatalf("unexpected candidate provenance: %+v", row)
	}
	if row.ReviewedAt != "2026-08-23 10:00:00" || !row.DeterministicWouldBlock {
		t.Fatalf("unexpected candidate decision: %+v", row)
	}
	if stats.SourceReports != 5 || stats.EligibleAllowReports != 3 || stats.UniqueEligibleDomains != 2 || stats.DuplicateReports != 1 {
		t.Fatalf("unexpected source statistics: %+v", stats)
	}
	if stats.InvalidProvenanceReports != 2 || stats.ExcludedLexicalVerdicts["SAFE"] != 1 || stats.CandidateDomains != 1 || stats.WouldBlock != 1 {
		t.Fatalf("unexpected selection statistics: %+v", stats)
	}
	if stats.ObservedFPR == nil || *stats.ObservedFPR != 1 {
		t.Fatalf("unexpected observed FPR: %+v", stats.ObservedFPR)
	}
}

func TestFetchAPISnapshotPaginatesAndPinsRuntimeContract(t *testing.T) {
	cfg := config.DefaultAnalysisConfig()
	revision := analysisConfigRevision(cfg)
	reports := make([]queueReport, 101)
	for i := range reports {
		reports[i] = queueReport{ID: int64(i + 1), Domain: "example.com", Status: "resolved"}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key-0123456789" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"analysis_config_reload": map[string]any{"revision": revision},
				"ml": map[string]any{
					"ml_mode": "shadow", "ml_enabled": true, "ml_state": "ready",
					"ml_model_version": "1.0.0", "ml_revision": "model-revision", "ml_block_threshold": 0.85,
				},
			})
		case "/v1/config/analysis":
			_ = json.NewEncoder(w).Encode(cfg)
		case "/v1/brands":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": analysis.DefaultTrustedBrands()})
		case "/v1/reports":
			offset := 0
			if r.URL.Query().Get("offset") == "100" {
				offset = 100
			}
			end := offset + 100
			if end > len(reports) {
				end = len(reports)
			}
			_ = json.NewEncoder(w).Encode(queueResponse{
				Reports: reports[offset:end], Total: len(reports), Counts: queueCounts{Resolved: len(reports)},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	snapshot, err := fetchAPISnapshot(context.Background(), server.Client(), server.URL, "test-key-0123456789", 200)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Reports) != 101 || snapshot.Total != 101 || snapshot.ConfigRevision != revision {
		t.Fatalf("unexpected snapshot: reports=%d total=%d revision=%s", len(snapshot.Reports), snapshot.Total, snapshot.ConfigRevision)
	}
	if snapshot.RuntimeMLMode != analysis.MLModeShadow || snapshot.RuntimeRevision != "model-revision" {
		t.Fatalf("unexpected runtime contract: %+v", snapshot)
	}
}

func TestWriteExportOmitsLabelsForEmptyQueue(t *testing.T) {
	target := filepath.Join(t.TempDir(), "run-empty")
	manifest := exportManifest{SchemaVersion: exportSchemaVersion, Status: "empty_queue"}
	result, err := writeExport(target, manifest, []byte("case_id,domain,human_label\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	if result.LabelsPath != "" {
		t.Fatalf("expected no labels path, got %s", result.LabelsPath)
	}
	if _, err := os.Stat(filepath.Join(target, "manifest.json")); err != nil {
		t.Fatalf("manifest missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "labels.csv")); !os.IsNotExist(err) {
		t.Fatalf("labels.csv must not exist for an empty queue: %v", err)
	}
}

func TestEncodeLabelsIsReplayCompatibleAndExcludesReviewText(t *testing.T) {
	rows := []candidateRow{{
		CaseID: "fpq-case", Domain: "login-safe.example", SourceReportIDs: "1", ReviewedBy: "operator",
		ReviewedAt: "2026-08-23 10:00:00", LexicalVerdict: analysis.VerdictSuspicious,
		LexicalScore: 55, LexicalConfidence: 0.55, ModelRevision: "revision", ModelThreshold: 0.85,
		ShadowProbability: 0.91, DeterministicWouldBlock: true,
	}}
	encoded, err := encodeLabels(rows)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, required := range []string{"case_id,domain,human_label", "false_positive_queue", "login-safe.example", "benign"} {
		if !strings.Contains(text, required) {
			t.Fatalf("labels missing %q: %s", required, text)
		}
	}
	if strings.Contains(text, "review_reason") || strings.Contains(text, "contact") || strings.Contains(text, "note") {
		t.Fatalf("labels expose excluded queue fields: %s", text)
	}
}

func TestValidCommit(t *testing.T) {
	if !validCommit(strings.Repeat("a", 40)) {
		t.Fatal("expected valid commit")
	}
	for _, value := range []string{"", "abc", strings.Repeat("g", 40), strings.Repeat("a", 39)} {
		if validCommit(value) {
			t.Fatalf("expected invalid commit: %q", value)
		}
	}
}
