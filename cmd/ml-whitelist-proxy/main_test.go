package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"safe-zone/internal/analysis"
)

type fakeAnalyzer struct {
	results map[string]analysis.Result
}

func (f fakeAnalyzer) Analyze(domain string) analysis.Result {
	return f.results[domain]
}

type fakeClassifier struct {
	threshold     float64
	probabilities map[string]float64
}

func (f fakeClassifier) BlockThreshold() float64 { return f.threshold }

func (f fakeClassifier) Classify(domain string) (analysis.MLDecision, error) {
	probability := f.probabilities[domain]
	action := analysis.MLActionAbstain
	if probability >= f.threshold {
		action = analysis.MLActionPromoteMalicious
	}
	return analysis.MLDecision{Probability: probability, Action: action}, nil
}

func TestEvaluateSourceComputesProxyRatesAndDeduplicates(t *testing.T) {
	t.Parallel()
	source := filepath.Join(t.TempDir(), "domains.txt")
	contents := []byte("safe.vn\nsuspicious.vn\nblock.vn\nblock.vn\ninvalid domain\n\n")
	if err := os.WriteFile(source, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	analyzer := fakeAnalyzer{results: map[string]analysis.Result{
		"safe.vn":       {Domain: "safe.vn", Verdict: analysis.VerdictSafe},
		"suspicious.vn": {Domain: "suspicious.vn", Verdict: analysis.VerdictSuspicious, Score: 55, Confidence: 0.55, Reasons: []string{"test"}},
		"block.vn":      {Domain: "block.vn", Verdict: analysis.VerdictSuspicious, Score: 80, Confidence: 0.8, Reasons: []string{"test"}},
	}}
	classifier := fakeClassifier{threshold: 0.85, probabilities: map[string]float64{
		"suspicious.vn": 0.82,
		"block.vn":      0.91,
	}}
	rows, stats, gotHash, gotBytes, err := evaluateSource(context.Background(), source, analyzer, classifier, selectionPolicy{SourceFormat: "domains"}, 0.05, 100)
	if err != nil {
		t.Fatal(err)
	}
	wantHashBytes := sha256.Sum256(contents)
	if gotHash != hex.EncodeToString(wantHashBytes[:]) || gotBytes != int64(len(contents)) {
		t.Fatalf("source identity = %s/%d, want %s/%d", gotHash, gotBytes, hex.EncodeToString(wantHashBytes[:]), len(contents))
	}
	if stats.SourceLines != 6 || stats.BlankLines != 1 || stats.InvalidDomains != 1 || stats.DuplicateDomains != 1 {
		t.Fatalf("unexpected source counters: %+v", stats)
	}
	if stats.UniqueProxyBenignDomains != 3 || stats.MLCandidateDomains != 2 || stats.WouldBlock != 1 || stats.WouldPass != 1 || stats.NearThreshold != 1 {
		t.Fatalf("unexpected evaluation counters: %+v", stats)
	}
	if stats.WhitelistProxyFPR == nil || *stats.WhitelistProxyFPR != 1.0/3.0 {
		t.Fatalf("whitelist proxy FPR = %v", stats.WhitelistProxyFPR)
	}
	if stats.CandidateConditionalBlockRate == nil || *stats.CandidateConditionalBlockRate != 0.5 {
		t.Fatalf("candidate block rate = %v", stats.CandidateConditionalBlockRate)
	}
	if len(rows) != 2 || !rows[1].WouldBlock {
		t.Fatalf("unexpected rows: %+v", rows)
	}
}

func TestEvaluateCSVFiltersEvidenceAndPublicSuffix(t *testing.T) {
	t.Parallel()
	source := filepath.Join(t.TempDir(), "websites.csv")
	contents := []byte("domain,detail_url\n" +
		"official.vn,https://tinnhiemmang.vn/evidence/1\n" +
		"safe.gov.vn,https://giayphep.abei.gov.vn/evidence/2\n" +
		"bad.invalidtld,https://tinnhiemmang.vn/evidence/3\n" +
		"missing.vn,\n" +
		"other.vn,https://unapproved.example/evidence/4\n" +
		"invalid.vn,not-a-url\n" +
		"official.vn,https://tinnhiemmang.vn/evidence/1\n")
	if err := os.WriteFile(source, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	analyzer := fakeAnalyzer{results: map[string]analysis.Result{
		"official.vn": {Domain: "official.vn", Verdict: analysis.VerdictSuspicious, Score: 60, Confidence: 0.6},
		"safe.gov.vn": {Domain: "safe.gov.vn", Verdict: analysis.VerdictSafe},
	}}
	classifier := fakeClassifier{threshold: 0.85, probabilities: map[string]float64{"official.vn": 0.9}}
	selection := selectionPolicy{
		SourceFormat:         "csv",
		DomainColumn:         "domain",
		EvidenceURLColumn:    "detail_url",
		AllowedEvidenceHosts: []string{"giayphep.abei.gov.vn", "tinnhiemmang.vn"},
		RequireICANNSuffix:   true,
	}
	rows, stats, _, _, err := evaluateSource(context.Background(), source, analyzer, classifier, selection, 0.05, 100)
	if err != nil {
		t.Fatal(err)
	}
	if stats.SourceLines != 7 || stats.MissingEvidence != 1 || stats.InvalidEvidenceURLs != 1 ||
		stats.UnapprovedEvidenceHosts != 1 || stats.UnknownPublicSuffixes != 1 || stats.DuplicateDomains != 1 {
		t.Fatalf("unexpected CSV selection counters: %+v", stats)
	}
	if stats.SelectedSourceRecords != 2 || stats.UniqueProxyBenignDomains != 2 || stats.MLCandidateDomains != 1 || stats.WouldBlock != 1 {
		t.Fatalf("unexpected CSV evaluation counters: %+v", stats)
	}
	if len(rows) != 1 || rows[0].EvidenceHost != "tinnhiemmang.vn" || rows[0].EvidenceReference == "" {
		t.Fatalf("unexpected CSV candidate: %+v", rows)
	}
}

func TestLoadSourceProvenanceRejectsPathMismatch(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	manifestDir := filepath.Join(root, "ml", "data")
	if err := os.MkdirAll(manifestDir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := dataManifest{
		ManifestVersion: 1,
		PipelineGitSHA:  "0123456789012345678901234567890123456789",
		GeneratedAt:     "2026-08-23T00:00:00Z",
		RawSources: []rawSource{{
			LogicalName: "vietnam_domains.txt",
			Path:        "data/whitelist/vietnam/vietnam_domains.txt",
			SHA256:      "5d8b902dc64e9d78fc91224abfdd47a8830aaec1ab17c4b0e96e83c37c0c1807",
			Bytes:       10,
		}},
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(manifestDir, "data_manifest.json")
	if err := os.WriteFile(manifestPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, _, err = loadSourceProvenance(manifestPath, "vietnam_domains.txt", filepath.Join(root, "wrong.txt"))
	if err == nil {
		t.Fatal("expected source path mismatch")
	}
}

func TestEncodeRowsUsesProxyLabel(t *testing.T) {
	t.Parallel()
	data, count, err := encodeRows([]candidateRow{{CaseID: "wlp-1", Domain: "example.vn", EvidenceHost: "tinnhiemmang.vn", EvidenceReference: "https://tinnhiemmang.vn/example"}}, func(candidateRow) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || !bytesContains(data, []byte("benign_proxy")) || !bytesContains(data, []byte("tinnhiemmang.vn")) || bytesContains(data, []byte("human_label")) {
		t.Fatalf("unexpected encoded CSV: %s", data)
	}
}

func bytesContains(data, fragment []byte) bool {
	for i := 0; i+len(fragment) <= len(data); i++ {
		match := true
		for j := range fragment {
			if data[i+j] != fragment[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
