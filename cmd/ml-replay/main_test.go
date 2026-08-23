package main

import (
	"os"
	"path/filepath"
	"testing"

	"safe-zone/internal/analysis"
)

func TestReadCasesHashesExactInputAndRejectsDuplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "labels.csv")
	content := "case_id,domain,human_label\ncase-1,example.com,benign\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cases, hash, err := readCases(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 || cases[0].CaseID != "case-1" || hash == "" {
		t.Fatalf("unexpected parsed cases/hash: %+v %q", cases, hash)
	}

	duplicate := "case_id,domain,human_label\ncase-1,a.example,benign\ncase-1,b.example,malicious\n"
	if err := os.WriteFile(path, []byte(duplicate), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readCases(path); err == nil {
		t.Fatal("expected duplicate case_id to fail")
	}
}

func TestCompareDecisionsFindsProbabilityAndActionMismatch(t *testing.T) {
	cases := []replayCase{
		{CaseID: "case-1", Domain: "one.example"},
		{CaseID: "case-2", Domain: "two.example"},
	}
	left := map[string]analysis.MLDecision{
		"one.example": {Probability: 0.9, Action: analysis.MLActionPromoteMalicious, Revision: "r1"},
		"two.example": {Probability: 0.1, Action: analysis.MLActionAbstain, Revision: "r1"},
	}
	right := map[string]analysis.MLDecision{
		"one.example": {Probability: 0.9, Action: analysis.MLActionPromoteMalicious, Revision: "r1"},
		"two.example": {Probability: 0.2, Action: analysis.MLActionPromoteMalicious, Revision: "r1"},
	}

	summary := compareDecisions(cases, left, right, 1e-12)
	if summary.Compared != 2 || summary.MismatchCount != 1 || summary.MismatchCaseIDs[0] != "case-2" {
		t.Fatalf("unexpected parity summary: %+v", summary)
	}
}

func TestCalculateFalsePositivesUsesOnlyRuntimeCandidates(t *testing.T) {
	cases := []replayCase{
		{CaseID: "safe-candidate", Domain: "safe.example", HumanLabel: "benign"},
		{CaseID: "safe-not-candidate", Domain: "uncalled.example", HumanLabel: "benign"},
	}
	decisions := map[string]analysis.MLDecision{
		"safe.example": {Probability: 0.95, Action: analysis.MLActionPromoteMalicious},
	}

	summary := calculateFalsePositives(cases, decisions)
	if summary.BenignCases != 1 || summary.FalsePositives != 1 || summary.FPR == nil || *summary.FPR != 1 {
		t.Fatalf("unexpected false-positive summary: %+v", summary)
	}
}
