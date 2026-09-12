package eval

import (
	"testing"
)

// The frozen runner must be deterministic: two passes over the same
// corpus cannot drift, or golden comparisons are meaningless.
func TestRunnerDeterministic(t *testing.T) {
	runner, err := NewRunner()
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	defer runner.Close()
	corpus := &Corpus{
		SchemaVersion: 1, Name: "det", Kind: CorpusContract,
		AdblockRules: []string{"det-parent.example.net"},
		FeedMembers:  []string{"det-feed.test"},
		Cases: []Case{
			{ID: "a", Domain: "sub.det-parent.example.net", Stratum: "policy", Security: LabelSafe, Confidence: ConfidenceHigh, Policy: PolicyBlock, Intent: IntentMustBlock},
			{ID: "b", Domain: "det-feed.test", Stratum: "malware_phishing", Security: LabelMalicious, Confidence: ConfidenceMedium, Policy: PolicyBlock, Intent: IntentMustBlock, Evidence: []string{"fixture"}},
			{ID: "c", Domain: "quiet-bench-hostname-example.test", Stratum: "benign", Security: LabelSafe, Confidence: ConfidenceHigh, Policy: PolicyAllow, Intent: IntentMustAllow},
		},
	}
	if err := corpus.Validate(); err != nil {
		t.Fatalf("fixture corpus invalid: %v", err)
	}
	if err := runner.LoadFixtures(corpus); err != nil {
		t.Fatalf("load fixtures: %v", err)
	}
	if drifts := runner.VerifyDeterministic(corpus); len(drifts) > 0 {
		t.Fatalf("non-deterministic cases: %v", drifts)
	}
	report := runner.Check(corpus, nil)
	if len(report.InvariantIssues) > 0 {
		t.Fatalf("invariant violations: %v", report.InvariantIssues)
	}
	if report.Contract.Mismatches != 0 {
		t.Fatalf("fixture mismatches: %+v", report.Results)
	}
	if report.Contract.MustBlock != 2 || report.Contract.MustAllow != 1 {
		t.Fatalf("unexpected contract summary: %+v", report.Contract)
	}
}

// Unknown labels record observations without gating anything.
func TestRunnerUnknownNeverFails(t *testing.T) {
	runner, err := NewRunner()
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	defer runner.Close()
	corpus := &Corpus{
		SchemaVersion: 1, Name: "unk", Kind: CorpusTruth,
		Cases: []Case{
			{ID: "u", Domain: "mystery-unknown-host.test", Stratum: "malware_phishing", Security: LabelUnknown, Confidence: ConfidenceLow, Policy: PolicyAny},
		},
	}
	report := runner.Check(corpus, nil)
	if report.Truth.Gated != 0 || report.Truth.UnknownExcluded != 1 {
		t.Fatalf("unknown must be excluded from gates, got %+v", report.Truth)
	}
	for _, res := range report.Results {
		if !res.Match {
			t.Fatalf("unknown case must never fail, got %+v", res)
		}
	}
}
