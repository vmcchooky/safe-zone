package eval

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCorpusValidation(t *testing.T) {
	valid := Corpus{
		SchemaVersion: 1, Name: "t", Kind: CorpusTruth,
		Cases: []Case{
			{ID: "a", Domain: "example.com", Stratum: "benign", Security: LabelSafe, Confidence: ConfidenceHigh, Policy: PolicyAllow},
			{ID: "b", Domain: "evil.example", Stratum: "malware_phishing", Security: LabelMalicious, Confidence: ConfidenceMedium, Policy: PolicyBlock, Evidence: []string{"community blacklist snapshot 2026-09-01"}},
		},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid corpus rejected: %v", err)
	}

	duplicate := valid
	duplicate.Cases = append(duplicate.Cases, duplicate.Cases[0])
	if err := duplicate.Validate(); err == nil {
		t.Fatal("duplicate ids must be rejected")
	}

	unproven := valid
	unproven.Cases[1] = Case{ID: "b", Domain: "evil.example", Stratum: "malware_phishing",
		Security: LabelMalicious, Confidence: ConfidenceHigh, Policy: PolicyBlock}
	if err := unproven.Validate(); err == nil {
		t.Fatal("high-confidence malicious without evidence/reviewer/date must be rejected")
	}

	badStratum := valid
	badStratum.Cases[0].Stratum = "nope"
	if err := badStratum.Validate(); err == nil {
		t.Fatal("unknown stratum must be rejected")
	}

	contract := Corpus{
		SchemaVersion: 1, Name: "c", Kind: CorpusContract,
		Cases: []Case{
			{ID: "g", Domain: "gap.test", Stratum: "adversarial", Security: LabelUnknown, Confidence: ConfidenceLow, Policy: PolicyAny, Intent: IntentKnownGap},
		},
	}
	if err := contract.Validate(); err == nil {
		t.Fatal("known_gap without a note must be rejected")
	}
}

func TestGatedExcludesUnknown(t *testing.T) {
	corpus := Corpus{
		SchemaVersion: 1, Name: "t", Kind: CorpusTruth,
		Cases: []Case{
			{ID: "a", Domain: "example.com", Stratum: "benign", Security: LabelSafe, Confidence: ConfidenceHigh, Policy: PolicyAllow},
			{ID: "b", Domain: "mystery.test", Stratum: "malware_phishing", Security: LabelUnknown, Confidence: ConfidenceLow, Policy: PolicyAny},
			{ID: "c", Domain: "soft.test", Stratum: "benign", Security: LabelSafe, Confidence: ConfidenceLow, Policy: PolicyAllow},
		},
	}
	gated := corpus.Gated()
	if len(gated) != 1 || gated[0].ID != "a" {
		t.Fatalf("gated set must hold only high/medium non-unknown, got %+v", gated)
	}
}

func TestExpectedRequiresReviewSignature(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "expected.json")
	content := `{"schema_version":1,"corpus":"x","corpus_sha256":"y","cases":{}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExpected(dir, "expected.json"); err == nil {
		t.Fatal("unsigned expected file must be refused")
	}
}
