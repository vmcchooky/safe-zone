// Package eval implements the offline end-to-end decision evaluation for
// Safe Zone: a frozen corpus replayed through Analyze and Policy with
// paired expected Security+Policy outputs.
//
// Two corpus kinds keep truth claims and behavioral pins apart:
//   - truth corpora assert ground-truth security/policy labels and carry
//     provenance requirements enforced by validation;
//   - contract corpora pin engine behavior (must_block, must_allow,
//     characterize) or track accepted gaps (known_gap, excluded from
//     pass/fail but reported, never hidden).
package eval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"safe-zone/internal/analysis"
	"safe-zone/internal/safefile"
)

// Corpus kinds.
const (
	CorpusTruth    = "truth"
	CorpusContract = "contract"
)

// Security labels. Unknown is a first-class outcome: insufficient
// evidence is reported, never folded into benign denominators.
const (
	LabelSafe       = "safe"
	LabelSuspicious = "suspicious"
	LabelMalicious  = "malicious"
	LabelUnknown    = "unknown"
	LabelInvalid    = "invalid"
)

// Label confidences. Gates consume high (and reported medium) labels;
// low and unknown never enter precision/recall denominators.
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// Policy expectations.
const (
	PolicyAllow = "allow"
	PolicyBlock = "block"
	PolicyAny   = "any"
)

// Contract intents.
const (
	IntentMustBlock    = "must_block"
	IntentMustAllow    = "must_allow"
	IntentKnownGap     = "known_gap"
	IntentCharacterize = "characterize"
)

// Strata for breakdowns.
var validStrata = map[string]bool{
	"benign": true, "malware_phishing": true, "policy": true,
	"brand_infra": true, "shared_cdn": true, "dead": true,
	"newly_registered": true, "vn_gov_bank": true, "adversarial": true,
}

// Corpus is one versioned evaluation file.
type Corpus struct {
	SchemaVersion int          `json:"schema_version"`
	Name          string       `json:"name"`
	Kind          string       `json:"kind"`
	Runner        RunnerConfig `json:"runner"`
	AdblockRules  []string     `json:"adblock_rules,omitempty"`
	FeedMembers   []string     `json:"feed_members,omitempty"`
	Cases         []Case       `json:"cases"`
	SHA256        string       `json:"-"`
}

// RunnerConfig pins the hermetic runner profile a corpus was built for.
type RunnerConfig struct {
	MLMode     string `json:"ml_mode"`
	Enrichment bool   `json:"enrichment"`
	OSINT      bool   `json:"osint"`
	AI         bool   `json:"ai"`
	Admission  string `json:"admission"`
	Group      string `json:"group"`
}

// Case is one evaluation item.
type Case struct {
	ID           string   `json:"id"`
	Domain       string   `json:"domain"`
	Stratum      string   `json:"stratum"`
	Security     string   `json:"security"`
	Confidence   string   `json:"confidence"`
	Policy       string   `json:"policy"`
	Intent       string   `json:"intent,omitempty"`
	Evidence     []string `json:"evidence,omitempty"`
	EvidenceKind string   `json:"evidence_kind,omitempty"`
	Reviewer     string   `json:"reviewer,omitempty"`
	CollectedAt  string   `json:"collected_at,omitempty"`
	Notes        string   `json:"notes,omitempty"`
}

// ExpectedVerdict is the reviewed paired output for one case.
type ExpectedVerdict struct {
	Verdict  string   `json:"verdict"`
	Score    int      `json:"score"`
	Policy   string   `json:"policy"`
	Decision string   `json:"decision"`
	Reasons  []string `json:"reasons"`
}

// ExpectedFile is the checked-in golden outputs for a corpus.
type ExpectedFile struct {
	SchemaVersion int                        `json:"schema_version"`
	Corpus        string                     `json:"corpus"`
	CorpusSHA256  string                     `json:"corpus_sha256"`
	ReviewedBy    string                     `json:"reviewed_by"`
	ReviewedAt    string                     `json:"reviewed_at"`
	Cases         map[string]ExpectedVerdict `json:"cases"`
}

// LoadCorpus reads and validates a corpus file. dir + file must stay
// inside the repository tree (safefile), so corpus paths cannot escape.
func LoadCorpus(dir, file string) (*Corpus, error) {
	data, err := safefile.ReadFileWithin(dir, file)
	if err != nil {
		return nil, fmt.Errorf("read corpus: %w", err)
	}
	var corpus Corpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		return nil, fmt.Errorf("parse corpus: %w", err)
	}
	sum := sha256.Sum256(data)
	corpus.SHA256 = hex.EncodeToString(sum[:])
	if err := corpus.Validate(); err != nil {
		return nil, err
	}
	return &corpus, nil
}

// Validate enforces schema and provenance discipline.
func (c *Corpus) Validate() error {
	if c.SchemaVersion != 1 {
		return fmt.Errorf("unsupported corpus schema %d", c.SchemaVersion)
	}
	if c.Kind != CorpusTruth && c.Kind != CorpusContract {
		return fmt.Errorf("unknown corpus kind %q", c.Kind)
	}
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("corpus name is required")
	}
	seen := make(map[string]bool, len(c.Cases))
	for i := range c.Cases {
		tc := &c.Cases[i]
		if err := tc.validate(c.Kind, seen); err != nil {
			return fmt.Errorf("case %d: %w", i, err)
		}
	}
	return nil
}

func (tc *Case) validate(kind string, seen map[string]bool) error {
	if strings.TrimSpace(tc.ID) == "" {
		return fmt.Errorf("id is required")
	}
	if seen[tc.ID] {
		return fmt.Errorf("duplicate id %q", tc.ID)
	}
	seen[tc.ID] = true
	if !validStrata[tc.Stratum] {
		return fmt.Errorf("case %q: unknown stratum %q", tc.ID, tc.Stratum)
	}
	switch tc.Security {
	case LabelSafe, LabelSuspicious, LabelMalicious, LabelUnknown, LabelInvalid:
	default:
		return fmt.Errorf("case %q: unknown security label %q", tc.ID, tc.Security)
	}
	switch tc.Confidence {
	case ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
	default:
		return fmt.Errorf("case %q: unknown confidence %q", tc.ID, tc.Confidence)
	}
	switch tc.Policy {
	case PolicyAllow, PolicyBlock, PolicyAny:
	default:
		return fmt.Errorf("case %q: unknown policy expectation %q", tc.ID, tc.Policy)
	}
	if kind == CorpusContract {
		switch tc.Intent {
		case IntentMustBlock, IntentMustAllow, IntentKnownGap, IntentCharacterize:
		default:
			return fmt.Errorf("case %q: contract intent %q is required", tc.ID, tc.Intent)
		}
		if tc.Intent == IntentKnownGap && strings.TrimSpace(tc.Notes) == "" {
			return fmt.Errorf("case %q: known_gap requires a note", tc.ID)
		}
		return tc.validateDomain()
	}
	// Truth provenance: high-confidence malicious claims require direct
	// evidence, a reviewer and a collection date. Medium allows pattern
	// and community provenance, explicitly marked. Unknown never gates.
	if tc.Security == LabelMalicious && tc.Confidence == ConfidenceHigh {
		if len(tc.Evidence) == 0 || strings.TrimSpace(tc.Reviewer) == "" || strings.TrimSpace(tc.CollectedAt) == "" {
			return fmt.Errorf("case %q: high-confidence malicious requires evidence, reviewer and collected_at", tc.ID)
		}
		switch tc.EvidenceKind {
		case "capture", "warning", "ownership-doc":
		default:
			return fmt.Errorf("case %q: high-confidence malicious requires direct evidence kind, got %q", tc.ID, tc.EvidenceKind)
		}
	}
	if tc.Security == LabelMalicious && tc.Confidence == ConfidenceMedium && len(tc.Evidence) == 0 {
		return fmt.Errorf("case %q: medium malicious requires evidence refs", tc.ID)
	}
	return tc.validateDomain()
}

func (tc *Case) validateDomain() error {
	if strings.TrimSpace(tc.Domain) == "" {
		return fmt.Errorf("case %q: domain is required", tc.ID)
	}
	if _, err := analysis.NormalizeDomain(tc.Domain); err != nil {
		if tc.Security == LabelInvalid {
			return nil
		}
		return fmt.Errorf("case %q: domain %q does not normalize: %v", tc.ID, tc.Domain, err)
	}
	if tc.Security == LabelInvalid {
		return fmt.Errorf("case %q: labeled invalid but domain normalizes", tc.ID)
	}
	return nil
}

// SortedIDs returns deterministic case order for replay.
func (c *Corpus) SortedIDs() []string {
	ids := make([]string, 0, len(c.Cases))
	for _, tc := range c.Cases {
		ids = append(ids, tc.ID)
	}
	sort.Strings(ids)
	return ids
}

// ByID indexes cases for lookup.
func (c *Corpus) ByID() map[string]Case {
	out := make(map[string]Case, len(c.Cases))
	for _, tc := range c.Cases {
		out[tc.ID] = tc
	}
	return out
}

// Gated returns truth cases eligible for precision/recall denominators:
// non-unknown labels at high or medium confidence.
func (c *Corpus) Gated() []Case {
	var out []Case
	for _, tc := range c.Cases {
		if c.Kind != CorpusTruth {
			continue
		}
		if tc.Security == LabelUnknown {
			continue
		}
		if tc.Confidence != ConfidenceHigh && tc.Confidence != ConfidenceMedium {
			continue
		}
		out = append(out, tc)
	}
	return out
}

// LoadExpected reads a golden expected-outputs file.
func LoadExpected(dir, file string) (*ExpectedFile, error) {
	data, err := safefile.ReadFileWithin(dir, file)
	if err != nil {
		return nil, fmt.Errorf("read expected: %w", err)
	}
	var expected ExpectedFile
	if err := json.Unmarshal(data, &expected); err != nil {
		return nil, fmt.Errorf("parse expected: %w", err)
	}
	if expected.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported expected schema %d", expected.SchemaVersion)
	}
	if strings.TrimSpace(expected.ReviewedBy) == "" {
		return nil, fmt.Errorf("expected outputs are unreviewed: reviewed_by is empty (generate with record, then human-review before check)")
	}
	return &expected, nil
}
