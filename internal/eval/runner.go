package eval

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/config"
	"safe-zone/internal/domaintrie"
	"safe-zone/internal/feed"
	"safe-zone/internal/risk"
)

// Observation is the deterministic subset of an evaluation compared
// against golden outputs. Timings, decision IDs and timestamps are
// excluded by construction so replays are stable.
type Observation struct {
	Verdict  string   `json:"verdict"`
	Score    int      `json:"score"`
	Policy   string   `json:"policy"`
	Decision string   `json:"decision"`
	Reasons  []string `json:"reasons"`
}

// CaseResult pairs a case with its observation and comparison outcome.
type CaseResult struct {
	ID        string      `json:"id"`
	Domain    string      `json:"domain"`
	Stratum   string      `json:"stratum"`
	Security  string      `json:"security"`
	Observed  Observation `json:"observed"`
	Excluded  string      `json:"excluded,omitempty"`
	Match     bool        `json:"match"`
	Diffs     []string    `json:"diffs,omitempty"`
	Invariant string      `json:"invariant_violation,omitempty"`
}

// TruthMetrics reports gated-set performance with explicit denominators.
// Unknown labels never enter these numbers.
type TruthMetrics struct {
	Gated           int            `json:"gated"`
	TruePositive    int            `json:"true_positive"`
	TrueNegative    int            `json:"true_negative"`
	FalsePositive   int            `json:"false_positive"`
	FalseNegative   int            `json:"false_negative"`
	Accuracy        *float64       `json:"accuracy,omitempty"`
	Precision       *float64       `json:"precision,omitempty"`
	Recall          *float64       `json:"recall,omitempty"`
	FPR             *float64       `json:"false_positive_rate,omitempty"`
	PolicyAgreement int            `json:"policy_agreement"`
	PolicyChecked   int            `json:"policy_checked"`
	UnknownExcluded int            `json:"unknown_excluded"`
	ByStratum       map[string]int `json:"by_stratum_gated"`
	ConfidenceMix   map[string]int `json:"confidence_mix"`
}

// ContractSummary counts behavioral pins by intent.
type ContractSummary struct {
	MustBlock    int `json:"must_block"`
	MustAllow    int `json:"must_allow"`
	KnownGaps    int `json:"known_gaps"`
	Characterize int `json:"characterize"`
	Mismatches   int `json:"mismatches"`
}

// Report is the full replay output.
type Report struct {
	SchemaVersion    string          `json:"schema_version"`
	GeneratedAt      string          `json:"generated_at"`
	Corpus           string          `json:"corpus"`
	CorpusSHA256     string          `json:"corpus_sha256"`
	SourceCommit     string          `json:"source_commit"`
	Runner           map[string]any  `json:"runner"`
	Cases            int             `json:"cases"`
	Deterministic    bool            `json:"deterministic"`
	NonDeterministic []string        `json:"non_deterministic,omitempty"`
	Truth            TruthMetrics    `json:"truth"`
	Contract         ContractSummary `json:"contract"`
	InvariantIssues  []string        `json:"invariant_violations,omitempty"`
	Results          []CaseResult    `json:"results"`
}

// Runner executes a corpus against a frozen, hermetic service: miniredis
// feed, pinned adblock trie, lexical-only engine (ML/AI/OSINT/enrichment
// disabled), default group. No network, no wall-clock in comparisons.
type Runner struct {
	service  *risk.Service
	feedAddr string
	closers  []func()
}

// NewRunner builds the frozen profile. Close releases miniredis and the
// service when done.
func NewRunner() (*Runner, error) {
	mr, err := miniredis.Run()
	if err != nil {
		return nil, fmt.Errorf("start fixture redis: %w", err)
	}
	svc := risk.NewService(risk.Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		Redis:              cache.NewRedis(mr.Addr(), "", 0),
		RedisTimeout:       time.Second,
		TTLAllowed:         time.Hour,
		TTLSuspicious:      time.Hour,
		TTLBlocked:         time.Hour,
		DisableAdblockSync: true,
	})
	return &Runner{
		service:  svc,
		feedAddr: mr.Addr(),
		closers:  []func(){mr.Close, func() { _ = svc.Close() }},
	}, nil
}

// Close releases runner resources.
func (r *Runner) Close() {
	for _, fn := range r.closers {
		fn()
	}
}

// LoadFixtures installs corpus feed members (24h future expiry) and the
// frozen adblock snapshot.
func (r *Runner) LoadFixtures(corpus *Corpus) error {
	if len(corpus.FeedMembers) == 0 && len(corpus.AdblockRules) == 0 {
		return nil
	}
	if len(corpus.FeedMembers) > 0 {
		direct := redis.NewClient(&redis.Options{Addr: r.feedAddr})
		defer func() { _ = direct.Close() }()
		expiry := float64(time.Now().Add(24 * time.Hour).Unix())
		members := make([]redis.Z, 0, len(corpus.FeedMembers))
		for _, domain := range corpus.FeedMembers {
			members = append(members, redis.Z{Score: expiry, Member: domain})
		}
		if err := direct.ZAdd(context.Background(), feed.DefaultThreatFeedKey, members...).Err(); err != nil {
			return fmt.Errorf("seed feed: %w", err)
		}
	}
	if len(corpus.AdblockRules) > 0 {
		trie := domaintrie.NewTrie()
		for _, rule := range corpus.AdblockRules {
			trie.Add(rule)
		}
		r.service.AdblockTrieOverride(trie)
	}
	return nil
}

// Observe runs one domain through Analyze and Policy and reduces both to
// the deterministic comparison subset.
func (r *Runner) Observe(domain string) Observation {
	ctx := context.Background()
	api := r.service.Analyze(ctx, domain, risk.ClientInfo{})
	pol := r.service.Policy(ctx, domain, risk.ClientInfo{})
	decision := ""
	if pol.Decision != nil {
		decision = pol.Decision.Action + "|" + pol.Decision.Kind + "|" + pol.Decision.Category
	}
	return Observation{
		Verdict:  string(api.Verdict),
		Score:    api.Score,
		Policy:   pol.Policy,
		Decision: decision,
		Reasons:  append([]string(nil), api.Reasons...),
	}
}

// verdictLabel maps engine verdicts to corpus label vocabulary.
func verdictLabel(v analysis.Verdict) string {
	switch v {
	case analysis.VerdictSafe:
		return LabelSafe
	case analysis.VerdictSuspicious:
		return LabelSuspicious
	case analysis.VerdictMalicious:
		return LabelMalicious
	default:
		return LabelInvalid
	}
}

// observedLabel maps a recorded observation back to label vocabulary.
func observedLabel(obs Observation) string {
	return verdictLabel(analysis.Verdict(obs.Verdict))
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ratio(numerator, denominator int) *float64 {
	if denominator <= 0 {
		return nil
	}
	value := float64(numerator) / float64(denominator)
	return &value
}

// Check replays the corpus against expected outputs. It returns the
// report; mismatches and invariant violations are recorded, never hidden.
func (r *Runner) Check(corpus *Corpus, expected *ExpectedFile) *Report {
	byID := corpus.ByID()
	report := &Report{
		SchemaVersion: "1",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		Corpus:        corpus.Name,
		CorpusSHA256:  corpus.SHA256,
		Runner: map[string]any{
			"ml_mode": "disabled", "enrichment": false, "osint": false,
			"ai": false, "admission": "legacy", "group": "default",
		},
		Truth: TruthMetrics{
			ByStratum:     make(map[string]int),
			ConfidenceMix: make(map[string]int),
		},
	}
	for _, id := range corpus.SortedIDs() {
		tc := byID[id]
		obs := r.Observe(tc.Domain)
		res := CaseResult{
			ID: id, Domain: tc.Domain, Stratum: tc.Stratum,
			Security: tc.Security, Observed: obs, Match: true,
		}
		// Structural invariant: a SAFE verdict paired with a block is
		// only expressible with an explicit content decision. INVALID
		// fail-closed blocks are default-deny, not masquerade.
		if obs.Policy == PolicyBlock && observedLabel(obs) == LabelSafe && obs.Decision == "" {
			res.Invariant = "block_without_content_decision"
			res.Match = false
			report.InvariantIssues = append(report.InvariantIssues, id)
		}
		if corpus.Kind == CorpusTruth {
			r.checkTruth(&res, tc, expected, report)
		} else {
			r.checkContract(&res, tc, expected, report)
		}
		report.Results = append(report.Results, res)
	}
	report.Cases = len(report.Results)
	finalizeTruthMetrics(report)
	sort.Strings(report.InvariantIssues)
	return report
}

func (r *Runner) checkTruth(res *CaseResult, tc Case, expected *ExpectedFile, report *Report) {
	if tc.Security == LabelUnknown {
		report.Truth.UnknownExcluded++
		res.Excluded = "unknown-label"
		return
	}
	if tc.Confidence != ConfidenceHigh && tc.Confidence != ConfidenceMedium {
		res.Excluded = "low-confidence"
		return
	}
	report.Truth.Gated++
	report.Truth.ByStratum[tc.Stratum]++
	report.Truth.ConfidenceMix[tc.Confidence]++
	obs := res.Observed
	obsLabel := observedLabel(obs)
	// Label gaps are measured, never gated: the golden expected file is
	// the regression gate, so a documented false positive (or a future
	// fix flipping it) shows up in metrics and in golden diffs, not as a
	// contradiction inside one run.
	if obsLabel != tc.Security {
		res.Diffs = append(res.Diffs, fmt.Sprintf("label-gap: observed %s, labeled %s", obs.Verdict, tc.Security))
	}
	switch {
	case tc.Security == LabelMalicious && obsLabel == LabelMalicious:
		report.Truth.TruePositive++
	case tc.Security == LabelMalicious:
		report.Truth.FalseNegative++
	case obsLabel == LabelMalicious:
		report.Truth.FalsePositive++
	case tc.Security == LabelSafe && obsLabel == LabelSafe:
		report.Truth.TrueNegative++
	case tc.Security == LabelInvalid && obsLabel == LabelInvalid:
		report.Truth.TrueNegative++
	}
	if tc.Policy != PolicyAny {
		report.Truth.PolicyChecked++
		if obs.Policy == tc.Policy {
			report.Truth.PolicyAgreement++
		} else {
			res.Match = false
			res.Diffs = append(res.Diffs, fmt.Sprintf("policy: observed %s, expected %s", obs.Policy, tc.Policy))
		}
	}
	if expected != nil {
		r.checkExpected(res, tc, expected, report)
	}
}

func (r *Runner) checkContract(res *CaseResult, tc Case, expected *ExpectedFile, report *Report) {
	obs := res.Observed
	obsLabel := observedLabel(obs)
	switch tc.Intent {
	case IntentMustBlock:
		// Policy behavior only; the exact security verdict is pinned by
		// the expected file (content blocks stay non-malicious there).
		report.Contract.MustBlock++
		if obs.Policy != PolicyBlock {
			res.Match = false
			res.Diffs = append(res.Diffs, fmt.Sprintf("must_block violated: policy %s", obs.Policy))
			report.Contract.Mismatches++
		}
	case IntentMustAllow:
		report.Contract.MustAllow++
		if obsLabel != LabelSafe || obs.Policy != PolicyAllow {
			res.Match = false
			res.Diffs = append(res.Diffs, fmt.Sprintf("must_allow violated: %s/%s", obs.Verdict, obs.Policy))
			report.Contract.Mismatches++
		}
	case IntentKnownGap:
		report.Contract.KnownGaps++
		res.Excluded = "known-gap"
	case IntentCharacterize:
		report.Contract.Characterize++
		res.Excluded = "characterize"
	}
	if expected != nil && res.Excluded == "" {
		r.checkExpected(res, tc, expected, report)
	}
}

func (r *Runner) checkExpected(res *CaseResult, tc Case, expected *ExpectedFile, report *Report) {
	want, ok := expected.Cases[tc.ID]
	if !ok {
		res.Match = false
		res.Diffs = append(res.Diffs, "missing from expected file")
		return
	}
	obs := res.Observed
	if obs.Verdict != want.Verdict || obs.Score != want.Score || obs.Policy != want.Policy ||
		obs.Decision != want.Decision || !equalStrings(obs.Reasons, want.Reasons) {
		res.Match = false
		res.Diffs = append(res.Diffs, fmt.Sprintf(
			"expected %+v, observed %+v", want, obs))
	}
}

func finalizeTruthMetrics(report *Report) {
	t := &report.Truth
	t.Accuracy = ratio(t.TruePositive+t.TrueNegative, t.Gated)
	t.Precision = ratio(t.TruePositive, t.TruePositive+t.FalsePositive)
	t.Recall = ratio(t.TruePositive, t.TruePositive+t.FalseNegative)
	t.FPR = ratio(t.FalsePositive, t.FalsePositive+t.TrueNegative)
}

// VerifyDeterministic replays every case twice; any verdict drift fails.
func (r *Runner) VerifyDeterministic(corpus *Corpus) []string {
	byID := corpus.ByID()
	var drifts []string
	for _, id := range corpus.SortedIDs() {
		first := r.Observe(byID[id].Domain)
		second := r.Observe(byID[id].Domain)
		if first.Verdict != second.Verdict || first.Score != second.Score ||
			first.Policy != second.Policy || first.Decision != second.Decision ||
			!equalStrings(first.Reasons, second.Reasons) {
			drifts = append(drifts, id)
		}
	}
	sort.Strings(drifts)
	return drifts
}

// Record builds an unreviewed expected file from live observations. The
// output always carries an empty reviewed_by: Check refuses it until a
// human reviews every line and signs.
func (r *Runner) Record(corpus *Corpus) *ExpectedFile {
	out := &ExpectedFile{
		SchemaVersion: 1,
		Corpus:        corpus.Name,
		CorpusSHA256:  corpus.SHA256,
		Cases:         make(map[string]ExpectedVerdict, len(corpus.Cases)),
	}
	byID := corpus.ByID()
	for _, id := range corpus.SortedIDs() {
		out.Cases[id] = ExpectedVerdict(r.Observe(byID[id].Domain))
	}
	return out
}
