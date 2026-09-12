// Command eval-decision runs the frozen end-to-end decision evaluation:
// replay a versioned corpus through Analyze and Policy and compare paired
// Security+Policy outputs against reviewed golden expectations.
//
//	check --corpus <file> --expected <file> [--out report.json]
//	record --corpus <file> --out expected.json
//
// Record output is always unsigned (reviewed_by empty) and check refuses
// it until a human reviews every line and signs.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"safe-zone/internal/buildinfo"
	"safe-zone/internal/eval"
	"safe-zone/internal/logjson"
)

func main() {
	buildinfo.Link()
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: eval-decision <check|record> [flags]")
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "check":
		err = runCheck(os.Args[2:])
	case "record":
		err = runRecord(os.Args[2:])
	default:
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "eval-decision failed:", err)
		os.Exit(1)
	}
}

func splitCorpusPath(path string) (string, string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}
	return filepath.Dir(abs), filepath.Base(abs), nil
}

func writeReport(path string, report *eval.Report) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, encoded, 0o600)
}

func printSummary(report *eval.Report) {
	fmt.Printf("corpus=%s cases=%d deterministic=%v\n", report.Corpus, report.Cases, report.Deterministic)
	t := report.Truth
	fmt.Printf("truth gated=%d tp=%d tn=%d fp=%d fn=%d unknown_excluded=%d\n",
		t.Gated, t.TruePositive, t.TrueNegative, t.FalsePositive, t.FalseNegative, t.UnknownExcluded)
	fmt.Printf("precision=%s recall=%s fpr=%s policy_agreement=%d/%d\n",
		formatRatio(t.Precision), formatRatio(t.Recall), formatRatio(t.FPR), t.PolicyAgreement, t.PolicyChecked)
	fmt.Printf("contract must_block=%d must_allow=%d known_gaps=%d characterize=%d mismatches=%d\n",
		report.Contract.MustBlock, report.Contract.MustAllow, report.Contract.KnownGaps,
		report.Contract.Characterize, report.Contract.Mismatches)
	if len(report.InvariantIssues) > 0 {
		fmt.Printf("INVARIANT VIOLATIONS: %s\n", strings.Join(report.InvariantIssues, ","))
	}
	for _, res := range report.Results {
		if !res.Match && res.Excluded == "" {
			fmt.Printf("MISMATCH %s %s: %s\n", res.ID, res.Domain, strings.Join(res.Diffs, "; "))
		}
	}
	for _, res := range report.Results {
		for _, diff := range res.Diffs {
			if strings.HasPrefix(diff, "label-gap:") {
				fmt.Printf("LABEL-GAP %s %s: %s\n", res.ID, res.Domain, diff)
			}
		}
	}
}

func formatRatio(value *float64) string {
	if value == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.4f", *value)
}

func runCheck(args []string) error {
	flags := flag.NewFlagSet("check", flag.ContinueOnError)
	corpusPath := flags.String("corpus", "", "corpus JSON file")
	expectedPath := flags.String("expected", "", "reviewed expected-outputs JSON file")
	outPath := flags.String("out", "", "optional report JSON path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*corpusPath) == "" || strings.TrimSpace(*expectedPath) == "" {
		return errors.New("--corpus and --expected are required")
	}
	corpusDir, corpusFile, err := splitCorpusPath(*corpusPath)
	if err != nil {
		return err
	}
	corpus, err := eval.LoadCorpus(corpusDir, corpusFile)
	if err != nil {
		return err
	}
	expDir, expFile, err := splitCorpusPath(*expectedPath)
	if err != nil {
		return err
	}
	expected, err := eval.LoadExpected(expDir, expFile)
	if err != nil {
		return err
	}
	if expected.CorpusSHA256 != corpus.SHA256 {
		return fmt.Errorf("expected file targets corpus %s, loaded %s: re-record and re-review", expected.CorpusSHA256, corpus.SHA256)
	}
	runner, err := eval.NewRunner()
	if err != nil {
		return err
	}
	defer runner.Close()
	if err := runner.LoadFixtures(corpus); err != nil {
		return err
	}
	if drifts := runner.VerifyDeterministic(corpus); len(drifts) > 0 {
		return fmt.Errorf("non-deterministic cases: %s", strings.Join(drifts, ","))
	}
	report := runner.Check(corpus, expected)
	if drifts := runner.VerifyDeterministic(corpus); len(drifts) > 0 {
		report.Deterministic = false
		report.NonDeterministic = drifts
		printSummary(report)
		if err := writeReport(*outPath, report); err != nil {
			return err
		}
		return fmt.Errorf("non-deterministic cases: %s", strings.Join(drifts, ","))
	}
	report.Deterministic = true
	printSummary(report)
	if err := writeReport(*outPath, report); err != nil {
		return err
	}
	failed := 0
	for _, res := range report.Results {
		if !res.Match && res.Excluded == "" {
			failed++
		}
	}
	if len(report.InvariantIssues) > 0 || failed > 0 {
		logjson.Error("eval-decision check failed", map[string]any{
			"service":    "eval-decision",
			"mismatches": failed,
			"invariant":  len(report.InvariantIssues),
		})
		return fmt.Errorf("%d mismatches, %d invariant violations", failed, len(report.InvariantIssues))
	}
	return nil
}

func runRecord(args []string) error {
	flags := flag.NewFlagSet("record", flag.ContinueOnError)
	corpusPath := flags.String("corpus", "", "corpus JSON file")
	outPath := flags.String("out", "", "expected-outputs JSON path to write")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*corpusPath) == "" || strings.TrimSpace(*outPath) == "" {
		return errors.New("--corpus and --out are required")
	}
	corpusDir, corpusFile, err := splitCorpusPath(*corpusPath)
	if err != nil {
		return err
	}
	corpus, err := eval.LoadCorpus(corpusDir, corpusFile)
	if err != nil {
		return err
	}
	runner, err := eval.NewRunner()
	if err != nil {
		return err
	}
	defer runner.Close()
	if err := runner.LoadFixtures(corpus); err != nil {
		return err
	}
	expected := runner.Record(corpus)
	encoded, err := json.MarshalIndent(expected, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*outPath, encoded, 0o600); err != nil {
		return err
	}
	fmt.Printf("recorded %d cases for corpus %s (%s); reviewed_by is empty: human review required before check\n",
		len(expected.Cases), corpus.Name, corpus.SHA256)
	return nil
}
