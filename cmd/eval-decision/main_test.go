package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"safe-zone/internal/eval"
)

func TestSplitCorpusPath(t *testing.T) {
	dir, base, err := splitCorpusPath("data/corpus/decisions.json")
	if err != nil {
		t.Fatal(err)
	}
	if base != "decisions.json" || !strings.HasSuffix(filepath.ToSlash(dir), "corpus") {
		t.Fatalf("splitCorpusPath = %q, %q", dir, base)
	}
}

func TestFormatRatio(t *testing.T) {
	value := 0.5
	if got := formatRatio(&value); got != "0.5000" {
		t.Fatalf("formatRatio = %q", got)
	}
	if got := formatRatio(nil); got != "n/a" {
		t.Fatalf("formatRatio(nil) = %q", got)
	}
}

func TestWriteReportEmptyPathIsNoop(t *testing.T) {
	if err := writeReport("  ", &eval.Report{}); err != nil {
		t.Fatalf("empty out path should be a no-op, got %v", err)
	}
}

func TestWriteReportWritesJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := writeReport(path, &eval.Report{Corpus: "c", Cases: 3}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"corpus": "c"`) {
		t.Fatalf("unexpected report content: %s", data)
	}
}

func TestRunCheckRequiresFlags(t *testing.T) {
	if err := runCheck([]string{}); err == nil || !strings.Contains(err.Error(), "--corpus and --expected are required") {
		t.Fatalf("runCheck with no flags = %v", err)
	}
	if err := runCheck([]string{"--corpus", "a.json"}); err == nil {
		t.Fatal("runCheck without --expected should fail")
	}
}

func TestRunRecordRequiresFlags(t *testing.T) {
	if err := runRecord([]string{}); err == nil || !strings.Contains(err.Error(), "--corpus and --out are required") {
		t.Fatalf("runRecord with no flags = %v", err)
	}
}
