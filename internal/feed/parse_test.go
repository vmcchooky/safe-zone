package feed

import (
	"strings"
	"testing"
)

func TestParseTXT(t *testing.T) {
	result, err := Parse(strings.NewReader(`
# comment
bad.test
https://evil.test/path
bad.test
bad test
`))
	if err != nil {
		t.Fatal(err)
	}

	if result.Stats.Valid != 2 {
		t.Fatalf("expected 2 valid domains, got %d", result.Stats.Valid)
	}
	if result.Stats.Duplicates != 1 {
		t.Fatalf("expected 1 duplicate, got %d", result.Stats.Duplicates)
	}
	if result.Stats.Invalid != 1 {
		t.Fatalf("expected 1 invalid row, got %d", result.Stats.Invalid)
	}
	if got := strings.Join(result.Domains, ","); got != "bad.test,evil.test" {
		t.Fatalf("unexpected domains: %s", got)
	}
}

func TestParseCSV(t *testing.T) {
	result, err := Parse(strings.NewReader("label,domain\nknown,bad.test\nurl,https://evil.test/path\n"))
	if err != nil {
		t.Fatal(err)
	}

	if result.Stats.Valid != 2 {
		t.Fatalf("expected 2 valid domains, got %d", result.Stats.Valid)
	}
	if got := strings.Join(result.Domains, ","); got != "bad.test,evil.test" {
		t.Fatalf("unexpected domains: %s", got)
	}
}

func TestParseRejectsOverlongTextLine(t *testing.T) {
	_, err := Parse(strings.NewReader(strings.Repeat("a", 1024*1024+1)))
	if err == nil || !strings.Contains(err.Error(), "feed line exceeds") {
		t.Fatalf("expected overlong line error, got %v", err)
	}
}
