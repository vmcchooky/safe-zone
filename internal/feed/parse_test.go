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

func TestParseHostsFileFormatIgnoresSinkholeIPs(t *testing.T) {
	result, err := Parse(strings.NewReader(`
0.0.0.0 phishing.test
127.0.0.1 scam.test # inline comment
::1 ipv6-sinkhole.test
`))
	if err != nil {
		t.Fatal(err)
	}

	if result.Stats.Valid != 3 {
		t.Fatalf("expected 3 valid domains, got %d", result.Stats.Valid)
	}
	if result.Stats.Invalid != 0 {
		t.Fatalf("expected sinkhole IPs not to count as invalid, got %d", result.Stats.Invalid)
	}
	if got := strings.Join(result.Domains, ","); got != "phishing.test,scam.test,ipv6-sinkhole.test" {
		t.Fatalf("unexpected domains: %s", got)
	}
}

func TestParseEachIndicatorPreservesURLScopeAndDuplicates(t *testing.T) {
	var indicators []Indicator
	var duplicates []bool
	var stats ParseStats
	err := ParseEachIndicator(strings.NewReader("https://evil.test/login\nhttps://evil.test/reset\nclean.test\n"), func(indicator Indicator, duplicate bool) error {
		indicators = append(indicators, indicator)
		duplicates = append(duplicates, duplicate)
		return nil
	}, &stats)
	if err != nil {
		t.Fatal(err)
	}
	if len(indicators) != 3 || indicators[0].Kind != IndicatorURL || !indicators[0].PathScoped {
		t.Fatalf("unexpected indicators: %#v", indicators)
	}
	if !duplicates[1] || duplicates[0] || duplicates[2] {
		t.Fatalf("unexpected duplicate flags: %#v", duplicates)
	}
	if stats.Valid != 2 || stats.Duplicates != 1 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
}

func TestParseEachIndicatorPreservesURLFragmentScope(t *testing.T) {
	var got Indicator
	err := ParseEachIndicator(strings.NewReader("https://evil.test/#login\n"), func(indicator Indicator, _ bool) error {
		got = indicator
		return nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !got.PathScoped || got.resourceFingerprint == [32]byte{} {
		t.Fatalf("expected fragment-scoped URL indicator, got %#v", got)
	}
}
