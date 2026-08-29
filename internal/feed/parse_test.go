package feed

import (
	"io"
	"strings"
	"testing"
)

// parseAll collects domains through the production ParseEach pipeline (the
// same entry point feed.Sync uses).
func parseAll(t *testing.T, reader io.Reader) ([]string, ParseStats) {
	t.Helper()
	var (
		domains []string
		stats   ParseStats
	)
	err := ParseEach(reader, func(domain string) error {
		domains = append(domains, domain)
		return nil
	}, &stats)
	if err != nil {
		t.Fatal(err)
	}
	return domains, stats
}

func TestParseEachTXT(t *testing.T) {
	domains, stats := parseAll(t, strings.NewReader(`
# comment
bad.test
https://evil.test/path
bad.test
bad test
`))

	if stats.Valid != 2 {
		t.Fatalf("expected 2 valid domains, got %d", stats.Valid)
	}
	if stats.Duplicates != 1 {
		t.Fatalf("expected 1 duplicate, got %d", stats.Duplicates)
	}
	if stats.Invalid != 1 {
		t.Fatalf("expected 1 invalid row, got %d", stats.Invalid)
	}
	if got := strings.Join(domains, ","); got != "bad.test,evil.test" {
		t.Fatalf("unexpected domains: %s", got)
	}
}

func TestParseEachCSV(t *testing.T) {
	domains, stats := parseAll(t, strings.NewReader("label,domain\nknown,bad.test\nurl,https://evil.test/path\n"))

	if stats.Valid != 2 {
		t.Fatalf("expected 2 valid domains, got %d", stats.Valid)
	}
	if got := strings.Join(domains, ","); got != "bad.test,evil.test" {
		t.Fatalf("unexpected domains: %s", got)
	}
}

func TestParseEachRejectsOverlongTextLine(t *testing.T) {
	var stats ParseStats
	err := ParseEach(strings.NewReader(strings.Repeat("a", 1024*1024+1)), func(string) error { return nil }, &stats)
	if err == nil || !strings.Contains(err.Error(), "feed line exceeds") {
		t.Fatalf("expected overlong line error, got %v", err)
	}
}

func TestParseEachHostsFileFormatIgnoresSinkholeIPs(t *testing.T) {
	domains, stats := parseAll(t, strings.NewReader(`
0.0.0.0 phishing.test
127.0.0.1 scam.test # inline comment
::1 ipv6-sinkhole.test
`))

	if stats.Valid != 3 {
		t.Fatalf("expected 3 valid domains, got %d", stats.Valid)
	}
	if stats.Invalid != 0 {
		t.Fatalf("expected sinkhole IPs not to count as invalid, got %d", stats.Invalid)
	}
	if got := strings.Join(domains, ","); got != "phishing.test,scam.test,ipv6-sinkhole.test" {
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
