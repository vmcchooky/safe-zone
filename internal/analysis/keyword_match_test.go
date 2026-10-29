package analysis

import (
	"testing"

	"safe-zone/internal/config"
)

// Phishing keywords must match on token boundaries, not as raw substrings:
// "secure" inside "ssecure-pay.net" was previously counted, penalizing an
// unrelated label. Delimited tokens and token prefix/suffixes still match so
// real phishing compositions keep scoring.
func TestSuspiciousKeywordStatsTokenBoundaries(t *testing.T) {
	a := NewAnalyzerWithBrandStore(config.DefaultAnalysisConfig(), nil)

	cases := []struct {
		domain string
		want   int
	}{
		{"secure-login.example.com", 2},  // both tokens match
		{"ssecure-pay.net", 1},           // keyword as token suffix still hits
		{"unsecurable-host.net", 0},      // infix substring no longer hits
		{"paypal-verify.example.net", 1}, // suffix-ish token match
		{"nganhang247.com", 1},           // keyword prefix of token
		{"safe-update-host.com", 1},      // exact token
		{"clean-domain.net", 0},
	}
	for _, tc := range cases {
		gotCount, score := a.suspiciousKeywordStats(tc.domain)
		if gotCount != tc.want {
			t.Errorf("keyword matches for %q = %d, want %d (score %d)", tc.domain, gotCount, tc.want, score)
		}
	}
}
