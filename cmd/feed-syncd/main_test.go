package main

import (
	"testing"

	"safe-zone/internal/feed"
)

// A multi-source cycle runs one report per source. The completed log entry
// must name the source of that report, not the comma-joined settings value,
// otherwise every line in the cycle carries the same outside field and an
// operator cannot tell which feed produced it.
func TestFeedSyncCompletedFieldsUsesTheReportSource(t *testing.T) {
	joinedSettingsSource := "https://a.example/feed,https://b.example/feed"
	report := feed.SyncReport{
		Source:  "https://b.example/feed",
		Written: 9,
		Stats:   feed.ParseStats{Valid: 11, Invalid: 2},
	}

	fields := feedSyncCompletedFields(report, `{"source":"https://b.example/feed"}`)

	if got := fields["source"]; got != report.Source {
		t.Fatalf("source = %v, want %q", got, report.Source)
	}
	if got := fields["source"]; got == joinedSettingsSource {
		t.Fatalf("source = %v, want the per-report source, not the joined settings value", got)
	}
	if got := fields["written"]; got != int64(9) {
		t.Fatalf("written = %v, want 9", got)
	}
	if got := fields["valid"]; got != 11 {
		t.Fatalf("valid = %v, want 11", got)
	}
	if got := fields["invalid"]; got != 2 {
		t.Fatalf("invalid = %v, want 2", got)
	}
	if got := fields["report"]; got != `{"source":"https://b.example/feed"}` {
		t.Fatalf("report = %v, want the encoded report", got)
	}
}

func TestFeedSyncParserDriftFieldsUsesTheReportSource(t *testing.T) {
	report := feed.SyncReport{
		Source:            "https://b.example/feed",
		ParserDrift:       true,
		ParserDriftReason: "invalid ratio 0.42 above 0.20",
	}

	fields := feedSyncParserDriftFields(report)

	if got := fields["source"]; got != report.Source {
		t.Fatalf("source = %v, want %q", got, report.Source)
	}
	if got := fields["reason"]; got != report.ParserDriftReason {
		t.Fatalf("reason = %v, want %q", got, report.ParserDriftReason)
	}
}
