package main

import (
	"strings"
	"testing"
	"time"
)

// time.NewTicker panics on a non-positive duration. parseSyncSettings already
// refuses a bad TTL, churn window, admission mode and empty source, so a
// non-positive interval was the one input that reached the ticker and crashed the
// daemon.
//
// feed.CheckChurnTTLAgainstInterval does take the interval, but it returns nil
// immediately when no churn window is configured — which is the default — so the
// default configuration never validated it.

func syncSettingsFor(t *testing.T, args ...string) (syncSettings, error) {
	t.Helper()
	flags := newTestFlagSet(t)
	return parseSyncSettings(flags, args)
}

func TestParseSyncSettingsRejectsNonPositiveInterval(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		// wantMessage is the refusal this case should produce. "--interval -1" is
		// not a duration string, so the flag package refuses it as a parse error
		// before this validation runs. That is a correct outcome too, just an
		// earlier one, so it is not held to the message below.
		wantMessage string
	}{
		{name: "zero", args: []string{"--source", "feed.txt", "--interval", "0s"}, wantMessage: "interval must be positive"},
		{name: "negative", args: []string{"--source", "feed.txt", "--interval", "-5s"}, wantMessage: "interval must be positive"},
		{name: "negative seconds", args: []string{"--source", "feed.txt", "--interval", "-1s"}, wantMessage: "interval must be positive"},
		{name: "bare negative", args: []string{"--source", "feed.txt", "--interval", "-1"}},
		{name: "zero with churn configured", args: []string{"--source", "feed.txt", "--interval", "0s", "--churn-ttl-days", "3"}, wantMessage: "interval must be positive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings, err := syncSettingsFor(t, tc.args...)
			if err == nil {
				t.Fatalf("parseSyncSettings accepted %v with interval %s; "+
					"time.NewTicker panics on that", tc.args, settings.Interval)
			}
			if tc.wantMessage != "" && !strings.Contains(err.Error(), tc.wantMessage) {
				t.Fatalf("error = %q, want it to say %q", err, tc.wantMessage)
			}
		})
	}
}

// A positive interval must keep working, so the validation cannot be a blanket
// refusal.
func TestParseSyncSettingsAcceptsAPositiveInterval(t *testing.T) {
	for _, d := range []time.Duration{time.Second, time.Hour, 24 * time.Hour} {
		settings, err := syncSettingsFor(t, "--source", "feed.txt", "--interval", d.String())
		if err != nil {
			t.Fatalf("interval %s was refused: %v", d, err)
		}
		if settings.Interval != d {
			t.Fatalf("interval = %s, want the supplied %s", settings.Interval, d)
		}
	}
}

// The validation must not change the documented default.
func TestParseSyncSettingsKeepsTheDefaultInterval(t *testing.T) {
	t.Setenv("SAFE_ZONE_FEED_SYNC_INTERVAL_SECONDS", "")
	settings, err := syncSettingsFor(t, "--source", "feed.txt")
	if err != nil {
		t.Fatalf("default configuration refused: %v", err)
	}
	if settings.Interval != 24*time.Hour {
		t.Fatalf("default interval = %s, want 24h", settings.Interval)
	}
}
