package feedsync

import (
	"errors"
	"flag"
	"net/http"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/feed"
)

func newTestFlagSet(t *testing.T) *flag.FlagSet {
	t.Helper()
	return flag.NewFlagSet("feed-syncd-test", flag.ContinueOnError)
}

func syncSettingsFor(t *testing.T, args ...string) (Settings, error) {
	t.Helper()
	flags := newTestFlagSet(t)
	return ParseSettings(ModeDaemon, flags, args)
}

// time.NewTicker panics on a non-positive duration. ParseSettings already
// refuses a bad TTL, churn window, admission mode and empty source, so a
// non-positive interval was the one input that reached the ticker and crashed the
// daemon.
//
// feed.CheckChurnTTLAgainstInterval does take the interval, but it returns nil
// immediately when no churn window is configured — which is the default — so the
// default configuration never validated it.
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
				t.Fatalf("ParseSettings accepted %v with interval %s; "+
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

// The daemon must resolve the same effective TTL contract as the one-shot
// feed-sync tool: SAFE_ZONE_FEED_TTL_DAYS with a 14-day default, validated
// through feed.TTLFromDays.
func TestSyncSettingsTTLParityWithFeedSync(t *testing.T) {
	t.Setenv("SAFE_ZONE_FEED_TTL_DAYS", "")
	t.Setenv("SAFE_ZONE_THREAT_FEED_SOURCE", "https://feeds.example.test/list.txt")
	t.Setenv("SAFE_ZONE_FEED_ADMISSION_MODE", "")

	settings, err := ParseSettings(ModeDaemon, newTestFlagSet(t), nil)
	if err != nil {
		t.Fatalf("parse default settings: %v", err)
	}
	if settings.TTL != 14*24*time.Hour {
		t.Fatalf("expected default TTL 14d (matching feed-sync), got %v", settings.TTL)
	}

	t.Setenv("SAFE_ZONE_FEED_TTL_DAYS", "21")
	settings, err = ParseSettings(ModeDaemon, newTestFlagSet(t), nil)
	if err != nil {
		t.Fatalf("parse configured settings: %v", err)
	}
	if settings.TTL != 21*24*time.Hour {
		t.Fatalf("expected configured TTL 21d, got %v", settings.TTL)
	}

	if _, err := feed.TTLFromDays(0); err == nil {
		t.Fatal("non-positive TTL must be rejected like feed-sync does")
	}
}

// The admission-mode contract matches feed-sync: unknown modes are rejected
// and the evaluation-only filter mode is refused at runtime.
func TestSyncSettingsRejectsInvalidAdmissionMode(t *testing.T) {
	t.Setenv("SAFE_ZONE_FEED_ADMISSION_MODE", "not-a-mode")
	if _, err := ParseSettings(ModeDaemon, newTestFlagSet(t), nil); err == nil {
		t.Fatal("expected invalid admission mode rejection")
	}

	t.Setenv("SAFE_ZONE_FEED_ADMISSION_MODE", string(feed.AdmissionFilter))
	_, err := ParseSettings(ModeDaemon, newTestFlagSet(t), nil)
	if err == nil || !errors.Is(err, errFilterEvaluationOnly) {
		t.Fatalf("expected evaluation-only rejection, got %v", err)
	}
}

func TestSyncSettingsRequiresSource(t *testing.T) {
	t.Setenv("SAFE_ZONE_FEED_ADMISSION_MODE", "")
	t.Setenv("SAFE_ZONE_THREAT_FEED_SOURCE", "")
	if _, err := ParseSettings(ModeDaemon, newTestFlagSet(t), nil); !errors.Is(err, errSourceRequired) {
		t.Fatalf("expected missing source rejection, got %v", err)
	}
}

// BuildSyncOptions must translate settings into the shared feed.Sync
// contract without dropping the TTL.
func TestBuildSyncOptionsCarriesTTL(t *testing.T) {
	settings := Settings{
		Source:        "https://feeds.example.test/list.txt",
		RedisAddr:     "127.0.0.1:6379",
		Key:           feed.DefaultThreatFeedKey,
		Replace:       true,
		Timeout:       30 * time.Second,
		AdmissionMode: feed.AdmissionLegacy,
		TTL:           7 * 24 * time.Hour,
	}
	options := BuildSyncOptions(settings, http.DefaultClient)
	if options.TTL != settings.TTL {
		t.Fatalf("expected TTL to carry through, got %v", options.TTL)
	}
	if options.Key != settings.Key || options.Source != settings.Source {
		t.Fatalf("expected source/key passthrough, got %+v", options)
	}
}

// AllowInsecureHTTP must default false and pass through to feed.Sync so
// the daemon never silently fetches plain-HTTP feeds.
func TestSyncSettingsAllowInsecureDefaultsFalse(t *testing.T) {
	t.Setenv("SAFE_ZONE_THREAT_FEED_SOURCE", "https://feeds.example.test/list.txt")
	t.Setenv("SAFE_ZONE_FEED_ADMISSION_MODE", "")
	t.Setenv("SAFE_ZONE_FEED_ALLOW_INSECURE_HTTP", "")

	settings, err := ParseSettings(ModeDaemon, newTestFlagSet(t), nil)
	if err != nil {
		t.Fatalf("parse default settings: %v", err)
	}
	if settings.AllowInsecure {
		t.Fatal("expected AllowInsecure default false")
	}
	if options := BuildSyncOptions(settings, http.DefaultClient); options.AllowInsecureHTTP {
		t.Fatal("expected AllowInsecureHTTP passthrough false")
	}

	t.Setenv("SAFE_ZONE_FEED_ALLOW_INSECURE_HTTP", "true")
	settings, err = ParseSettings(ModeDaemon, newTestFlagSet(t), []string{"-allow-insecure-http"})
	if err != nil {
		t.Fatalf("parse opt-in settings: %v", err)
	}
	if options := BuildSyncOptions(settings, http.DefaultClient); !options.AllowInsecureHTTP {
		t.Fatal("expected AllowInsecureHTTP passthrough true")
	}
}

// Replace defaults to false so multiple writers (one daemon per source,
// or the one-shot loop) can share a feed key without staging renames
// wiping each other. Single-source freshness then rests on per-member TTL
// expiry instead of whole-key replacement.
func TestSyncSettingsReplaceDefaultsFalse(t *testing.T) {
	t.Setenv("SAFE_ZONE_THREAT_FEED_SOURCE", "https://feeds.example.test/list.txt")
	t.Setenv("SAFE_ZONE_FEED_ADMISSION_MODE", "")

	settings, err := ParseSettings(ModeDaemon, newTestFlagSet(t), nil)
	if err != nil {
		t.Fatalf("parse default settings: %v", err)
	}
	if settings.Replace {
		t.Fatal("expected replace=false by default so concurrent writers cannot clobber the shared key")
	}
}

// Explicit --replace keeps working for operators who dedicate one key to
// one daemon and want immediate removal of delisted members.
func TestSyncSettingsReplaceExplicitOptIn(t *testing.T) {
	t.Setenv("SAFE_ZONE_THREAT_FEED_SOURCE", "https://feeds.example.test/list.txt")
	t.Setenv("SAFE_ZONE_FEED_ADMISSION_MODE", "")

	settings, err := ParseSettings(ModeDaemon, newTestFlagSet(t), []string{"-replace"})
	if err != nil {
		t.Fatalf("parse explicit replace settings: %v", err)
	}
	if !settings.Replace {
		t.Fatal("expected explicit -replace to stay enabled")
	}
}

// The one-shot shares the strict admission validation now: an invalid mode
// or the evaluation-only filter is refused at parse time instead of being
// passed through raw to feed.Sync. This pins the intentional alignment.
func TestOneShotModeRejectsInvalidAdmissionMode(t *testing.T) {
	t.Setenv("SAFE_ZONE_FEED_ADMISSION_MODE", "not-a-mode")
	if _, err := ParseSettings(ModeOneShot, newTestFlagSet(t), []string{"--source", "feed.txt"}); err == nil {
		t.Fatal("expected invalid admission mode rejection in one-shot mode")
	}

	t.Setenv("SAFE_ZONE_FEED_ADMISSION_MODE", string(feed.AdmissionFilter))
	_, err := ParseSettings(ModeOneShot, newTestFlagSet(t), []string{"--source", "feed.txt"})
	if err == nil || !errors.Is(err, errFilterEvaluationOnly) {
		t.Fatalf("expected evaluation-only rejection in one-shot mode, got %v", err)
	}
}

// The churn-vs-interval check needs a schedule, which the one-shot has none
// of, so it applies in daemon mode only. A churn window that would be refused
// on a 24h daemon schedule must still parse for the one-shot.
func TestOneShotModeSkipsChurnIntervalCheck(t *testing.T) {
	t.Setenv("SAFE_ZONE_FEED_ADMISSION_MODE", "")
	if _, err := ParseSettings(ModeOneShot, newTestFlagSet(t), []string{"--source", "feed.txt", "--churn-ttl-days", "3"}); err != nil {
		t.Fatalf("one-shot has no interval to check churn against, must parse: %v", err)
	}
}

// The one-shot owns --dry-run and the daemon owns --once/--interval: each
// mode must refuse the other's flags rather than silently ignoring them.
func TestModesRejectEachOthersFlags(t *testing.T) {
	t.Setenv("SAFE_ZONE_FEED_ADMISSION_MODE", "")
	if _, err := ParseSettings(ModeOneShot, newTestFlagSet(t), []string{"--source", "feed.txt", "--once"}); err == nil {
		t.Fatal("expected one-shot mode to refuse --once")
	}
	if _, err := ParseSettings(ModeDaemon, newTestFlagSet(t), []string{"--source", "feed.txt", "--dry-run"}); err == nil {
		t.Fatal("expected daemon mode to refuse --dry-run")
	}
}
