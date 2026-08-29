package main

import (
	"errors"
	"flag"
	"net/http"
	"testing"
	"time"

	"safe-zone/internal/feed"
)

// The daemon must resolve the same effective TTL contract as the one-shot
// feed-sync tool: SAFE_ZONE_FEED_TTL_DAYS with a 14-day default, validated
// through feed.TTLFromDays.
func TestSyncSettingsTTLParityWithFeedSync(t *testing.T) {
	t.Setenv("SAFE_ZONE_FEED_TTL_DAYS", "")
	t.Setenv("SAFE_ZONE_THREAT_FEED_SOURCE", "https://feeds.example.test/list.txt")
	t.Setenv("SAFE_ZONE_FEED_ADMISSION_MODE", "")

	settings, err := parseSyncSettings(newTestFlagSet(t), nil)
	if err != nil {
		t.Fatalf("parse default settings: %v", err)
	}
	if settings.TTL != 14*24*time.Hour {
		t.Fatalf("expected default TTL 14d (matching feed-sync), got %v", settings.TTL)
	}

	t.Setenv("SAFE_ZONE_FEED_TTL_DAYS", "21")
	settings, err = parseSyncSettings(newTestFlagSet(t), nil)
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
	if _, err := parseSyncSettings(newTestFlagSet(t), nil); err == nil {
		t.Fatal("expected invalid admission mode rejection")
	}

	t.Setenv("SAFE_ZONE_FEED_ADMISSION_MODE", string(feed.AdmissionFilter))
	_, err := parseSyncSettings(newTestFlagSet(t), nil)
	if err == nil || !errors.Is(err, errFilterEvaluationOnly) {
		t.Fatalf("expected evaluation-only rejection, got %v", err)
	}
}

func TestSyncSettingsRequiresSource(t *testing.T) {
	t.Setenv("SAFE_ZONE_FEED_ADMISSION_MODE", "")
	t.Setenv("SAFE_ZONE_THREAT_FEED_SOURCE", "")
	if _, err := parseSyncSettings(newTestFlagSet(t), nil); !errors.Is(err, errSourceRequired) {
		t.Fatalf("expected missing source rejection, got %v", err)
	}
}

// buildSyncOptions must translate settings into the shared feed.Sync
// contract without dropping the TTL.
func TestBuildSyncOptionsCarriesTTL(t *testing.T) {
	settings := syncSettings{
		Source:        "https://feeds.example.test/list.txt",
		RedisAddr:     "127.0.0.1:6379",
		Key:           feed.DefaultThreatFeedKey,
		Replace:       true,
		Timeout:       30 * time.Second,
		AdmissionMode: feed.AdmissionLegacy,
		TTL:           7 * 24 * time.Hour,
	}
	options := buildSyncOptions(settings, http.DefaultClient)
	if options.TTL != settings.TTL {
		t.Fatalf("expected TTL to carry through, got %v", options.TTL)
	}
	if options.Key != settings.Key || options.Source != settings.Source {
		t.Fatalf("expected source/key passthrough, got %+v", options)
	}
}

func newTestFlagSet(t *testing.T) *flag.FlagSet {
	t.Helper()
	return flag.NewFlagSet("feed-syncd-test", flag.ContinueOnError)
}
