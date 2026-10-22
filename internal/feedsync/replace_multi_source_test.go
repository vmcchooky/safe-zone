package feedsync

import (
	"flag"
	"strings"
	"testing"
)

// Replace stages one source and renames it over the live set, which
// deletes everything the other sources wrote. With several sources in one
// run that is data loss, not a warning.
func TestParseSettingsRefusesReplaceWithSeveralSources(t *testing.T) {
	t.Setenv("SAFE_ZONE_THREAT_FEED_SOURCE", "")
	t.Setenv("SAFE_ZONE_FEED_ADMISSION_MODE", "")
	t.Setenv("SAFE_ZONE_FEED_ALLOW_INSECURE_HTTP", "")

	flags := flag.NewFlagSet("feed-syncd", flag.ContinueOnError)
	_, err := ParseSettings(ModeDaemon, flags, []string{
		"--source", "https://a.example.test/list.txt,https://b.example.test/list.txt",
		"--replace",
	})
	if err == nil {
		t.Fatal("expected replace mode with several sources to be refused")
	}
	if !strings.Contains(err.Error(), "replace") {
		t.Fatalf("the error should explain the replace hazard, got %v", err)
	}
}

func TestParseSettingsAllowsReplaceWithOneSource(t *testing.T) {
	t.Setenv("SAFE_ZONE_THREAT_FEED_SOURCE", "")
	t.Setenv("SAFE_ZONE_FEED_ADMISSION_MODE", "")
	t.Setenv("SAFE_ZONE_FEED_ALLOW_INSECURE_HTTP", "")

	flags := flag.NewFlagSet("feed-syncd", flag.ContinueOnError)
	settings, err := ParseSettings(ModeDaemon, flags, []string{
		"--source", "https://a.example.test/list.txt",
		"--replace",
	})
	if err != nil {
		t.Fatalf("replace mode with a single source must stay available: %v", err)
	}
	if !settings.Replace {
		t.Fatal("replace mode was not carried through")
	}
}
