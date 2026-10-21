package feedsync

import (
	"flag"
	"strings"
	"testing"
)

// The daemon used to accept exactly one source while the agent task and the
// alert rules assumed several, so the production path and the monitoring path
// disagreed about what "the feed" was.
func TestParseSettingsAcceptsSeveralSources(t *testing.T) {
	t.Setenv("SAFE_ZONE_THREAT_FEED_SOURCE", "")
	t.Setenv("SAFE_ZONE_FEED_ADMISSION_MODE", "")
	t.Setenv("SAFE_ZONE_FEED_ALLOW_INSECURE_HTTP", "")

	flags := flag.NewFlagSet("feed-syncd", flag.ContinueOnError)
	settings, err := ParseSettings(ModeDaemon, flags, []string{
		"--source", "https://a.example.test/list.txt,https://b.example.test/list.txt",
	})
	if err != nil {
		t.Fatalf("expected several sources to parse, got %v", err)
	}
	if len(settings.Sources) != 2 {
		t.Fatalf("expected 2 sources, got %v", settings.Sources)
	}
	if settings.Sources[0] != "https://a.example.test/list.txt" || settings.Sources[1] != "https://b.example.test/list.txt" {
		t.Fatalf("unexpected sources: %v", settings.Sources)
	}
}

func TestParseSettingsReadsSeveralSourcesFromEnvironment(t *testing.T) {
	t.Setenv("SAFE_ZONE_THREAT_FEED_SOURCE", "https://a.example.test/list.txt,https://b.example.test/list.txt")
	t.Setenv("SAFE_ZONE_FEED_ADMISSION_MODE", "")
	t.Setenv("SAFE_ZONE_FEED_ALLOW_INSECURE_HTTP", "")

	flags := flag.NewFlagSet("feed-syncd", flag.ContinueOnError)
	settings, err := ParseSettings(ModeDaemon, flags, nil)
	if err != nil {
		t.Fatalf("expected several sources to parse, got %v", err)
	}
	if len(settings.Sources) != 2 {
		t.Fatalf("expected 2 sources, got %v", settings.Sources)
	}
}

func TestParseSettingsRejectsEmptySource(t *testing.T) {
	t.Setenv("SAFE_ZONE_THREAT_FEED_SOURCE", "")
	t.Setenv("SAFE_ZONE_FEED_ADMISSION_MODE", "")
	t.Setenv("SAFE_ZONE_FEED_ALLOW_INSECURE_HTTP", "")

	flags := flag.NewFlagSet("feed-syncd", flag.ContinueOnError)
	_, err := ParseSettings(ModeDaemon, flags, nil)
	if err == nil {
		t.Fatal("expected an empty source list to be refused")
	}
	if !strings.Contains(err.Error(), "source") {
		t.Fatalf("the error should mention the source, got %v", err)
	}
}

// The one-shot and the daemon must resolve the same effective options.
func TestParseSettingsIsIdenticalAcrossModes(t *testing.T) {
	t.Setenv("SAFE_ZONE_THREAT_FEED_SOURCE", "")
	t.Setenv("SAFE_ZONE_FEED_ADMISSION_MODE", "")
	t.Setenv("SAFE_ZONE_FEED_ALLOW_INSECURE_HTTP", "")

	oneShotFlags := flag.NewFlagSet("feed-sync", flag.ContinueOnError)
	oneShot, err := ParseSettings(ModeOneShot, oneShotFlags, []string{"--source", "https://a.example.test/list.txt"})
	if err != nil {
		t.Fatal(err)
	}

	daemonFlags := flag.NewFlagSet("feed-syncd", flag.ContinueOnError)
	daemon, err := ParseSettings(ModeDaemon, daemonFlags, []string{"--source", "https://a.example.test/list.txt"})
	if err != nil {
		t.Fatal(err)
	}

	if oneShot.Key != daemon.Key ||
		oneShot.RedisAddr != daemon.RedisAddr ||
		oneShot.Timeout != daemon.Timeout ||
		oneShot.AdmissionMode != daemon.AdmissionMode ||
		oneShot.TTL != daemon.TTL {
		t.Fatalf("the two entrypoints disagree:\none-shot: %+v\ndaemon:   %+v", oneShot, daemon)
	}
}
