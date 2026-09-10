package feed

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/alicebob/miniredis/v2"

	"safe-zone/internal/cache"
)

const pslGuardFixture = "github.io\nevil.github.io\nworkers.dev\nco.uk\nevil.com\n"

// A feed member that IS a public suffix must never become a host IOC:
// admitting github.io would block every tenant beneath it via the
// parent-walk matcher. Subdomains of shared roots stay admissible.
func TestSyncDryRunSkipsPublicSuffixMembers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(path, []byte(pslGuardFixture), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Sync(context.Background(), SyncOptions{
		Source:   path,
		FileRoot: dir,
		DryRun:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.SkippedPublicSuffix != 3 {
		t.Fatalf("expected 3 public-suffix skips (github.io, workers.dev, co.uk), got %#v", report.Stats)
	}
}

func TestSyncWriteSkipsPublicSuffixMembers(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(path, []byte(pslGuardFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Sync(context.Background(), SyncOptions{
		Source:    path,
		FileRoot:  dir,
		RedisAddr: server.Addr(),
		Key:       DefaultThreatFeedKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Written != 2 {
		t.Fatalf("expected only evil.github.io and evil.com written, got %d (%#v)", report.Written, report.Stats)
	}
	redisCache := cache.NewRedis(server.Addr(), "", 0)
	defer redisCache.Close()
	for _, blocked := range []string{"github.io", "workers.dev", "co.uk"} {
		if _, err := redisCache.ZScore(context.Background(), DefaultThreatFeedKey, blocked); err == nil {
			t.Fatalf("public suffix %s must not be admitted to the feed", blocked)
		}
	}
	for _, allowed := range []string{"evil.github.io", "evil.com"} {
		if _, err := redisCache.ZScore(context.Background(), DefaultThreatFeedKey, allowed); err != nil {
			t.Fatalf("expected %s in feed: %v", allowed, err)
		}
	}
}

func TestSyncShadowAdmissionSkipsPublicSuffixMembers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(path, []byte("https://evil.github.io/a\nhttps://workers.dev/b\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Sync(context.Background(), SyncOptions{
		Source:        path,
		FileRoot:      dir,
		DryRun:        true,
		AdmissionMode: AdmissionShadow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.SkippedPublicSuffix != 1 {
		t.Fatalf("expected workers.dev filtered from shadow plan, got %#v", report.Stats)
	}
}
