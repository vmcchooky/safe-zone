package feed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/cache"

	"github.com/alicebob/miniredis/v2"
)

// cacheFor wraps a miniredis listener in the layer the status summary reads through.
func cacheFor(server *miniredis.Miniredis) *cache.Redis {
	return cache.NewRedis(server.Addr(), "", 0)
}

// A source that syncs "successfully" with zero valid domains was invisible.
//
// The Replace path refuses an empty parse, because there it would wipe the live
// feed. Additive mode — which is what production runs — wipes nothing, so nothing
// refused it: the sync exited 0, recorded success, and that source's members aged
// out over their TTL while blocking coverage quietly shrank.
//
// parser_drift could not cover it either. An empty or comment-only body has no
// invalid lines, so the invalid-ratio denominator is zero and drift reports false
// by construction.
// healthySource syncs a feed with real domains into the same key, standing in for
// the other configured sources. Production shares one ZSET across all four, so the
// aggregate has entries and the "missing" branch does not apply; without this the
// test would pass through a state production never occupies.
func healthySource(t *testing.T, server *miniredis.Miniredis) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "healthy.txt")
	if err := os.WriteFile(path, []byte("good-one.test\ngood-two.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Sync(context.Background(), SyncOptions{
		Source:    path,
		FileRoot:  dir,
		RedisAddr: server.Addr(),
		Key:       DefaultThreatFeedKey,
		Timeout:   time.Second,
	}); err != nil {
		t.Fatalf("seeding sync: %v", err)
	}
	return path
}

func TestSuccessfulSyncWithZeroValidDomainsIsFlagged(t *testing.T) {
	for _, tc := range []struct {
		name           string
		body           string
		wantReasonPart string
	}{
		{name: "empty body", body: "", wantReasonPart: "no candidate lines"},
		{name: "comments only", body: "# Title: list\n#\n# nothing here\n", wantReasonPart: "comments"},
		{name: "whitespace only", body: "   \n\t\n\n", wantReasonPart: "comments"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, err := miniredis.Run()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()

			healthy := healthySource(t, server)

			dir := t.TempDir()
			path := filepath.Join(dir, "feed.txt")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}

			report, err := Sync(context.Background(), SyncOptions{
				Source:    path,
				FileRoot:  dir,
				RedisAddr: server.Addr(),
				Key:       DefaultThreatFeedKey,
				Timeout:   time.Second,
			})
			if err != nil {
				t.Fatalf("a sync that ingested nothing must not be an error: %v", err)
			}
			if report.Stats.Valid != 0 {
				t.Fatalf("fixture produced %d valid domains, expected 0", report.Stats.Valid)
			}

			summary := ReadStatusSummary(context.Background(), cacheFor(server), DefaultThreatFeedKey,
				"", []string{healthy, path}, time.Hour)
			if len(summary.Sources) != 2 {
				t.Fatalf("expected two source statuses, got %d", len(summary.Sources))
			}
			if summary.Status != "warning" {
				t.Fatalf("aggregate status = %q, want %q so this is not reported as healthy",
					summary.Status, "warning")
			}
			if !summary.EmptyIngest {
				t.Fatal("empty_ingest must survive aggregation into the summary")
			}
			if summary.Stale {
				t.Fatal("a source that just synced successfully is not stale; the warning must not claim staleness")
			}
			if summary.ActiveEntries == 0 {
				t.Fatal("the healthy source should have populated the key; the fixture is not exercising the real case")
			}

			var flagged *SourceStatus
			for i := range summary.Sources {
				if summary.Sources[i].EmptyIngest {
					flagged = &summary.Sources[i]
				}
			}
			if flagged == nil {
				t.Fatal("the empty source must be flagged by name, not only in the aggregate")
			}
			if flagged.Source != path {
				t.Fatalf("flagged the wrong source: %q, want %q", flagged.Source, path)
			}
			if reason := flagged.EmptyIngestReason; !strings.Contains(reason, tc.wantReasonPart) {
				t.Fatalf("empty_ingest_reason = %q, want it to mention %q", reason, tc.wantReasonPart)
			}
		})
	}
}

// The flag must not fire on a healthy sync, or the alert becomes noise that gets
// suppressed rather than fixed.
func TestSuccessfulSyncWithDomainsIsNotFlagged(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(path, []byte("first.test\nsecond.test\n# a comment\nthird.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Sync(context.Background(), SyncOptions{
		Source:    path,
		FileRoot:  dir,
		RedisAddr: server.Addr(),
		Key:       DefaultThreatFeedKey,
		Timeout:   time.Second,
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if report.Stats.Valid == 0 {
		t.Fatal("fixture produced no valid domains; the test is not exercising what it claims")
	}

	summary := ReadStatusSummary(context.Background(), cacheFor(server), DefaultThreatFeedKey,
		"", []string{path}, time.Hour)
	if summary.EmptyIngest {
		t.Fatal("a sync that ingested domains must not set empty_ingest")
	}
	if got := summary.Sources[0].EmptyIngestReason; got != "" {
		t.Fatalf("empty_ingest_reason = %q, want empty", got)
	}
	if summary.Status == "warning" {
		t.Fatalf("status = %q; a healthy sync must not warn", summary.Status)
	}
}

// A failed sync already reports through status:error. Empty-ingest describes a
// *successful* sync, so the two must not be conflated — they call for different
// operator responses.
func TestFailedSyncIsNotReportedAsEmptyIngest(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist.txt")
	if _, err := Sync(context.Background(), SyncOptions{
		Source:    missing,
		FileRoot:  dir,
		RedisAddr: server.Addr(),
		Key:       DefaultThreatFeedKey,
		Timeout:   time.Second,
	}); err == nil {
		t.Fatal("expected a missing source to fail the sync")
	}

	summary := ReadStatusSummary(context.Background(), cacheFor(server), DefaultThreatFeedKey,
		"", []string{missing}, time.Hour)
	if len(summary.Sources) != 1 {
		t.Fatalf("expected one source status, got %d", len(summary.Sources))
	}
	if summary.Sources[0].Status != "error" {
		t.Fatalf("status = %q, want error", summary.Sources[0].Status)
	}
	if summary.EmptyIngest {
		t.Fatal("a failed sync is an error, not an empty ingest")
	}
}

// The reasons must be distinguishable, because the operator action differs: an
// all-garbage body points at a format change, an empty body at an upstream outage.
func TestEmptyIngestReasonDistinguishesTheCauses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stats ParseStats
		want  string
	}{
		{name: "nothing at all", stats: ParseStats{}, want: "no candidate lines"},
		{name: "all invalid", stats: ParseStats{Invalid: 40}, want: "unparseable"},
		{name: "comments only", stats: ParseStats{Skipped: 40}, want: "comments"},
		{name: "mixed", stats: ParseStats{Invalid: 3, Skipped: 5}, want: "no valid domain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason := emptyIngestReason(SyncReport{Stats: tc.stats})
			if !strings.Contains(reason, tc.want) {
				t.Fatalf("reason = %q, want it to mention %q", reason, tc.want)
			}
		})
	}
	if got := emptyIngestReason(SyncReport{Stats: ParseStats{Valid: 3}}); got != "" {
		t.Fatalf("a sync with valid domains must have no empty-ingest reason, got %q", got)
	}
}
