package feed

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"safe-zone/internal/cache"
)

func TestOpenSourceHandlesGzipHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		writer := gzip.NewWriter(w)
		_, _ = writer.Write([]byte("bad.test\n"))
		_ = writer.Close()
	}))
	defer server.Close()

	reader, closeReader, err := OpenSource(context.Background(), server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer closeReader()

	parsed, err := Parse(reader)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.Stats.Valid != 1 {
		t.Fatalf("expected 1 valid domain, got %d", parsed.Stats.Valid)
	}
	if len(parsed.Domains) != 1 || parsed.Domains[0] != "bad.test" {
		t.Fatalf("unexpected parsed domains: %#v", parsed.Domains)
	}
}

func TestOpenSourceLimitsDecompressedHTTPFeed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		writer := gzip.NewWriter(w)
		_, _ = writer.Write([]byte("one.test\ntwo.test\n"))
		_ = writer.Close()
	}))
	defer server.Close()

	reader, closeReader, err := OpenSourceWithin(context.Background(), server.URL, server.Client(), t.TempDir(), 8)
	if err != nil {
		t.Fatal(err)
	}
	defer closeReader()

	_, err = Parse(reader)
	if err == nil || !strings.Contains(err.Error(), "maximum size") {
		t.Fatalf("expected max-size error, got %v", err)
	}
}

func TestSyncDryRunWithGzipFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.txt.gz")
	writeGzipFile(t, path, "# comment\nbad.test\nbad.test\nhttps://evil.test/path\n")

	report, err := Sync(context.Background(), SyncOptions{
		Source:   path,
		FileRoot: dir,
		DryRun:   true,
		Timeout:  time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	if report.Stats.Valid != 2 {
		t.Fatalf("expected 2 valid domains, got %d", report.Stats.Valid)
	}
	if report.Stats.Duplicates != 1 {
		t.Fatalf("expected 1 duplicate, got %d", report.Stats.Duplicates)
	}
	if report.Written != 0 {
		t.Fatalf("expected dry-run to write 0 domains, got %d", report.Written)
	}
	if report.RedisAddr != "" {
		t.Fatalf("expected empty redis addr in dry-run, got %q", report.RedisAddr)
	}
}

func TestSyncWritesToRedis(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(path, []byte("bad.test\nhttps://evil.test/path\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Sync(context.Background(), SyncOptions{
		Source:        path,
		FileRoot:      dir,
		RedisAddr:     server.Addr(),
		RedisPassword: "",
		RedisDB:       0,
		Key:           DefaultThreatFeedKey,
		Replace:       true,
		Timeout:       time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	if report.Written != 2 {
		t.Fatalf("expected 2 written domains, got %d", report.Written)
	}

	redisCache := cache.NewRedis(server.Addr(), "", 0)
	defer func() {
		if err := redisCache.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	if ok, err := redisCache.SetIsMember(context.Background(), DefaultThreatFeedKey, "bad.test"); err != nil || !ok {
		t.Fatalf("expected bad.test in redis feed set, ok=%v err=%v", ok, err)
	}
	if ok, err := redisCache.SetIsMember(context.Background(), DefaultThreatFeedKey, "evil.test"); err != nil || !ok {
		t.Fatalf("expected evil.test in redis feed set, ok=%v err=%v", ok, err)
	}
	revision, err := redisCache.GetInt64(context.Background(), RevisionKey(DefaultThreatFeedKey))
	if err != nil {
		t.Fatal(err)
	}
	if revision != 1 {
		t.Fatalf("expected feed revision 1, got %d", revision)
	}
	var status SourceStatus
	found, err := redisCache.GetJSON(context.Background(), StatusKey(DefaultThreatFeedKey, path), &status)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected source status metadata to be written")
	}
	if status.Status != "ok" {
		t.Fatalf("expected source status ok, got %s", status.Status)
	}
	if status.LastSuccessAt == "" {
		t.Fatal("expected last success timestamp")
	}
	if status.FeedRevision != 1 {
		t.Fatalf("expected source revision 1, got %d", status.FeedRevision)
	}
}

func TestParseOpenPhishCommunityFeed(t *testing.T) {
	parsed, err := Parse(bytes.NewBufferString("https://a.example/login https://b.example/pay http://a.example/retry"))
	if err != nil {
		t.Fatal(err)
	}

	if parsed.Stats.Valid != 2 {
		t.Fatalf("expected 2 valid domains, got %d", parsed.Stats.Valid)
	}
	if parsed.Stats.Duplicates != 1 {
		t.Fatalf("expected 1 duplicate domain, got %d", parsed.Stats.Duplicates)
	}
	if len(parsed.Domains) != 2 {
		t.Fatalf("expected 2 normalized domains, got %d", len(parsed.Domains))
	}
}

func TestReadStatusSummaryMarksStale(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	redisCache := cache.NewRedis(server.Addr(), "", 0)
	defer func() {
		if err := redisCache.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	source := "https://example.test/feed.txt"
	status := SourceStatus{
		Source:        source,
		SourceID:      "abc123",
		FeedKey:       DefaultThreatFeedKey,
		Status:        "ok",
		LastAttemptAt: time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339Nano),
		LastSuccessAt: time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339Nano),
	}
	if err := redisCache.SetJSON(context.Background(), StatusKey(DefaultThreatFeedKey, source), status, 0); err != nil {
		t.Fatal(err)
	}
	if err := redisCache.SetString(context.Background(), RevisionKey(DefaultThreatFeedKey), "3", 0); err != nil {
		t.Fatal(err)
	}

	summary := ReadStatusSummary(context.Background(), redisCache, DefaultThreatFeedKey, ProductionFreePreset, []string{source}, 24*time.Hour)
	if summary.Status != "stale" {
		t.Fatalf("expected stale summary status, got %s", summary.Status)
	}
	if !summary.Stale {
		t.Fatal("expected summary stale flag")
	}
	if summary.Revision != 3 {
		t.Fatalf("expected revision 3, got %d", summary.Revision)
	}
	if len(summary.Sources) != 1 || !summary.Sources[0].Stale {
		t.Fatalf("expected one stale source, got %#v", summary.Sources)
	}
}

func TestResolveProductionVNPreset(t *testing.T) {
	sources, err := ResolveSources("", ProductionVNPreset)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 4 {
		t.Fatalf("expected 4 production-vn sources, got %d", len(sources))
	}
	if !strings.Contains(strings.Join(sources, "\n"), "phishdestroy/destroylist") {
		t.Fatal("expected production-vn preset to include PhishDestroy")
	}
	if !strings.Contains(strings.Join(sources, "\n"), "Phishing-Database/Phishing.Database") {
		t.Fatal("expected production-vn preset to include Phishing.Database")
	}
}

func writeGzipFile(t *testing.T, path string, content string) {
	t.Helper()

	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}
