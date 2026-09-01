package feed

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"safe-zone/internal/cache"
	"safe-zone/internal/netguard"
)

// policySourceURL rewrites a loopback httptest URL to a public RFC 5737
// documentation IP so the source passes the outbound policy checks, while
// the returned client still dials the real loopback listener. This keeps
// end-to-end HTTP behavior and exercises the same validation path as
// production traffic.
func policySourceURL(t *testing.T, srv *httptest.Server) (string, *http.Client) {
	t.Helper()

	serverURL := strings.TrimSuffix(srv.URL, "/")
	host := serverURL[len("http://"):]
	_, port, err := net.SplitHostPort(host)
	if err != nil {
		t.Fatalf("split httptest host: %v", err)
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, dialPort, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				var dialer net.Dialer
				return dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", dialPort))
			},
		},
	}
	return "http://" + net.JoinHostPort("198.51.100.10", port), client
}

func TestOpenSourceHandlesGzipHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		writer := gzip.NewWriter(w)
		_, _ = writer.Write([]byte("bad.test\n"))
		_ = writer.Close()
	}))
	defer server.Close()

	sourceURL, client := policySourceURL(t, server)
	reader, closeReader, err := OpenSourceWithin(context.Background(), sourceURL, client, t.TempDir(), DefaultMaxFeedBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer closeReader()

	domains, stats := collectParsed(t, reader)

	if stats.Valid != 1 {
		t.Fatalf("expected 1 valid domain, got %d", stats.Valid)
	}
	if len(domains) != 1 || domains[0] != "bad.test" {
		t.Fatalf("unexpected parsed domains: %#v", domains)
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

	sourceURL, client := policySourceURL(t, server)
	reader, closeReader, err := OpenSourceWithin(context.Background(), sourceURL, client, t.TempDir(), 8)
	if err != nil {
		t.Fatal(err)
	}
	defer closeReader()

	var stats ParseStats
	err = ParseEach(reader, func(string) error { return nil }, &stats)
	if err == nil || !strings.Contains(err.Error(), "maximum size") {
		t.Fatalf("expected max-size error, got %v", err)
	}
}

func TestOpenSourceRejectsPrivateHTTPFeedSource(t *testing.T) {
	// The feed layer must reject private sources even when the caller
	// supplies an unguarded client: policy enforcement cannot depend on
	// caller discipline.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("bad.test\n"))
	}))
	defer server.Close()

	_, closeReader, err := OpenSourceWithin(context.Background(), server.URL, server.Client(), t.TempDir(), DefaultMaxFeedBytes)
	if closeReader != nil {
		defer closeReader()
	}
	if err == nil || !strings.Contains(err.Error(), "blocked private or local address") {
		t.Fatalf("expected feed layer to reject private feed URL, got %v", err)
	}
}

func TestOpenSourceRejectsRedirectToBlockedTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect từ source "hợp lệ" sang đích bị cấm (CGNAT): phải bị chặn.
		http.Redirect(w, r, "http://100.64.0.1/hosts.txt", http.StatusFound)
	}))
	defer server.Close()

	sourceURL, client := policySourceURL(t, server)
	_, closeReader, err := OpenSourceWithin(context.Background(), sourceURL, client, t.TempDir(), DefaultMaxFeedBytes)
	if closeReader != nil {
		defer closeReader()
	}
	if err == nil {
		t.Fatal("expected redirect to blocked target to fail")
	}
	if !errors.Is(err, netguard.ErrBlockedAddress) {
		t.Fatalf("expected ErrBlockedAddress, got %v", err)
	}
}

func TestOpenSourceFollowsRedirectToAllowedTarget(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&requests, 1) == 1 {
			// Redirect hop trỏ về chính endpoint public-mapped (r.Host là
			// 198.51.100.10:port) — hợp lệ theo policy nên phải được theo.
			http.Redirect(w, r, "http://"+r.Host+"/hosts.txt", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("bad.test\n"))
	}))
	defer server.Close()

	sourceURL, client := policySourceURL(t, server)
	reader, closeReader, err := OpenSourceWithin(context.Background(), sourceURL, client, t.TempDir(), DefaultMaxFeedBytes)
	if err != nil {
		t.Fatalf("expected valid redirect to be followed, got %v", err)
	}
	defer closeReader()

	domains, _ := collectParsed(t, reader)
	if len(domains) != 1 || domains[0] != "bad.test" {
		t.Fatalf("expected 1 valid domain after redirect, got %#v", domains)
	}
	if atomic.LoadInt32(&requests) != 2 {
		t.Fatalf("expected 2 requests (initial + redirect), got %d", requests)
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

func TestSyncAdmissionShadowReportsWithoutFiltering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(path, []byte("https://single.test/login\nhttps://repeated.test/a\nhttps://repeated.test/b\n"), 0o600); err != nil {
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
	if report.Admission == nil || report.Admission.AuthoritativeHosts != 1 || report.Admission.ContextualHosts != 1 {
		t.Fatalf("unexpected admission report: %#v", report.Admission)
	}
	if report.Stats.Valid != 2 {
		t.Fatalf("expected legacy-valid count 2, got %d", report.Stats.Valid)
	}
}

func TestSyncRejectsAdmissionFilterOutsideDryRun(t *testing.T) {
	_, err := Sync(context.Background(), SyncOptions{
		Source:        "unused.test",
		AdmissionMode: AdmissionFilter,
	})
	if err == nil || !strings.Contains(err.Error(), "evaluation-only") {
		t.Fatalf("expected evaluation-only admission error, got %v", err)
	}
}

func TestSyncAdmissionShadowWritesLegacyMembership(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(path, []byte("https://single.test/login\nhttps://repeated.test/a\nhttps://repeated.test/b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Sync(context.Background(), SyncOptions{
		Source:        path,
		FileRoot:      dir,
		RedisAddr:     server.Addr(),
		Key:           DefaultThreatFeedKey,
		AdmissionMode: AdmissionShadow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Written != 2 {
		t.Fatalf("expected both legacy hosts written in shadow mode, got %d", report.Written)
	}
	redisCache := cache.NewRedis(server.Addr(), "", 0)
	defer redisCache.Close()
	for _, domain := range []string{"single.test", "repeated.test"} {
		if _, err := redisCache.ZScore(context.Background(), DefaultThreatFeedKey, domain); err != nil {
			t.Fatalf("expected %s in shadow membership: %v", domain, err)
		}
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

	if score, err := redisCache.ZScore(context.Background(), DefaultThreatFeedKey, "bad.test"); err != nil || score == 0 {
		t.Fatalf("expected bad.test in redis feed set with score, score=%v err=%v", score, err)
	}
	if score, err := redisCache.ZScore(context.Background(), DefaultThreatFeedKey, "evil.test"); err != nil || score == 0 {
		t.Fatalf("expected evil.test in redis feed set with score, score=%v err=%v", score, err)
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
	domains, stats := collectParsed(t, bytes.NewBufferString("https://a.example/login https://b.example/pay http://a.example/retry"))

	if stats.Valid != 2 {
		t.Fatalf("expected 2 valid domains, got %d", stats.Valid)
	}
	if stats.Duplicates != 1 {
		t.Fatalf("expected 1 duplicate domain, got %d", stats.Duplicates)
	}
	if len(domains) != 2 {
		t.Fatalf("expected 2 normalized domains, got %d", len(domains))
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
	if _, err := redisCache.ZAdd(context.Background(), DefaultThreatFeedKey, redis.Z{
		Score:  float64(time.Now().Add(time.Hour).Unix()),
		Member: "active.test",
	}); err != nil {
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
	if summary.ActiveEntries != 1 {
		t.Fatalf("expected one active feed entry, got %d", summary.ActiveEntries)
	}
	if len(summary.Sources) != 1 || !summary.Sources[0].Stale {
		t.Fatalf("expected one stale source, got %#v", summary.Sources)
	}
}

func TestReadStatusSummaryDetectsMissingFeedAfterSuccessfulSync(t *testing.T) {
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
	now := time.Now().UTC().Format(time.RFC3339Nano)
	status := SourceStatus{
		Source:        source,
		SourceID:      "abc123",
		FeedKey:       DefaultThreatFeedKey,
		Status:        "ok",
		LastAttemptAt: now,
		LastSuccessAt: now,
	}
	if err := redisCache.SetJSON(context.Background(), StatusKey(DefaultThreatFeedKey, source), status, 0); err != nil {
		t.Fatal(err)
	}
	if err := redisCache.SetString(context.Background(), RevisionKey(DefaultThreatFeedKey), "3", 0); err != nil {
		t.Fatal(err)
	}

	summary := ReadStatusSummary(context.Background(), redisCache, DefaultThreatFeedKey, ProductionFreePreset, []string{source}, 24*time.Hour)
	if summary.Status != "missing" {
		t.Fatalf("expected missing summary status, got %s", summary.Status)
	}
	if !summary.Stale {
		t.Fatal("expected a missing feed to be marked stale")
	}
	if summary.ActiveEntries != 0 {
		t.Fatalf("expected zero active entries, got %d", summary.ActiveEntries)
	}
	if !strings.Contains(summary.Error, "no active entries") {
		t.Fatalf("expected actionable missing-feed error, got %q", summary.Error)
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

// collectParsed drains a feed through the production ParseEach pipeline and
// returns every accepted domain with its stats.
func collectParsed(t *testing.T, reader io.Reader) ([]string, ParseStats) {
	t.Helper()
	var (
		domains []string
		stats   ParseStats
	)
	err := ParseEach(reader, func(domain string) error {
		domains = append(domains, domain)
		return nil
	}, &stats)
	if err != nil {
		t.Fatal(err)
	}
	return domains, stats
}
