package risk

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
	"safe-zone/internal/domaintrie"
	"safe-zone/internal/store"
)

// newTestServiceWithAdblockSemantics creates a service with a pre-populated
// adblock trie and an explicit policy semantics mode.
func newTestServiceWithAdblockSemantics(t *testing.T, semantics PolicySemantics, domains []string) *Service {
	t.Helper()

	tempDir := t.TempDir()
	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")

	dbPath := filepath.Join(tempDir, "test.db")
	storeDB, err := store.New(dbPath, 30)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}

	// Enable adblock via system config
	if err := storeDB.SetSystemConfig(context.Background(), "adblock_enabled", "true"); err != nil {
		t.Fatalf("failed to set adblock_enabled: %v", err)
	}

	service := NewService(Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		RedisTimeout:       10 * time.Millisecond,
		TTLAllowed:         time.Hour,
		TTLSuspicious:      time.Hour,
		TTLBlocked:         time.Hour,
		RecentLimit:        10,
		Store:              storeDB,
		AdblockFileRoot:    tempDir,
		PolicySemantics:    semantics,
		DisableAdblockSync: true,
	})

	// Manually populate the adblock trie (bypass network sync)
	trie := domaintrie.NewTrie()
	for _, d := range domains {
		trie.Add(d)
	}
	service.adblockTrie.Store(trie)

	t.Cleanup(func() {
		_ = service.Close()
	})

	return service
}

// newTestServiceWithAdblock creates a service with a pre-populated adblock
// trie under the default (separated) policy semantics.
func newTestServiceWithAdblock(t *testing.T, domains []string) *Service {
	return newTestServiceWithAdblockSemantics(t, PolicySemanticsSeparated, domains)
}

func newManualAdblockSyncService(t *testing.T, adblockClient *http.Client) *Service {
	t.Helper()

	tempDir := t.TempDir()
	t.Setenv("SAFE_ZONE_ADBLOCK_ENABLED", "false")

	dbPath := filepath.Join(tempDir, "test.db")
	storeDB, err := store.New(dbPath, 30)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	if err := storeDB.SetSystemConfig(context.Background(), "adblock_enabled", "false"); err != nil {
		t.Fatalf("failed to disable background adblock sync: %v", err)
	}

	service := NewService(Options{
		AnalysisConfig:    config.DefaultAnalysisConfig(),
		RedisTimeout:      10 * time.Millisecond,
		TTLAllowed:        time.Hour,
		TTLSuspicious:     time.Hour,
		TTLBlocked:        time.Hour,
		RecentLimit:       10,
		Store:             storeDB,
		AdblockFileRoot:   tempDir,
		AdblockHTTPClient: adblockClient,
	})

	t.Cleanup(func() {
		_ = service.Close()
	})

	return service
}

func TestAdblockTrieMatchInAnalyze(t *testing.T) {
	service := newTestServiceWithAdblockSemantics(t, PolicySemanticsLegacy, []string{
		"ads.example.com",
		"tracker.doubleclick.net",
	})

	result := service.Analyze(context.Background(), "ads.example.com", ClientInfo{})
	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected malicious verdict for adblocked domain, got %s", result.Verdict)
	}
	if result.Score != 100 {
		t.Fatalf("expected score 100, got %d", result.Score)
	}
	if len(result.Reasons) == 0 || result.Reasons[0] != "adblock" {
		t.Fatalf("expected reason 'adblock', got %v", result.Reasons)
	}
	if result.Result.Category != "adware" {
		t.Fatalf("expected category 'adware', got %s", result.Result.Category)
	}
}

// In separated semantics the adblock match must not produce a security
// verdict by itself: a lexical-safe domain flows through the normal analysis
// pipeline and its reasons never mention adblock.
func TestAdblockTrieMatchInAnalyzeSeparated(t *testing.T) {
	service := newTestServiceWithAdblock(t, []string{
		"ads.example.com",
		"tracker.doubleclick.net",
	})

	result := service.Analyze(context.Background(), "ads.example.com", ClientInfo{})
	if result.Verdict == analysis.VerdictMalicious && result.Score >= 70 && result.Reasons[0] == "adblock" {
		t.Fatalf("adblock match must not drive the security verdict, got %s/%d reasons=%v", result.Verdict, result.Score, result.Reasons)
	}
	for _, r := range result.Reasons {
		if r == "adblock" {
			t.Fatalf("adblock must not appear in security reasons, got %v", result.Reasons)
		}
	}
}

func TestAdblockTrieMatchInPolicy(t *testing.T) {
	service := newTestServiceWithAdblockSemantics(t, PolicySemanticsLegacy, []string{
		"ads.example.com",
	})

	pol := service.Policy(context.Background(), "ads.example.com", ClientInfo{})
	if pol.Policy != "block" {
		t.Fatalf("expected policy 'block' for adblocked domain, got %s", pol.Policy)
	}
	if pol.Result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected malicious verdict in policy, got %s", pol.Result.Verdict)
	}
	if pol.Result.Category != "adware" {
		t.Fatalf("expected category 'adware', got %s", pol.Result.Category)
	}
}

// In separated semantics Policy must still block an adblock match, but the
// attached security Result comes from the lexical analyzer and the reason is
// carried by Decision, never by Result.Reasons.
func TestAdblockTrieMatchInPolicySeparated(t *testing.T) {
	service := newTestServiceWithAdblock(t, []string{
		"ads.example.com",
	})

	pol := service.Policy(context.Background(), "ads.example.com", ClientInfo{})
	if pol.Policy != "block" {
		t.Fatalf("expected policy 'block' for adblocked domain, got %s", pol.Policy)
	}
	if pol.Decision == nil {
		t.Fatal("expected decision on separated adblock block")
	}
	if pol.Decision.Action != "block" || pol.Decision.Reason != "adblock_match" ||
		pol.Decision.Source != "adblock" || pol.Decision.AssessmentMode != "lexical_local_default_brands" ||
		pol.Decision.Kind != "content" || pol.Decision.Category != "unknown" {
		t.Fatalf("unexpected decision: %+v", pol.Decision)
	}
	if pol.Result.Verdict == analysis.VerdictMalicious && pol.Result.Score >= 70 && pol.Result.Reasons[0] == "adblock" {
		t.Fatalf("adblock must not drive the security result, got %s/%d reasons=%v", pol.Result.Verdict, pol.Result.Score, pol.Result.Reasons)
	}
	for _, r := range pol.Result.Reasons {
		if r == "adblock" {
			t.Fatalf("adblock must not appear in Result.Reasons, got %v", pol.Result.Reasons)
		}
	}
}

func TestAdblockDisabled(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")

	dbPath := filepath.Join(tempDir, "test.db")
	storeDB, err := store.New(dbPath, 30)
	if err != nil {
		t.Fatal(err)
	}
	// Explicitly disable adblock
	if err := storeDB.SetSystemConfig(context.Background(), "adblock_enabled", "false"); err != nil {
		t.Fatal(err)
	}

	service := NewService(Options{
		AnalysisConfig:  config.DefaultAnalysisConfig(),
		RedisTimeout:    10 * time.Millisecond,
		TTLAllowed:      time.Hour,
		TTLSuspicious:   time.Hour,
		TTLBlocked:      time.Hour,
		RecentLimit:     10,
		Store:           storeDB,
		AdblockFileRoot: tempDir,
	})
	t.Cleanup(func() { _ = service.Close() })

	// Manually add a domain to the trie
	trie := domaintrie.NewTrie()
	trie.Add("ads.example.com")
	service.adblockTrie.Store(trie)

	// Even though the trie has the domain, adblock is disabled
	result := service.Analyze(context.Background(), "ads.example.com", ClientInfo{})
	if result.Verdict == analysis.VerdictMalicious && len(result.Reasons) > 0 && result.Reasons[0] == "adblock" {
		t.Fatal("expected adblock to be disabled; domain should not be blocked via adblock")
	}
}

func TestAdblockWhitelistPriority(t *testing.T) {
	service := newTestServiceWithAdblock(t, []string{
		"ads.example.com",
	})

	// Whitelist the same domain via DB
	if err := service.store.UpdateWhitelist(context.Background(), []string{"ads.example.com"}); err != nil {
		t.Fatalf("failed to update whitelist: %v", err)
	}
	if err := service.whitelist.LoadFromDB(); err != nil {
		t.Fatalf("failed to reload whitelist: %v", err)
	}

	result := service.Analyze(context.Background(), "ads.example.com", ClientInfo{})
	// Whitelist check comes before adblock, so it should be safe
	if result.Verdict != analysis.VerdictSafe {
		t.Fatalf("expected whitelisted domain to bypass adblock, got verdict %s", result.Verdict)
	}
	if len(result.Reasons) == 0 || result.Reasons[0] != "whitelisted" {
		t.Fatalf("expected reason 'whitelisted', got %v", result.Reasons)
	}
}

func TestAdblockOverridePriority(t *testing.T) {
	service := newTestServiceWithAdblock(t, []string{
		"ads.example.com",
	})

	// Add admin override to allow the domain
	if err := service.UpsertOverride("ads.example.com", "allow", "false positive"); err != nil {
		t.Fatalf("upsert override failed: %v", err)
	}

	result := service.Analyze(context.Background(), "ads.example.com", ClientInfo{})
	// Override check comes before adblock, so it should be safe
	if result.Verdict != analysis.VerdictSafe {
		t.Fatalf("expected override-allowed domain to bypass adblock, got verdict %s", result.Verdict)
	}
	if len(result.Reasons) == 0 || result.Reasons[0] != "admin override: allow (false positive)" {
		t.Fatalf("expected admin override allow reason, got %v", result.Reasons)
	}
}

func TestAdblockSubdomainMatch(t *testing.T) {
	service := newTestServiceWithAdblockSemantics(t, PolicySemanticsLegacy, []string{
		"ads.example.com",
	})

	// Subdomains of blocked domains should also be blocked
	result := service.Analyze(context.Background(), "sub.ads.example.com", ClientInfo{})
	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected subdomain of adblocked domain to be blocked, got %s", result.Verdict)
	}
	if len(result.Reasons) == 0 || result.Reasons[0] != "adblock" {
		t.Fatalf("expected reason 'adblock', got %v", result.Reasons)
	}
}

func TestAdblockSafetyGuardRejectsTLD(t *testing.T) {
	service := newTestServiceWithAdblock(t, []string{
		"com",    // single-label TLD
		"com.vn", // multi-label public suffix
	})

	// "com" should have been rejected at trie.Add level
	result := service.Analyze(context.Background(), "google.com", ClientInfo{})
	for _, r := range result.Reasons {
		if r == "adblock" {
			t.Fatal("single-label TLD 'com' should have been rejected by safety guard")
		}
	}

	result2 := service.Analyze(context.Background(), "example.com.vn", ClientInfo{})
	for _, r := range result2.Reasons {
		if r == "adblock" {
			t.Fatal("multi-label public suffix 'com.vn' should have been rejected by safety guard")
		}
	}
}

func TestAdblockPolicyWhitelistPriority(t *testing.T) {
	service := newTestServiceWithAdblock(t, []string{
		"ads.example.com",
	})

	// Whitelist the same domain via DB
	if err := service.store.UpdateWhitelist(context.Background(), []string{"ads.example.com"}); err != nil {
		t.Fatalf("failed to update whitelist: %v", err)
	}
	if err := service.whitelist.LoadFromDB(); err != nil {
		t.Fatalf("failed to reload whitelist: %v", err)
	}

	pol := service.Policy(context.Background(), "ads.example.com", ClientInfo{})
	if pol.Policy != "allow" {
		t.Fatalf("expected whitelisted domain to bypass adblock in Policy, got %s", pol.Policy)
	}
}

func TestAdblockWildcardEntryMatchesViaNormalization(t *testing.T) {
	service := newTestServiceWithAdblockSemantics(t, PolicySemanticsLegacy, []string{
		"*.ads.example.com",
	})

	result := service.Analyze(context.Background(), "sub.ads.example.com", ClientInfo{})
	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected wildcard adblock entry to block subdomain, got %s", result.Verdict)
	}
	if len(result.Reasons) == 0 || result.Reasons[0] != "adblock" {
		t.Fatalf("expected reason 'adblock', got %v", result.Reasons)
	}
}

// loopbackDialClient dials the loopback listener regardless of the URL host,
// so sources can be addressed through a public RFC 5737 IP that passes the
// outbound policy the same way production traffic does.
func loopbackDialClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				var dialer net.Dialer
				return dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
			},
		},
	}
}

// publicMappedSource rewrites an httptest URL's loopback host to a public
// documentation IP so remote adblock sources pass the outbound policy.
func publicMappedSource(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	host := strings.TrimPrefix(srv.URL, "http://")
	_, port, err := net.SplitHostPort(host)
	if err != nil {
		t.Fatalf("split source host: %v", err)
	}
	return "http://" + net.JoinHostPort("198.51.100.10", port)
}

func TestAdblockSyncReusesPerSourceCacheOn304(t *testing.T) {
	service := newManualAdblockSyncService(t, loopbackDialClient())

	var mu sync.Mutex
	sourceAMethods := []string{}
	sourceBMethods := []string{}
	sourceBIfNoneMatch := []string{}
	sourceABody := "0.0.0.0 ads.one.test\n"
	sourceAEtag := "a-v1"

	sourceA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sourceAMethods = append(sourceAMethods, r.Method)
		mu.Unlock()

		if r.Header.Get("If-None-Match") == sourceAEtag {
			sourceAEtag = "a-v2"
			sourceABody = "0.0.0.0 ads.one.test\n0.0.0.0 ads.two.test\n"
		}
		w.Header().Set("ETag", sourceAEtag)
		_, _ = w.Write([]byte(sourceABody))
	}))
	defer sourceA.Close()

	sourceB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sourceBMethods = append(sourceBMethods, r.Method)
		sourceBIfNoneMatch = append(sourceBIfNoneMatch, r.Header.Get("If-None-Match"))
		mu.Unlock()

		if r.Header.Get("If-None-Match") == "b-v1" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", "b-v1")
		_, _ = w.Write([]byte("0.0.0.0 cache.keep.test\n"))
	}))
	defer sourceB.Close()

	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", publicMappedSource(t, sourceA)+","+publicMappedSource(t, sourceB))

	service.syncAdblockLists()
	service.syncAdblockLists()
	service.adblockEnabled.Store(true)

	// Assert on the trie directly so the sync contract stays independent of
	// policy semantics (separated mode no longer surfaces "adblock" reasons).
	trie := service.adblockTrie.Load()
	if !trie.Match("ads.two.test") {
		t.Fatal("expected changed source entry to be active after second sync")
	}
	if !trie.Match("sub.cache.keep.test") {
		t.Fatal("expected cached 304 source entry to remain active")
	}

	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(sourceAMethods, []string{http.MethodGet, http.MethodGet}) {
		t.Fatalf("expected source A to be fetched twice with GET, got %v", sourceAMethods)
	}
	if !slices.Equal(sourceBMethods, []string{http.MethodGet, http.MethodGet}) {
		t.Fatalf("expected source B to be fetched twice with GET, got %v", sourceBMethods)
	}
	if len(sourceBIfNoneMatch) != 2 || sourceBIfNoneMatch[1] != "b-v1" {
		t.Fatalf("expected second source B request to send cached ETag, got %v", sourceBIfNoneMatch)
	}
}

func TestAdblockSyncFallsBackToSourceCacheWhenRemoteFails(t *testing.T) {
	service := newManualAdblockSyncService(t, loopbackDialClient())

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", "stable-v1")
		_, _ = w.Write([]byte("0.0.0.0 resilient-cache.test\n"))
	}))

	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", publicMappedSource(t, source))

	service.syncAdblockLists()
	source.Close()
	service.syncAdblockLists()
	service.adblockEnabled.Store(true)

	// Assert on the trie directly so the sync contract stays independent of
	// policy semantics (separated mode no longer surfaces "adblock" reasons).
	trie := service.adblockTrie.Load()
	if !trie.Match("sub.resilient-cache.test") {
		t.Fatal("expected cached source to survive remote failure")
	}
}

type coordinatedAdblockReader struct {
	payload []byte
	ready   *sync.WaitGroup
	release <-chan struct{}
	offset  int
	waited  bool
}

func (r *coordinatedAdblockReader) Read(p []byte) (int, error) {
	if !r.waited {
		r.waited = true
		r.ready.Done()
		<-r.release
	}
	if r.offset >= len(r.payload) {
		return 0, io.EOF
	}
	n := copy(p, r.payload[r.offset:])
	r.offset += n
	return n, nil
}

func TestAdblockSourceCacheWritesUseUniqueTempFiles(t *testing.T) {
	tempDir := t.TempDir()
	serviceA := &Service{adblockDataRoot: tempDir}
	serviceB := &Service{adblockDataRoot: tempDir}
	source := "https://example.com/adblock.txt"

	var ready sync.WaitGroup
	ready.Add(2)
	release := make(chan struct{})
	errCh := make(chan error, 2)

	runSave := func(service *Service) {
		trie := domaintrie.NewTrie()
		reader := &coordinatedAdblockReader{
			payload: []byte("0.0.0.0 ads.concurrent.test\n"),
			ready:   &ready,
			release: release,
		}
		errCh <- service.saveAdblockSourceCache(source, reader, trie, canonicalSourceID(source), domaintrie.DefaultRuleCategory, domaintrie.RuleScopeSuffix, domaintrie.OriginGlobalDefault)
	}

	go runSave(serviceA)
	go runSave(serviceB)

	ready.Wait()
	close(release)

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("expected concurrent cache writes to succeed, got %v", err)
		}
	}

	loadedTrie := domaintrie.NewTrie()
	if !serviceA.loadAdblockSourceCache(source, loadedTrie, canonicalSourceID(source), domaintrie.DefaultRuleCategory, domaintrie.RuleScopeSuffix, domaintrie.OriginGlobalDefault) {
		t.Fatal("expected source cache to be readable after concurrent writes")
	}
	if !loadedTrie.Match("ads.concurrent.test") {
		t.Fatal("expected concurrent cache write to persist domain entry")
	}
}
