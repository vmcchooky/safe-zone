package risk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"safe-zone/internal/config"
	"safe-zone/internal/domaintrie"
	"safe-zone/internal/store"
)

// --- canonicalSourceID ---

func TestCanonicalSourceIDStable(t *testing.T) {
	const source = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
	first := canonicalSourceID(source)
	again := canonicalSourceID(source)
	if first == "" || first != again {
		t.Fatalf("source ID must be stable, got %q vs %q", first, again)
	}
	if canonicalSourceID(" https://RAW.githubusercontent.com/StevenBlack/hosts/master/hosts ") != first {
		t.Fatal("canonicalization must trim and lowercase")
	}
	if canonicalSourceID("https://other.example/hosts") == first {
		t.Fatal("different sources must yield different IDs")
	}
	// 16 bytes = 32 hex chars.
	if len(first) != 32 {
		t.Fatalf("expected 32 hex chars, got %d", len(first))
	}
}

// --- parseAdblockMatchMode ---

func TestParseAdblockMatchModeFallbacks(t *testing.T) {
	cases := map[string]adblockMatchMode{
		"":       adblockMatchModeSuffix,
		"suffix": adblockMatchModeSuffix,
		"SUFFIX": adblockMatchModeSuffix,
		"exact":  adblockMatchModeExact,
		" EXACT": adblockMatchModeExact,
		"bogus":  adblockMatchModeSuffix,
	}
	for raw, want := range cases {
		if got := parseAdblockMatchMode(raw); got != want {
			t.Fatalf("parseAdblockMatchMode(%q) = %s, want %s", raw, got, want)
		}
	}
}

// --- parseAdblockSource with policies ---

func newParseTestService(t *testing.T) *Service {
	t.Helper()
	tempDir := t.TempDir()
	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")
	storeDB, err := store.New(filepath.Join(tempDir, "parse.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storeDB.Close() })
	return &Service{
		adblockDataRoot: tempDir,
		lifecycleCtx:    context.Background(),
		store:           storeDB,
	}
}

func TestParseAdblockSourceAppliesSourcePolicy(t *testing.T) {
	svc := newParseTestService(t)
	trie := domaintrie.NewTrie()
	sourceID := canonicalSourceID("https://example.test/hosts")

	body := "# comment with #[some-group] label\n" +
		"0.0.0.0 ads.example.com\n" +
		"tracker.example.net\n" +
		"*.wild.example.org\n" +
		"0.0.0.0 localhost\n"
	if err := svc.parseAdblockSource(strings.NewReader(body), trie, sourceID, "ads", domaintrie.RuleScopeExact, domaintrie.OriginGlobalDefault); err != nil {
		t.Fatal(err)
	}

	// Hosts-style entries use the configured exact scope.
	rule, ok := trie.MatchRule("ads.example.com")
	if !ok || rule.Scope != domaintrie.RuleScopeExact || rule.SourceID != sourceID || rule.Category != "ads" || rule.Action != domaintrie.RuleActionBlock {
		t.Fatalf("host entry must carry configured provenance, got %+v ok=%v", rule, ok)
	}
	if _, ok := trie.MatchRule("sub.ads.example.com"); ok {
		t.Fatal("exact-scoped host entry must not match subdomains")
	}

	// Wildcard entries are forced to suffix scope regardless of the policy.
	rule, ok = trie.MatchRule("deep.wild.example.org")
	if !ok || rule.Scope != domaintrie.RuleScopeSuffix {
		t.Fatalf("wildcard entry must become a suffix rule, got %+v ok=%v", rule, ok)
	}

	// Comments and localhost are dropped.
	if _, ok := trie.MatchRule("localhost"); ok {
		t.Fatal("localhost must not be ingested")
	}
	if trie.Count() != 3 {
		t.Fatalf("unexpected rule count %d", trie.Count())
	}
}

func TestParseAdblockSourceFallsBackWithoutPolicy(t *testing.T) {
	svc := newParseTestService(t)
	trie := domaintrie.NewTrie()
	// No configured policy: scope comes from the global match mode (default
	// suffix), category unknown.
	if err := svc.parseAdblockSource(strings.NewReader("0.0.0.0 ads.example.com\n"), trie, canonicalSourceID("src"), domaintrie.DefaultRuleCategory, domaintrie.RuleScopeSuffix, domaintrie.OriginGlobalDefault); err != nil {
		t.Fatal(err)
	}
	rule, ok := trie.MatchRule("sub.ads.example.com")
	if !ok || rule.Category != domaintrie.DefaultRuleCategory {
		t.Fatalf("unconfigured source must fall back to defaults, got %+v ok=%v", rule, ok)
	}
}

// --- resolveAdblockSourcePolicy ---

func TestResolveAdblockSourcePolicyFallbacks(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")
	storeDB, err := store.New(filepath.Join(tempDir, "pol.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storeDB.Close() })
	svc := &Service{
		adblockDataRoot: tempDir,
		store:           storeDB,
	}
	svc.adblockMatchMode.Store(string(adblockMatchModeExact))
	svc.adblockSourcePolicies = parseAdblockSourcePolicies(`{
		"https://good.test/hosts": {"category":"telemetry","scope":"suffix"},
		"https://badcat.test/hosts": {"category":"spyware"},
		"https://badscope.test/hosts": {"scope":"glob"},
		"https://partial.test/hosts": {"category":"tracking"}
	}`)

	if cat, scope, origin := svc.resolveAdblockSourcePolicy("https://good.test/hosts"); cat != "telemetry" || scope != domaintrie.RuleScopeSuffix || origin != domaintrie.OriginSourcePolicySuffix {
		t.Fatalf("valid policy must win, got %s/%s/%v", cat, scope, origin)
	}
	if cat, scope, origin := svc.resolveAdblockSourcePolicy("https://badcat.test/hosts"); cat != domaintrie.DefaultRuleCategory || scope != domaintrie.RuleScopeExact || origin != domaintrie.OriginGlobalDefault {
		t.Fatalf("invalid category must fall back to unknown+global, got %s/%s/%v", cat, scope, origin)
	}
	if cat, scope, origin := svc.resolveAdblockSourcePolicy("https://badscope.test/hosts"); cat != domaintrie.DefaultRuleCategory || scope != domaintrie.RuleScopeExact || origin != domaintrie.OriginGlobalDefault {
		t.Fatalf("invalid scope must fall back to global mode, got %s/%s/%v", cat, scope, origin)
	}
	if cat, scope, origin := svc.resolveAdblockSourcePolicy("https://partial.test/hosts"); cat != "tracking" || scope != domaintrie.RuleScopeExact || origin != domaintrie.OriginGlobalDefault {
		t.Fatalf("partial policy must keep global scope, got %s/%s/%v", cat, scope, origin)
	}
	if cat, scope, origin := svc.resolveAdblockSourcePolicy("https://unconfigured.test/hosts"); cat != domaintrie.DefaultRuleCategory || scope != domaintrie.RuleScopeExact || origin != domaintrie.OriginGlobalDefault {
		t.Fatalf("unconfigured source must use global defaults, got %s/%s/%v", cat, scope, origin)
	}
}

func TestParseAdblockSourcePoliciesInvalidJSON(t *testing.T) {
	policies := parseAdblockSourcePolicies("{not json")
	if len(policies) != 0 {
		t.Fatalf("invalid JSON must yield an empty set, got %v", policies)
	}
	if policies == nil {
		t.Fatal("must return an usable empty set")
	}
}

// --- cache v2 round trip and legacy load through the Service ---

func TestAdblockCacheV2RoundTripThroughService(t *testing.T) {
	svc := newParseTestService(t)

	trie := domaintrie.NewTrie()
	trie.AddRule(domaintrie.Rule{Domain: "exact.example.com", Scope: domaintrie.RuleScopeExact, SourceID: "src-a", Category: "ads", Action: domaintrie.RuleActionBlock})
	trie.AddRule(domaintrie.Rule{Domain: "suffix.example.com", Scope: domaintrie.RuleScopeSuffix, SourceID: "src-b", Category: "telemetry", Action: domaintrie.RuleActionBlock})
	svc.saveAdblockCache(trie)

	reloaded := domaintrie.NewTrie()
	if !svc.loadAdblockCache(reloaded) {
		t.Fatal("expected v2 cache to load")
	}
	rule, ok := reloaded.MatchRule("exact.example.com")
	if !ok || rule.Scope != domaintrie.RuleScopeExact || rule.SourceID != "src-a" || rule.Category != "ads" {
		t.Fatalf("v2 metadata lost through service save/load: %+v ok=%v", rule, ok)
	}
	if _, ok := reloaded.MatchRule("sub.exact.example.com"); ok {
		t.Fatal("exact scope must survive the service round-trip")
	}
	rule, ok = reloaded.MatchRule("deep.sub.suffix.example.com")
	if !ok || rule.SourceID != "src-b" || rule.Category != "telemetry" {
		t.Fatalf("suffix metadata lost through service save/load: %+v ok=%v", rule, ok)
	}
}

func TestAdblockLegacyCacheLoadSemantics(t *testing.T) {
	svc := newParseTestService(t)

	legacy := "exact.example.com\nsuffix.example.com\n"
	svc.saveAdblockCacheRaw(legacy)

	reloaded := domaintrie.NewTrie()
	if !svc.loadAdblockCache(reloaded) {
		t.Fatal("expected legacy cache to load")
	}
	// Legacy entries must reload as suffix/unknown/block with the
	// legacy-cache provenance, never as the configured exact default.
	rule, ok := reloaded.MatchRule("sub.exact.example.com")
	if !ok || rule.Scope != domaintrie.RuleScopeSuffix || rule.SourceID != domaintrie.CacheV2LegacySourceID ||
		rule.Category != domaintrie.DefaultRuleCategory || rule.Action != domaintrie.RuleActionBlock {
		t.Fatalf("legacy cache must reload with rollback semantics, got %+v ok=%v", rule, ok)
	}
}

func TestAdblockCacheSkipsMalformedRecords(t *testing.T) {
	svc := newParseTestService(t)

	mixed := domaintrie.CacheV2Header + "\n" +
		"good.example.com\texact\tads\tblock\tsrc-a\n" +
		"bad.example.com\tweird-scope\tunknown\tblock\tsrc-a\n" +
		"another.example.com\tsuffix\tunknown\tblock\tsrc-b\n"
	svc.saveAdblockCacheRaw(mixed)

	reloaded := domaintrie.NewTrie()
	if !svc.loadAdblockCache(reloaded) {
		t.Fatal("expected partially-valid cache to load")
	}
	if reloaded.Count() != 2 {
		t.Fatalf("malformed record must be skipped, got %d rules", reloaded.Count())
	}
	if _, ok := reloaded.MatchRule("good.example.com"); !ok {
		t.Fatal("valid exact record must load")
	}
	if _, ok := reloaded.MatchRule("bad.example.com"); ok {
		t.Fatal("malformed record must not load")
	}
}

// --- source order determinism through sync parsing ---

func TestSourceOrderDeterministicProvenance(t *testing.T) {
	svc := newParseTestService(t)
	trie := domaintrie.NewTrie()

	idA := canonicalSourceID("https://a.test/hosts")
	idB := canonicalSourceID("https://b.test/hosts")
	// Sources are processed in SAFE_ZONE_ADBLOCK_SOURCES order; the first
	// rule for a (domain, scope) slot must keep its provenance.
	if err := svc.parseAdblockSource(strings.NewReader("0.0.0.0 ads.example.com\n"), trie, idA, "ads", domaintrie.RuleScopeSuffix, domaintrie.OriginGlobalDefault); err != nil {
		t.Fatal(err)
	}
	if err := svc.parseAdblockSource(strings.NewReader("0.0.0.0 ads.example.com\n"), trie, idB, "tracking", domaintrie.RuleScopeSuffix, domaintrie.OriginGlobalDefault); err != nil {
		t.Fatal(err)
	}
	rule, ok := trie.MatchRule("ads.example.com")
	if !ok || rule.SourceID != idA || rule.Category != "ads" {
		t.Fatalf("first source must win deterministically, got %+v ok=%v", rule, ok)
	}
}

// --- AdblockStatus ---

func TestAdblockStatusCountsAndMode(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")
	storeDB, err := store.New(filepath.Join(tempDir, "status.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storeDB.Close() })

	service := NewService(Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		RedisTimeout:       10 * time.Millisecond,
		Store:              storeDB,
		AdblockFileRoot:    tempDir,
		DisableAdblockSync: true,
	})
	t.Cleanup(func() { _ = service.Close() })

	trie := domaintrie.NewTrie()
	trie.AddRule(domaintrie.Rule{Domain: "a.example.com", Scope: domaintrie.RuleScopeExact, SourceID: "s", Category: "ads", Action: domaintrie.RuleActionBlock})
	trie.AddRule(domaintrie.Rule{Domain: "b.example.com", Scope: domaintrie.RuleScopeSuffix, SourceID: "s", Category: "ads", Action: domaintrie.RuleActionBlock})
	service.AdblockTrieOverride(trie)
	service.adblockMatchMode.Store(string(adblockMatchModeExact))

	status := service.AdblockStatus()
	if status.MatchMode != "exact" {
		t.Fatalf("expected match_mode exact, got %s", status.MatchMode)
	}
	if status.ExactRuleCount != 1 || status.SuffixRuleCount != 1 || status.DomainCount != 2 {
		t.Fatalf("unexpected counts: %+v", status)
	}
	if status.SourceCount != 0 {
		t.Fatalf("no sync ran, expected 0 sources, got %d", status.SourceCount)
	}
}

// --- config reload in sync tick ---

func TestSyncTickReloadsMatchMode(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")
	storeDB, err := store.New(filepath.Join(tempDir, "tick.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storeDB.Close() })

	service := NewService(Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		RedisTimeout:       10 * time.Millisecond,
		Store:              storeDB,
		AdblockFileRoot:    tempDir,
		DisableAdblockSync: true,
	})
	t.Cleanup(func() { _ = service.Close() })

	t.Setenv(envAdblockMatchMode, "exact")
	t.Setenv(envAdblockSourcePoliciesJSON, `{"https://x.test/hosts":{"category":"tracking"}}`)
	service.adblockMatchMode.Store(string(parseAdblockMatchMode(config.String(envAdblockMatchMode, string(adblockMatchModeSuffix)))))
	service.adblockSourcePolicies = parseAdblockSourcePolicies(config.String(envAdblockSourcePoliciesJSON, ""))

	if v := service.adblockMatchMode.Load(); v != string(adblockMatchModeExact) {
		t.Fatalf("expected exact mode after reload, got %v", v)
	}
	if _, ok := service.adblockSourcePolicies["https://x.test/hosts"]; !ok {
		t.Fatal("expected source policy to be parsed")
	}

	// syncAdblockLists with no reachable sources still refreshes the mode.
	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")
	service.syncAdblockLists()
	if v := service.adblockMatchMode.Load(); v != string(adblockMatchModeExact) {
		t.Fatalf("expected mode to persist after sync, got %v", v)
	}
}

// --- sync failure retains the current trie ---

func TestAdblockSyncFailureRetainsCurrentTrie(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")
	storeDB, err := store.New(filepath.Join(tempDir, "retain.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storeDB.Close() })

	service := NewService(Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		RedisTimeout:       10 * time.Millisecond,
		Store:              storeDB,
		AdblockFileRoot:    tempDir,
		DisableAdblockSync: true,
	})
	t.Cleanup(func() { _ = service.Close() })

	// Seed a live trie as if a previous sync succeeded.
	trie := domaintrie.NewTrie()
	trie.AddRule(domaintrie.Rule{Domain: "live.example.com", Scope: domaintrie.RuleScopeSuffix, SourceID: "src", Category: "ads", Action: domaintrie.RuleActionBlock})
	service.adblockTrie.Store(trie)
	service.adblockOKCount.Store(1)
	service.adblockLastSyncOK.Store(true)

	// A dead source with no per-source cache must not wipe the live trie.
	// Deterministic fixture: a missing file inside the data root fails via
	// safefile.OpenWithin without any external network I/O.
	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "missing-hosts-dead.txt")
	service.syncAdblockLists()

	current := service.adblockTrie.Load()
	if current == nil || !current.Match("live.example.com") {
		t.Fatal("failed sync must retain the current trie")
	}
	if service.adblockLastSyncOK.Load() {
		t.Fatal("expected last sync to be marked failed")
	}
}

// --- source-level atomicity regressions ---

// A source with one valid domain followed by a >10MiB token must fail and
// contribute zero rules to the destination trie.
func TestParseAdblockSourceAtomicOnScannerError(t *testing.T) {
	svc := newParseTestService(t)
	dest := domaintrie.NewTrie()
	srcID := canonicalSourceID("https://example.test/atomic")
	huge := strings.Repeat("a", 11*1024*1024)
	body := "0.0.0.0 good.example.com\n" + huge + "\n"
	if err := svc.parseAdblockSource(strings.NewReader(body), dest, srcID, "ads", domaintrie.RuleScopeSuffix, domaintrie.OriginGlobalDefault); err == nil {
		t.Fatal("expected scanner error for >10MiB token")
	}
	if dest.Count() != 0 {
		t.Fatalf("failed source must contribute zero rules, got %d", dest.Count())
	}
	if _, ok := dest.MatchRule("good.example.com"); ok {
		t.Fatal("valid line before the failure must not leak into the trie")
	}
}

// A failed source must not poison later sources: only the successful source's
// rules are published, in source order with first-wins preserved.
func TestSyncAtomicOneFailOneSuccess(t *testing.T) {
	service := newManualAdblockSyncService(t, loopbackDialClient())

	huge := strings.Repeat("a", 11*1024*1024)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("0.0.0.0 bad-only.test\n" + huge + "\n"))
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("0.0.0.0 good-only.test\n"))
	}))
	defer good.Close()

	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", publicMappedSource(t, bad)+","+publicMappedSource(t, good))
	service.syncAdblockLists()
	service.adblockEnabled.Store(true)

	trie := service.adblockTrie.Load()
	if trie == nil {
		t.Fatal("expected trie after partial sync")
	}
	if trie.Match("bad-only.test") {
		t.Fatal("failed source must not contribute any rule")
	}
	if !trie.Match("sub.good-only.test") {
		t.Fatal("successful source must be published")
	}
	if !service.adblockLastSyncOK.Load() {
		t.Fatal("partial sync with one success must be marked ok")
	}
}

// When an old trie exists and every source fails, the old trie is retained.
func TestSyncAtomicAllFailRetainsOldTrie(t *testing.T) {
	service := newManualAdblockSyncService(t, loopbackDialClient())

	live := domaintrie.NewTrie()
	live.AddRule(domaintrie.Rule{Domain: "live.example.com", Scope: domaintrie.RuleScopeSuffix, SourceID: "src", Category: "ads", Action: domaintrie.RuleActionBlock})
	service.adblockTrie.Store(live)

	huge := strings.Repeat("a", 11*1024*1024)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("0.0.0.0 bad-only.test\n" + huge + "\n"))
	}))
	defer bad.Close()

	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", publicMappedSource(t, bad))
	service.syncAdblockLists()

	current := service.adblockTrie.Load()
	if current == nil || !current.Match("live.example.com") {
		t.Fatal("all-fail sync must retain the old trie")
	}
	if current.Match("bad-only.test") {
		t.Fatal("failed source must not leak into the retained trie")
	}
	if service.adblockLastSyncOK.Load() {
		t.Fatal("all-fail sync must be marked failed")
	}
}

// A global cache with one valid record followed by a Scanner error must fail
// the whole load without publishing the partial record.
func TestParseAdblockCacheScannerErrorFailsWholeLoad(t *testing.T) {
	svc := newParseTestService(t)
	dest := domaintrie.NewTrie()
	huge := strings.Repeat("b", 11*1024*1024)
	content := domaintrie.CacheV2Header + "\n" +
		"good.example.com\texact\tads\tblock\tsrc-a\n" + huge + "\n"
	if svc.parseAdblockCache(strings.NewReader(content), dest) {
		t.Fatal("cache Scanner error must fail the whole load")
	}
	if dest.Count() != 0 {
		t.Fatalf("partial cache must not load, got %d rules", dest.Count())
	}
}

// --- warning deduplication race ---

func TestWarnOnceConcurrentNoRace(t *testing.T) {
	warnOnceFlags = syncWarnFlags{}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = parseAdblockMatchMode("bogus-concurrent")
			warnOnceFlags.once("concurrent-key", "msg", map[string]any{"service": "risk"})
		}()
	}
	wg.Wait()
}

// --- source identity ---

func TestCanonicalSourceIDCaseSensitivePath(t *testing.T) {
	base := canonicalSourceID("https://example.com/ListA")
	if len(base) != 32 {
		t.Fatalf("expected 32 hex chars, got %d", len(base))
	}
	trimmed := canonicalSourceID("  https://example.com/ListA  ")
	if trimmed != base {
		t.Fatal("same source after trim must be stable")
	}
	other := canonicalSourceID("https://example.com/lista")
	if other == base {
		t.Fatal("/ListA and /lista must yield different source_ids")
	}
	queryA := canonicalSourceID("https://example.com/feed?Token=ABC")
	queryB := canonicalSourceID("https://example.com/feed?Token=abc")
	if queryA == queryB {
		t.Fatal("query case must be preserved in source_id")
	}
	hostA := canonicalSourceID("HTTPS://EXAMPLE.COM/ListA")
	if hostA != base {
		t.Fatal("scheme/host case must not affect source_id")
	}
}

// SourceID must round-trip through the v2 cache and into PolicyDecision.
func TestSourceIDRoundTripsCacheAndDecision(t *testing.T) {
	svc := newParseTestService(t)
	srcID := canonicalSourceID("https://example.com/ListA")

	trie := domaintrie.NewTrie()
	trie.AddRule(domaintrie.Rule{Domain: "ads.example.com", Scope: domaintrie.RuleScopeSuffix, SourceID: srcID, Category: "ads", Action: domaintrie.RuleActionBlock})
	svc.saveAdblockCache(trie)

	reloaded := domaintrie.NewTrie()
	if !svc.loadAdblockCache(reloaded) {
		t.Fatal("expected cache to load")
	}
	rule, ok := reloaded.MatchRule("sub.ads.example.com")
	if !ok || rule.SourceID != srcID {
		t.Fatalf("source_id lost through cache round-trip: %+v ok=%v", rule, ok)
	}
	decision := adblockDecision(adblockAssessmentLocalDefaultBrands, &rule)
	if decision.SourceID != srcID {
		t.Fatalf("source_id lost into decision: %+v", decision)
	}
}

// --- nil safety ---

func TestPolicyNoPanicOnNilTrieOverride(t *testing.T) {
	service := newTestServiceWithAdblock(t, []string{"ads.example.com"})
	service.AdblockTrieOverride(nil)
	if got := service.adblockTrie.Load(); got == nil || got.Count() != 0 {
		t.Fatalf("nil override must normalize to empty trie, got %v", got)
	}
	pol := service.Policy(context.Background(), "ads.example.com", ClientInfo{})
	if pol.Policy != "allow" {
		t.Fatalf("empty trie must not block, got %s", pol.Policy)
	}
}

// --- per-source cache commit atomicity (correction #2) ---

// A successful parse followed by a failed cache commit must contribute zero
// rules. The commit is forced to fail with a non-empty directory at the final
// cache path so os.Remove/replaceFile cannot succeed.
func TestSaveAdblockSourceCacheCommitFailureMergesNothing(t *testing.T) {
	svc := newParseTestService(t)
	source := "https://example.com/commit-fail-cache"
	finalPath := svc.adblockSourceCachePath(source)
	if err := os.MkdirAll(finalPath, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(finalPath, "child"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	dest := domaintrie.NewTrie()
	err := svc.saveAdblockSourceCache(source,
		strings.NewReader("0.0.0.0 commit-fail-only.test\n"),
		dest, canonicalSourceID(source), domaintrie.DefaultRuleCategory, domaintrie.RuleScopeSuffix, domaintrie.OriginGlobalDefault)
	if err == nil {
		t.Fatal("expected cache commit error after successful parse")
	}
	if dest.Count() != 0 {
		t.Fatalf("failed cache commit must contribute zero rules, got %d", dest.Count())
	}
	if dest.Match("sub.commit-fail-only.test") {
		t.Fatal("parsed-but-uncommitted rule must not leak into the destination trie")
	}
}

// Full sync: a remote source whose parse succeeds but whose cache commit
// fails must vanish; a later successful source is published alone.
func TestSyncCommitFailureThenSecondSourceSucceeds(t *testing.T) {
	service := newManualAdblockSyncService(t, loopbackDialClient())

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("0.0.0.0 commit-fail-only.test\n"))
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("0.0.0.0 commit-good-only.test\n"))
	}))
	defer good.Close()

	badURL := publicMappedSource(t, bad)
	goodURL := publicMappedSource(t, good)
	// Block only the first source's commit with a non-empty directory.
	blockPath := service.adblockSourceCachePath(badURL)
	if err := os.MkdirAll(blockPath, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blockPath, "child"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", badURL+","+goodURL)
	service.syncAdblockLists()
	service.adblockEnabled.Store(true)

	trie := service.adblockTrie.Load()
	if trie == nil {
		t.Fatal("expected trie after partial sync")
	}
	if trie.Match("commit-fail-only.test") {
		t.Fatal("commit-failed source must not contribute any rule")
	}
	if !trie.Match("sub.commit-good-only.test") {
		t.Fatal("successful second source must be published")
	}
}

// Failed refresh followed by a fallback load of the old per-source cache must
// yield exactly the old data: no refreshed-but-uncommitted rule may mix in.
func TestSaveCommitFailureFallbackKeepsOldCacheOnly(t *testing.T) {
	svc := newParseTestService(t)
	source := "https://example.com/refresh-fallback"
	srcID := canonicalSourceID(source)
	finalPath := svc.adblockSourceCachePath(source)

	// Force the refresh commit to fail after a successful parse.
	if err := os.MkdirAll(finalPath, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(finalPath, "child"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := domaintrie.NewTrie()
	if err := svc.saveAdblockSourceCache(source,
		strings.NewReader("0.0.0.0 refreshed-new.test\n"),
		dest, srcID, domaintrie.DefaultRuleCategory, domaintrie.RuleScopeSuffix, domaintrie.OriginGlobalDefault); err == nil {
		t.Fatal("expected refresh commit error")
	}
	if dest.Count() != 0 {
		t.Fatalf("failed refresh must contribute zero rules, got %d", dest.Count())
	}

	// Fallback: restore the old cache file, then load it.
	if err := os.Remove(filepath.Join(finalPath, "child")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(finalPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(finalPath, []byte("0.0.0.0 cached-old.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !svc.loadAdblockSourceCache(source, dest, srcID, domaintrie.DefaultRuleCategory, domaintrie.RuleScopeSuffix, domaintrie.OriginGlobalDefault) {
		t.Fatal("expected old cache to load")
	}
	if dest.Match("refreshed-new.test") {
		t.Fatal("fallback trie must not mix in the uncommitted refresh rule")
	}
	if !dest.Match("sub.cached-old.test") {
		t.Fatal("fallback trie must contain exactly the old cache data")
	}
}

// --- source identity: userinfo case (correction #2) ---

func TestCanonicalSourceIDPreservesUserinfo(t *testing.T) {
	withCreds := canonicalSourceID("https://User:Secret@example.com/ListA")
	lowerCreds := canonicalSourceID("https://user:secret@example.com/ListA")
	if withCreds == lowerCreds {
		t.Fatal("userinfo case must be preserved in source_id")
	}
	again := canonicalSourceID("https://User:Secret@example.com/ListA")
	if again != withCreds {
		t.Fatal("same URL must yield a stable source_id")
	}
	if len(withCreds) != 32 {
		t.Fatalf("expected 32 hex chars, got %d", len(withCreds))
	}
}

func TestCanonicalSourceKeyUnparsableDeterministic(t *testing.T) {
	// Local paths and garbage have no authority to normalize: identity is the
	// trimmed string itself, deterministic and panic-free.
	first := canonicalSourceID("lists/custom.txt")
	if first != canonicalSourceID("  lists/custom.txt  ") {
		t.Fatal("local path must be stable after trim")
	}
	for _, raw := range []string{"https://[::1", "://", "", "https://", "not a url at all \n with newline"} {
		a, b := canonicalSourceID(raw), canonicalSourceID(raw)
		if a != b || len(a) != 32 {
			t.Fatalf("unparsable source %q must be deterministic 32-hex, got %q", raw, a)
		}
	}
	if canonicalSourceID("lists/custom.txt") == canonicalSourceID("lists/other.txt") {
		t.Fatal("different local paths must yield different IDs")
	}
}

// saveAdblockCacheRaw writes raw content to the global cache path, used to
// simulate legacy and malformed cache files.
func (s *Service) saveAdblockCacheRaw(content string) {
	if err := s.ensureAdblockDataRoot(); err != nil {
		panic(err)
	}
	f, tmpPath, err := createReplaceTempFile(s.adblockCachePath())
	if err != nil {
		panic(err)
	}
	if _, err := f.Write([]byte(content)); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		panic(err)
	}
	_ = f.Close()
	if err := replaceFile(tmpPath, s.adblockCachePath()); err != nil {
		panic(err)
	}
}
