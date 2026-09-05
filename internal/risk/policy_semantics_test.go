package risk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"safe-zone/internal/ai"
	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
	"safe-zone/internal/domaintrie"
	"safe-zone/internal/store"
)

// newSemanticsTestService builds a store-backed service with a populated
// adblock trie and optional AI client. It returns the service and the store
// so telemetry assertions can flush via Close.
func newSemanticsTestService(t *testing.T, semantics PolicySemantics, domains []string, aiClient *ai.Client) (*Service, *store.DB) {
	t.Helper()

	tempDir := t.TempDir()
	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")

	dbPath := filepath.Join(tempDir, "test.db")
	storeDB, err := store.New(dbPath, 30)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
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
		AIClient:           aiClient,
		DisableAdblockSync: true,
	})

	trie := domaintrie.NewTrie()
	for _, d := range domains {
		trie.Add(d)
	}
	service.adblockTrie.Store(trie)

	t.Cleanup(func() {
		_ = service.Close()
	})

	return service, storeDB
}

// countingAIRefineServer counts every refinement request and always answers
// with a benign (non-promoting) result so it can be used both for the
// zero-call assertion and the legacy fallback path.
func countingAIRefineServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"{\"verdict\":\"SAFE\",\"confidence\":0.5,\"reason\":\"ai benign\"}"}]}}]}`))
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

// 1. Separated Analyze: a lexical-safe adblock domain must not become
// MALICIOUS just because of the trie, and its security reasons must not
// contain the adblock marker.
func TestSeparatedAnalyzeAdblockOnlyIsNotMalicious(t *testing.T) {
	service, _ := newSemanticsTestService(t, PolicySemanticsSeparated, []string{"clean-ads.example.com"}, nil)

	result := service.Analyze(context.Background(), "clean-ads.example.com", ClientInfo{})
	if result.Verdict == analysis.VerdictMalicious && result.Score >= 70 {
		t.Fatalf("adblock-only domain must not be malicious without independent evidence, got %s/%d reasons=%v", result.Verdict, result.Score, result.Reasons)
	}
	if slicesContains(result.Reasons, "adblock") {
		t.Fatalf("adblock must not be injected into security reasons, got %v", result.Reasons)
	}
	if result.Domain != "clean-ads.example.com" {
		t.Fatalf("expected normal pipeline result for the domain, got %+v", result.Result)
	}
}

// 2. Separated Policy: block stays, Decision carries the adblock reason, and
// the lexical-only Result must not be MALICIOUS/100 for a lexical-safe domain.
func TestSeparatedPolicyBlocksAdblockWithLexicalResult(t *testing.T) {
	service, _ := newSemanticsTestService(t, PolicySemanticsSeparated, []string{"clean-ads.example.com"}, nil)

	pol := service.Policy(context.Background(), "clean-ads.example.com", ClientInfo{})
	if pol.Policy != "block" {
		t.Fatalf("expected DNS policy block, got %s", pol.Policy)
	}
	if pol.Decision == nil {
		t.Fatal("expected decision on separated adblock block")
	}
	want := PolicyDecision{
		Action:         "block",
		Kind:           "content",
		Category:       "unknown",
		Reason:         "adblock_match",
		Source:         "adblock",
		AssessmentMode: "lexical_local_default_brands",
		// Seeded via the legacy Add helper in the test service.
		MatchedRule: "clean-ads.example.com",
		MatchType:   "suffix",
		SourceID:    "legacy",
	}
	if *pol.Decision != want {
		t.Fatalf("decision mismatch:\n got %+v\nwant %+v", *pol.Decision, want)
	}
	if pol.Result.Verdict == analysis.VerdictMalicious && pol.Result.Score >= 70 {
		t.Fatalf("lexical-only result must not be MALICIOUS/100 for a safe domain, got %s/%d", pol.Result.Verdict, pol.Result.Score)
	}
	if pol.Result.Confidence >= 1.0 {
		t.Fatalf("lexical result must not claim full confidence, got %v", pol.Result.Confidence)
	}
	if pol.Result.Category == "adware" {
		t.Fatalf("adware category must not come from adblock match, got %s", pol.Result.Category)
	}
	if slicesContains(pol.Result.Reasons, "adblock") {
		t.Fatalf("adblock must not appear in Result.Reasons, got %v", pol.Result.Reasons)
	}
	if pol.CacheHit {
		t.Fatal("adblock fast path must not be a cache hit")
	}
}

// 3. Lexical independence: when the lexical analyzer independently scores a
// domain MALICIOUS, Policy keeps the block and the verdict, but the reasons
// are lexical ones — never the adblock marker.
func TestSeparatedPolicyKeepsIndependentLexicalMalicious(t *testing.T) {
	service, _ := newSemanticsTestService(t, PolicySemanticsSeparated, []string{"secure-login-verify-account.example.com"}, nil)

	pol := service.Policy(context.Background(), "secure-login-verify-account.example.com", ClientInfo{})
	if pol.Policy != "block" {
		t.Fatalf("expected block, got %s", pol.Policy)
	}
	if pol.Result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected independent lexical verdict malicious, got %s reasons=%v", pol.Result.Verdict, pol.Result.Reasons)
	}
	if slicesContains(pol.Result.Reasons, "adblock") {
		t.Fatalf("adblock must not appear in security reasons, got %v", pol.Result.Reasons)
	}
	if pol.Decision == nil || pol.Decision.Reason != "adblock_match" || pol.Decision.AssessmentMode != "lexical_local_default_brands" {
		t.Fatalf("expected adblock content decision, got %+v", pol.Decision)
	}
	if pol.Decision.MatchedRule != "secure-login-verify-account.example.com" || pol.Decision.MatchType != "suffix" || pol.Decision.SourceID != "legacy" {
		t.Fatalf("expected rule provenance in decision, got %+v", pol.Decision)
	}
}

// 4. Legacy rollback: SAFE_ZONE_POLICY_SEMANTICS=legacy reproduces the fused
// MALICIOUS/100/adware behavior for both Analyze and Policy.
func TestLegacySemanticsReproduceMaliciousHundred(t *testing.T) {
	service, _ := newSemanticsTestService(t, PolicySemanticsLegacy, []string{"clean-ads.example.com"}, nil)

	result := service.Analyze(context.Background(), "clean-ads.example.com", ClientInfo{})
	if result.Verdict != analysis.VerdictMalicious || result.Score != 100 || result.Confidence != 1.0 {
		t.Fatalf("legacy analyze must reproduce MALICIOUS/100/1.0, got %s/%d/%v", result.Verdict, result.Score, result.Confidence)
	}
	if result.Result.Category != "adware" || len(result.Reasons) == 0 || result.Reasons[0] != "adblock" {
		t.Fatalf("legacy analyze must report adblock/adware, got category %s reasons %v", result.Result.Category, result.Reasons)
	}

	pol := service.Policy(context.Background(), "clean-ads.example.com", ClientInfo{})
	if pol.Policy != "block" || pol.Result.Verdict != analysis.VerdictMalicious || pol.Result.Score != 100 {
		t.Fatalf("legacy policy must reproduce block + MALICIOUS/100, got %s %s/%d", pol.Policy, pol.Result.Verdict, pol.Result.Score)
	}
	if pol.Decision != nil {
		t.Fatalf("legacy policy must not attach a separated decision, got %+v", pol.Decision)
	}
}

// NormalizePolicySemantics must default to separated and tolerate unknown
// values instead of failing startup.
func TestNormalizePolicySemantics(t *testing.T) {
	cases := map[string]PolicySemantics{
		"separated": PolicySemanticsSeparated,
		"SEPARATED": PolicySemanticsSeparated,
		" legacy ":  PolicySemanticsLegacy,
		"legacy":    PolicySemanticsLegacy,
		"":          PolicySemanticsSeparated,
		"bogus":     PolicySemanticsSeparated,
	}
	for raw, want := range cases {
		if got := NormalizePolicySemantics(raw); got != want {
			t.Fatalf("NormalizePolicySemantics(%q) = %s, want %s", raw, got, want)
		}
	}
}

// 5. The separated adblock Policy fast path must not call the AI provider.
// The domain is lexical-suspicious so the non-adblock pipeline would reach
// refineWithAI; if this path went through s.analyze() the counter would move.
func TestSeparatedAdblockPolicyDoesNotCallAI(t *testing.T) {
	server, calls := countingAIRefineServer(t)
	aiClient := ai.NewClient(ai.Config{
		Provider:      "gemini",
		GeminiBaseURL: server.URL,
		GeminiAPIKey:  "test-key",
		GeminiModel:   "gemini-test",
		GeminiTimeout: 2 * time.Second,
	})
	if !aiClient.Enabled() {
		t.Fatal("expected ai client to be enabled for the test")
	}

	service, _ := newSemanticsTestService(t, PolicySemanticsSeparated, []string{"secure-login.example.com"}, aiClient)

	pol := service.Policy(context.Background(), "secure-login.example.com", ClientInfo{})
	if pol.Policy != "block" {
		t.Fatalf("expected block, got %s", pol.Policy)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("separated adblock policy must not call AI, got %d calls", got)
	}
}

// 6. Telemetry: the separated adblock block records source "adblock" while
// verdict/score/reasons stay the untouched lexical result.
func TestSeparatedAdblockPolicyTelemetrySourceIsAdblock(t *testing.T) {
	service, storeDB := newSemanticsTestService(t, PolicySemanticsSeparated, []string{"clean-ads.example.com"}, nil)

	pol := service.Policy(context.Background(), "clean-ads.example.com", ClientInfo{})
	if pol.Policy != "block" {
		t.Fatalf("expected block, got %s", pol.Policy)
	}

	// RecordAnalysis is non-blocking; poll until the async writer lands the
	// entry (production drain happens in Close, which would disable queries).
	deadline := time.Now().Add(5 * time.Second)
	var entries []store.TelemetryEntry
	var err error
	for {
		entries, err = storeDB.QueryRecentFiltered(context.Background(), store.TelemetryFilter{Source: "adblock"}, 10, 0)
		if err != nil {
			t.Fatalf("query telemetry: %v", err)
		}
		if len(entries) == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one adblock telemetry entry, got %d", len(entries))
	}
	entry := entries[0]
	if entry.Source != "adblock" {
		t.Fatalf("expected telemetry source adblock, got %s", entry.Source)
	}
	if entry.Verdict != string(pol.Result.Verdict) || entry.Score != pol.Result.Score {
		t.Fatalf("telemetry must record the lexical result, got %s/%d want %s/%d", entry.Verdict, entry.Score, pol.Result.Verdict, pol.Result.Score)
	}
	if slicesContains(entry.Reasons, "adblock") {
		t.Fatalf("telemetry reasons must not be polluted by the policy reason, got %v", entry.Reasons)
	}
}

// 7. JSON compatibility: payloads without decision decode fine, and a
// decision-bearing payload round-trips.
func TestPolicyJSONBackwardCompatibility(t *testing.T) {
	legacyPayload := `{"domain":"ads.example.com","policy":"block","result":{"domain":"ads.example.com","verdict":"MALICIOUS","confidence":1,"score":100,"reasons":["adblock"]},"cache_hit":false}`
	var legacy Policy
	if err := json.Unmarshal([]byte(legacyPayload), &legacy); err != nil {
		t.Fatalf("legacy payload must decode: %v", err)
	}
	if legacy.Decision != nil {
		t.Fatalf("payload without decision must decode to nil decision, got %+v", legacy.Decision)
	}
	if legacy.Policy != "block" || legacy.Result.Score != 100 {
		t.Fatalf("legacy payload fields lost: %+v", legacy)
	}

	separated := Policy{
		Domain: "ads.example.com",
		Policy: "block",
		Result: analysis.Result{Domain: "ads.example.com", Verdict: analysis.VerdictSafe, Score: 0, Reasons: []string{}},
		Decision: &PolicyDecision{
			Action:         "block",
			Kind:           "content",
			Category:       "unknown",
			Reason:         "adblock_match",
			Source:         "adblock",
			AssessmentMode: "lexical_local_default_brands",
		},
	}
	data, err := json.Marshal(separated)
	if err != nil {
		t.Fatalf("marshal separated policy: %v", err)
	}
	if !strings.Contains(string(data), `"decision"`) {
		t.Fatalf("decision must be serialized, got %s", data)
	}
	var decoded Policy
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode separated payload: %v", err)
	}
	if decoded.Decision == nil || decoded.Decision.Reason != "adblock_match" {
		t.Fatalf("decision round-trip failed: %+v", decoded.Decision)
	}
}

// 8. The AI fallback path still works under separated semantics for
// non-adblock suspicious domains, proving the flag only rewrites the adblock
// branch and not the general pipeline.
func TestSeparatedSemanticsKeepGeneralPipeline(t *testing.T) {
	server, calls := countingAIRefineServer(t)
	aiClient := ai.NewClient(ai.Config{
		Provider:      "gemini",
		GeminiBaseURL: server.URL,
		GeminiAPIKey:  "test-key",
		GeminiModel:   "gemini-test",
		GeminiTimeout: 2 * time.Second,
	})

	// Lexical-suspicious domain (keywords secure+login, score 45) that is NOT
	// in the adblock trie.
	service, _ := newSemanticsTestService(t, PolicySemanticsSeparated, []string{"unrelated-ads.example.com"}, aiClient)

	result := service.Analyze(context.Background(), "secure-login.example.com", ClientInfo{})
	if got := calls.Load(); got == 0 {
		t.Fatal("expected AI refinement for a suspicious non-adblock domain under separated semantics")
	}
	if result.Verdict != analysis.VerdictSuspicious {
		t.Fatalf("expected suspicious verdict to survive benign AI refinement, got %s reasons=%v", result.Verdict, result.Reasons)
	}
}

// 9. The separated adblock Policy fast path must be strictly local-only: the
// analyzer backing the service must never consult BrandStore.ListBrands
// (which can hit Redis/SQLite on a cold cache), even when the fake store
// would panic if called.
func TestSeparatedAdblockPolicyNeverTouchesBrandStore(t *testing.T) {
	fake := &panickingBrandStore{calls: &atomic.Int64{}}
	service, _ := newSemanticsTestService(t, PolicySemanticsSeparated, []string{"clean-ads.example.com"}, nil)

	// Wire an analyzer whose brand store panics if consulted.
	service.analyzerMu.Lock()
	service.analyzer = analysis.NewAnalyzerWithBrandStore(config.DefaultAnalysisConfig(), fake)
	service.analyzerMu.Unlock()

	pol := service.Policy(context.Background(), "clean-ads.example.com", ClientInfo{})
	if pol.Policy != "block" || pol.Decision == nil || pol.Decision.Reason != "adblock_match" {
		t.Fatalf("expected adblock block with decision, got %+v", pol)
	}
	if got := fake.calls.Load(); got != 0 {
		t.Fatalf("adblock Policy fast path must not call ListBrands, got %d calls", got)
	}
	if pol.Result.Verdict == analysis.VerdictMalicious && pol.Result.Score >= 70 {
		t.Fatalf("lexical-local result must stay non-malicious for a safe domain, got %s/%d", pol.Result.Verdict, pol.Result.Score)
	}
}

// countingBrandStore implements analysis.BrandStore, counting ListBrands
// calls and returning an error for each one.
type countingBrandStore struct {
	listCalls *atomic.Int64
}

func (c *countingBrandStore) ListBrands(ctx context.Context) ([]analysis.Brand, error) {
	c.listCalls.Add(1)
	return nil, errors.New("countingBrandStore: ListBrands must not be called on the adblock fast path")
}

func (c *countingBrandStore) GetBrand(ctx context.Context, id int64) (analysis.Brand, error) {
	return analysis.Brand{}, errors.New("not implemented")
}

func (c *countingBrandStore) CreateBrand(ctx context.Context, brand analysis.Brand) (analysis.Brand, error) {
	return analysis.Brand{}, errors.New("not implemented")
}

func (c *countingBrandStore) UpdateBrand(ctx context.Context, id int64, brand analysis.Brand) (analysis.Brand, error) {
	return analysis.Brand{}, errors.New("not implemented")
}

func (c *countingBrandStore) DeleteBrand(ctx context.Context, id int64) error {
	return errors.New("not implemented")
}

// panickingBrandStore panics on ListBrands so that any accidental call on the
// adblock fast path fails the test even before the counter assertion. The
// panic is delivered as the recorded error in spirit: the assertion is zero
// calls, so neither a panic nor an error branch may ever run.
type panickingBrandStore struct {
	calls *atomic.Int64
}

func (p *panickingBrandStore) ListBrands(ctx context.Context) ([]analysis.Brand, error) {
	p.calls.Add(1)
	panic("ListBrands must not be called on the adblock fast path")
}

func (p *panickingBrandStore) GetBrand(ctx context.Context, id int64) (analysis.Brand, error) {
	p.calls.Add(1)
	panic("GetBrand must not be called on the adblock fast path")
}

func (p *panickingBrandStore) CreateBrand(ctx context.Context, brand analysis.Brand) (analysis.Brand, error) {
	return analysis.Brand{}, errors.New("not implemented")
}

func (p *panickingBrandStore) UpdateBrand(ctx context.Context, id int64, brand analysis.Brand) (analysis.Brand, error) {
	return analysis.Brand{}, errors.New("not implemented")
}

func (p *panickingBrandStore) DeleteBrand(ctx context.Context, id int64) error {
	return errors.New("not implemented")
}

// The error-returning variant keeps the invariant while proving the general
// pipeline tolerates a failing brand store (trustedBrands falls back to the
// default seed) and still consults it at least once.
func TestNonAdblockPipelineToleratesBrandStoreError(t *testing.T) {
	fake := &countingBrandStore{listCalls: &atomic.Int64{}}
	service, _ := newSemanticsTestService(t, PolicySemanticsSeparated, []string{"unrelated-ads.example.com"}, nil)

	service.analyzerMu.Lock()
	service.analyzer = analysis.NewAnalyzerWithBrandStore(config.DefaultAnalysisConfig(), fake)
	service.analyzerMu.Unlock()

	result := service.Analyze(context.Background(), "secure-login.example.com", ClientInfo{})
	if result.Verdict != analysis.VerdictSuspicious {
		t.Fatalf("expected normal pipeline result despite brand store error, got %s reasons=%v", result.Verdict, result.Reasons)
	}
	if got := fake.listCalls.Load(); got == 0 {
		t.Fatal("expected the general pipeline to consult the brand store at least once")
	}
}

func slicesContains(haystack []string, needle string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}
