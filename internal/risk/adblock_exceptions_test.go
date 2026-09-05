package risk

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"safe-zone/internal/ai"
	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
	"safe-zone/internal/domaintrie"
	"safe-zone/internal/store"
)

// newAdblockExceptionService builds a separated-semantics service with the
// given typed rules and exception config file content. Empty configJSON means
// the feature is disabled. Callers may tune Options before construction.
func newAdblockExceptionService(t *testing.T, base Options, rules []domaintrie.Rule, configJSON string) *Service {
	t.Helper()

	tempDir := t.TempDir()
	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")
	if configJSON != "" {
		excPath := filepath.Join(tempDir, "exceptions.json")
		if err := os.WriteFile(excPath, []byte(configJSON), 0o600); err != nil {
			t.Fatalf("write exceptions file: %v", err)
		}
		t.Setenv(envAdblockExceptionsFile, excPath)
	} else {
		t.Setenv(envAdblockExceptionsFile, "")
	}

	dbPath := filepath.Join(tempDir, "test.db")
	storeDB, err := store.New(dbPath, 30)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	if err := storeDB.SetSystemConfig(context.Background(), "adblock_enabled", "true"); err != nil {
		t.Fatalf("enable adblock: %v", err)
	}

	if base.RedisTimeout == 0 {
		base.RedisTimeout = 10 * time.Millisecond
	}
	if base.TTLAllowed == 0 {
		base.TTLAllowed = time.Hour
	}
	if base.TTLSuspicious == 0 {
		base.TTLSuspicious = time.Hour
	}
	if base.TTLBlocked == 0 {
		base.TTLBlocked = time.Hour
	}
	if base.RecentLimit == 0 {
		base.RecentLimit = 10
	}
	base.AnalysisConfig = config.DefaultAnalysisConfig()
	base.Store = storeDB
	base.AdblockFileRoot = tempDir
	base.PolicySemantics = PolicySemanticsSeparated
	base.DisableAdblockSync = true

	service := NewService(base)

	trie := domaintrie.NewTrie()
	for _, rule := range rules {
		if !trie.AddRule(rule) {
			t.Fatalf("test rule rejected: %+v", rule)
		}
	}
	service.AdblockTrieOverride(trie)

	t.Cleanup(func() { _ = service.Close() })
	return service
}

func exceptionEntry(id, domain, scope, matchedRule, sourceID, matchType, category, reason string) string {
	cat := ""
	if category != "" {
		cat = fmt.Sprintf(`,"category":%q`, category)
	}
	return fmt.Sprintf(`{"id":%q,"domain":%q,"scope":%q,"matched_rule":%q,"source_id":%q,"match_type":%q%s,"reason":%q}`,
		id, domain, scope, matchedRule, sourceID, matchType, cat, reason)
}

func exceptionFile(entries ...string) string {
	return fmt.Sprintf(`{"version":1,"exceptions":[%s]}`, strings.Join(entries, ","))
}

// 1. Exact exception suppresses the content block and the full pipeline runs
// (proven by the AI refinement call a lexical-local path would never make).
func TestExceptionSuppressesExactMatchAndRunsPipeline(t *testing.T) {
	server, aiCalls := countingAIRefineServer(t)
	aiClient := ai.NewClient(ai.Config{
		Provider:      "gemini",
		GeminiBaseURL: server.URL,
		GeminiAPIKey:  "test-key",
		GeminiModel:   "gemini-test",
		GeminiTimeout: 2 * time.Second,
	})

	srcA := canonicalSourceID("https://a.test/hosts")
	// Lexical-suspicious domain so the full pipeline reaches AI refinement.
	domain := "secure-login.example.com"
	rules := []domaintrie.Rule{
		{Domain: domain, Scope: domaintrie.RuleScopeSuffix, SourceID: srcA, Category: "tracking", Action: domaintrie.RuleActionBlock},
	}
	cfg := exceptionFile(exceptionEntry("fp-2026-001", domain, "exact", domain, srcA, "suffix", "", "INC-1 verified false positive"))
	service := newAdblockExceptionService(t, Options{AIClient: aiClient}, rules, cfg)

	pol := service.Policy(context.Background(), domain, ClientInfo{})
	if pol.Policy != "allow" {
		t.Fatalf("expected allow after suppression, got %s reasons=%v", pol.Policy, pol.Result.Reasons)
	}
	if pol.Decision == nil {
		t.Fatal("expected exception decision")
	}
	d := pol.Decision
	if d.Action != "allow" || d.Kind != "content" || d.Reason != "adblock_exception" ||
		d.Source != "adblock" || d.AssessmentMode != adblockAssessmentFullPipeline {
		t.Fatalf("unexpected decision: %+v", d)
	}
	if d.MatchedRule != domain || d.MatchType != "suffix" || d.SourceID != srcA || d.ExceptionID != "fp-2026-001" {
		t.Fatalf("decision must carry the real rule provenance plus exception id: %+v", d)
	}
	for _, r := range pol.Result.Reasons {
		if r == "adblock" {
			t.Fatalf("adblock must not leak into the security result: %v", pol.Result.Reasons)
		}
	}
	if got := aiCalls.Load(); got == 0 {
		t.Fatal("expected the full pipeline to reach AI refinement for a suspicious domain")
	}
	if got := service.AdblockExceptionStatus().Matches; got != 1 {
		t.Fatalf("expected 1 exception match, got %d", got)
	}
}

// 2. Lexical-malicious stays blocked even with a matching exception.
func TestExceptionDoesNotSaveLexicalMalicious(t *testing.T) {
	srcA := canonicalSourceID("https://a.test/hosts")
	domain := "secure-login-verify-account.example.com"
	rules := []domaintrie.Rule{
		{Domain: domain, Scope: domaintrie.RuleScopeSuffix, SourceID: srcA, Category: "tracking", Action: domaintrie.RuleActionBlock},
	}
	cfg := exceptionFile(exceptionEntry("fp-2026-002", domain, "exact", domain, srcA, "suffix", "", "INC-2"))
	service := newAdblockExceptionService(t, Options{}, rules, cfg)

	pol := service.Policy(context.Background(), domain, ClientInfo{})
	if pol.Policy != "block" {
		t.Fatalf("expected security block to win, got %s", pol.Policy)
	}
	if pol.Result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected malicious security verdict, got %s", pol.Result.Verdict)
	}
	if pol.Decision == nil || pol.Decision.Action != "allow" || pol.Decision.Reason != "adblock_exception" {
		t.Fatalf("expected content-axis allow decision alongside the block, got %+v", pol.Decision)
	}
}

// 3. ML enforce promotion still blocks with an exception; AI routing follows
// the old pipeline (no AI call once ML promotes).
func TestExceptionMLPromoteStillBlocks(t *testing.T) {
	server, aiCalls := countingAIRefineServer(t)
	aiClient := ai.NewClient(ai.Config{
		Provider:      "gemini",
		GeminiBaseURL: server.URL,
		GeminiAPIKey:  "test-key",
		GeminiModel:   "gemini-test",
		GeminiTimeout: 2 * time.Second,
	})
	fake := &fakeMLClassifier{decision: analysis.MLDecision{
		Probability:  0.93,
		Action:       analysis.MLActionPromoteMalicious,
		ModelVersion: "test-model",
	}}

	srcA := canonicalSourceID("https://a.test/hosts")
	domain := "secure-login.example.com"
	rules := []domaintrie.Rule{
		{Domain: domain, Scope: domaintrie.RuleScopeSuffix, SourceID: srcA, Category: "tracking", Action: domaintrie.RuleActionBlock},
	}
	cfg := exceptionFile(exceptionEntry("fp-2026-003", domain, "exact", domain, srcA, "suffix", "", "INC-3"))
	service := newAdblockExceptionService(t, Options{
		AIClient:     aiClient,
		MLClassifier: fake,
		MLMode:       analysis.MLModeEnforce,
		MLCanary:     MLCanaryConfig{Percent: 100, Seed: "test-enforce"},
	}, rules, cfg)

	pol := service.Policy(context.Background(), domain, ClientInfo{})
	if pol.Policy != "block" {
		t.Fatalf("expected ML-promoted block to win, got %s", pol.Policy)
	}
	if fake.calls != 1 {
		t.Fatalf("expected one ML call, got %d", fake.calls)
	}
	if got := aiCalls.Load(); got != 0 {
		t.Fatalf("ML promotion must keep skipping AI, got %d calls", got)
	}
	if pol.Decision == nil || pol.Decision.Reason != "adblock_exception" {
		t.Fatalf("expected exception decision attached, got %+v", pol.Decision)
	}
}

// 4. Admin block wins; the exception is never consulted (no match counted).
func TestAdminOverrideWinsOverException(t *testing.T) {
	srcA := canonicalSourceID("https://a.test/hosts")
	domain := "override-me.example.com"
	rules := []domaintrie.Rule{
		{Domain: domain, Scope: domaintrie.RuleScopeSuffix, SourceID: srcA, Category: "ads", Action: domaintrie.RuleActionBlock},
	}
	cfg := exceptionFile(exceptionEntry("fp-2026-004", domain, "exact", domain, srcA, "suffix", "", "INC-4"))
	service := newAdblockExceptionService(t, Options{}, rules, cfg)

	if err := service.UpsertOverride(domain, "block", "admin says so"); err != nil {
		t.Fatalf("upsert override: %v", err)
	}

	pol := service.Policy(context.Background(), domain, ClientInfo{})
	if pol.Policy != "block" {
		t.Fatalf("expected admin block, got %s", pol.Policy)
	}
	if pol.Decision != nil {
		t.Fatalf("override path must not carry a content decision, got %+v", pol.Decision)
	}
	if got := service.AdblockExceptionStatus().Matches; got != 0 {
		t.Fatalf("exception must not be consulted past an override, matches=%d", got)
	}
}

// 5. Whitelist precedence stays locked: early allow, no decision rewrite.
func TestWhitelistPrecedenceLockedWithException(t *testing.T) {
	srcA := canonicalSourceID("https://a.test/hosts")
	domain := "listed.example.com"
	rules := []domaintrie.Rule{
		{Domain: domain, Scope: domaintrie.RuleScopeSuffix, SourceID: srcA, Category: "ads", Action: domaintrie.RuleActionBlock},
	}
	cfg := exceptionFile(exceptionEntry("fp-2026-005", domain, "exact", domain, srcA, "suffix", "", "INC-5"))
	service := newAdblockExceptionService(t, Options{}, rules, cfg)

	if err := service.store.UpdateWhitelist(context.Background(), []string{domain}); err != nil {
		t.Fatalf("update whitelist: %v", err)
	}
	if err := service.whitelist.LoadFromDB(); err != nil {
		t.Fatalf("reload whitelist: %v", err)
	}

	pol := service.Policy(context.Background(), domain, ClientInfo{})
	if pol.Policy != "allow" {
		t.Fatalf("expected whitelist allow, got %s", pol.Policy)
	}
	if pol.Decision != nil {
		t.Fatalf("whitelist path must not carry a decision, got %+v", pol.Decision)
	}
}

// 6. Source isolation: source B's exception never suppresses source A's rule.
func TestExceptionSourceIsolation(t *testing.T) {
	srcA := canonicalSourceID("https://a.test/hosts")
	srcB := canonicalSourceID("https://b.test/hosts")
	domain := "iso.example.com"
	rules := []domaintrie.Rule{
		{Domain: domain, Scope: domaintrie.RuleScopeSuffix, SourceID: srcA, Category: "ads", Action: domaintrie.RuleActionBlock},
	}
	wrong := exceptionFile(exceptionEntry("fp-2026-006", domain, "exact", domain, srcB, "suffix", "", "INC-6"))
	service := newAdblockExceptionService(t, Options{}, rules, wrong)

	pol := service.Policy(context.Background(), domain, ClientInfo{})
	if pol.Policy != "block" || pol.Decision == nil || pol.Decision.Reason != "adblock_match" {
		t.Fatalf("wrong-source exception must not suppress, got %+v", pol.Decision)
	}

	// Rewrite with the right source and reload: now it suppresses.
	excPath := os.Getenv(envAdblockExceptionsFile)
	right := exceptionFile(exceptionEntry("fp-2026-006", domain, "exact", domain, srcA, "suffix", "", "INC-6"))
	if err := os.WriteFile(excPath, []byte(right), 0o600); err != nil {
		t.Fatal(err)
	}
	service.reloadAdblockExceptions()

	pol = service.Policy(context.Background(), domain, ClientInfo{})
	if pol.Policy != "allow" || pol.Decision == nil || pol.Decision.Reason != "adblock_exception" {
		t.Fatalf("right-source exception must suppress, got %s %+v", pol.Policy, pol.Decision)
	}
}

// 7. Category constraint: ads does not suppress telemetry; omitted is wildcard.
func TestExceptionCategoryConstraint(t *testing.T) {
	srcA := canonicalSourceID("https://a.test/hosts")
	domain := "cat.example.com"
	rules := []domaintrie.Rule{
		{Domain: domain, Scope: domaintrie.RuleScopeSuffix, SourceID: srcA, Category: "telemetry", Action: domaintrie.RuleActionBlock},
	}
	narrow := exceptionFile(exceptionEntry("fp-2026-007", domain, "exact", domain, srcA, "suffix", "ads", "INC-7"))
	service := newAdblockExceptionService(t, Options{}, rules, narrow)

	pol := service.Policy(context.Background(), domain, ClientInfo{})
	if pol.Policy != "block" || pol.Decision == nil || pol.Decision.Reason != "adblock_match" {
		t.Fatalf("ads exception must not suppress a telemetry rule, got %+v", pol.Decision)
	}

	excPath := os.Getenv(envAdblockExceptionsFile)
	wide := exceptionFile(exceptionEntry("fp-2026-007", domain, "exact", domain, srcA, "suffix", "", "INC-7"))
	if err := os.WriteFile(excPath, []byte(wide), 0o600); err != nil {
		t.Fatal(err)
	}
	service.reloadAdblockExceptions()

	pol = service.Policy(context.Background(), domain, ClientInfo{})
	if pol.Policy != "allow" || pol.Decision == nil || pol.Decision.Reason != "adblock_exception" {
		t.Fatalf("omitted category must wildcard, got %s %+v", pol.Policy, pol.Decision)
	}
}

// 8. Exact exception never covers a subdomain.
func TestExactExceptionIgnoresSubdomain(t *testing.T) {
	srcA := canonicalSourceID("https://a.test/hosts")
	domain := "app.example.com"
	rules := []domaintrie.Rule{
		{Domain: domain, Scope: domaintrie.RuleScopeSuffix, SourceID: srcA, Category: "ads", Action: domaintrie.RuleActionBlock},
	}
	cfg := exceptionFile(exceptionEntry("fp-2026-008", domain, "exact", domain, srcA, "suffix", "", "INC-8"))
	service := newAdblockExceptionService(t, Options{}, rules, cfg)

	pol := service.Policy(context.Background(), "sub."+domain, ClientInfo{})
	if pol.Policy != "block" || pol.Decision == nil || pol.Decision.Reason != "adblock_match" {
		t.Fatalf("exact exception must not cover subdomains, got %s %+v", pol.Policy, pol.Decision)
	}
}

// 9. Suffix exception covers the domain and subdomains at label boundaries.
func TestSuffixExceptionBoundary(t *testing.T) {
	srcA := canonicalSourceID("https://a.test/hosts")
	domain := "example.com"
	rules := []domaintrie.Rule{
		{Domain: domain, Scope: domaintrie.RuleScopeSuffix, SourceID: srcA, Category: "ads", Action: domaintrie.RuleActionBlock},
	}
	cfg := exceptionFile(exceptionEntry("fp-2026-009", domain, "suffix", domain, srcA, "suffix", "", "INC-9"))
	service := newAdblockExceptionService(t, Options{}, rules, cfg)

	for _, q := range []string{domain, "sub." + domain, "deep.sub." + domain} {
		pol := service.Policy(context.Background(), q, ClientInfo{})
		if pol.Decision == nil || pol.Decision.Reason != "adblock_exception" {
			t.Fatalf("suffix exception must suppress %s, got %+v", q, pol.Decision)
		}
	}
	pol := service.Policy(context.Background(), "evil-"+domain, ClientInfo{})
	if pol.Decision != nil && pol.Decision.Reason == "adblock_exception" {
		t.Fatalf("sibling must never match a suffix selector: %+v", pol.Decision)
	}
}

// 10. Invalid configs fail closed without panic.
func TestExceptionConfigValidationFailClosed(t *testing.T) {
	srcA := canonicalSourceID("https://a.test/hosts")
	goodEntry := exceptionEntry("fp-good", "good.example.com", "exact", "good.example.com", srcA, "suffix", "", "ok")
	good := exceptionFile(goodEntry)

	newStartupService := func(t *testing.T, body string) *Service {
		t.Helper()
		tempDir := t.TempDir()
		t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")
		if body != "" {
			if err := os.WriteFile(filepath.Join(tempDir, "exceptions.json"), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv(envAdblockExceptionsFile, filepath.Join(tempDir, "exceptions.json"))
		} else {
			t.Setenv(envAdblockExceptionsFile, filepath.Join(tempDir, "does-not-exist.json"))
		}
		dbPath := filepath.Join(tempDir, "test.db")
		storeDB, err := store.New(dbPath, 30)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = storeDB.Close() })
		return NewService(Options{
			AnalysisConfig:     config.DefaultAnalysisConfig(),
			RedisTimeout:       10 * time.Millisecond,
			Store:              storeDB,
			AdblockFileRoot:    tempDir,
			PolicySemantics:    PolicySemanticsSeparated,
			DisableAdblockSync: true,
		})
	}

	oversized := `{"version":1,"exceptions":[` + strings.Repeat(`{"id":"x","domain":"a.example.com","scope":"exact","matched_rule":"a.example.com","source_id":"`+srcA+`","match_type":"suffix","reason":"r"},`, 3000) + `]}`
	manyEntries := `{"version":1,"exceptions":[`
	for i := 0; i < 1025; i++ {
		if i > 0 {
			manyEntries += ","
		}
		manyEntries += fmt.Sprintf(`{"id":"fp-%d","domain":"h%d.example.com","scope":"exact","matched_rule":"h%d.example.com","source_id":%q,"match_type":"suffix","reason":"r"}`,
			i, i, i, srcA)
	}
	manyEntries += `]}`

	cases := map[string]string{
		"missing_file":     "",
		"bad_version":      `{"version":2,"exceptions":[]}`,
		"unknown_top":      `{"version":1,"bogus":true,"exceptions":[]}`,
		"unknown_entry":    exceptionFile(`{"id":"a","domain":"a.example.com","scope":"exact","matched_rule":"a.example.com","source_id":"` + srcA + `","match_type":"suffix","reason":"r","action":"allow"}`),
		"duplicate_id":     exceptionFile(goodEntry, exceptionEntry("fp-good", "other.example.com", "exact", "other.example.com", srcA, "suffix", "", "r")),
		"duplicate_sel":    exceptionFile(goodEntry, exceptionEntry("fp-other", "good.example.com", "exact", "good.example.com", srcA, "suffix", "", "r")),
		"public_suffix":    exceptionFile(exceptionEntry("fp-ps", "com", "suffix", "com", srcA, "suffix", "", "r")),
		"oversized":        oversized,
		"too_many":         manyEntries,
		"unknown_scope":    exceptionFile(exceptionEntry("fp-s", "s.example.com", "glob", "s.example.com", srcA, "suffix", "", "r")),
		"unknown_match":    exceptionFile(exceptionEntry("fp-m", "s.example.com", "exact", "s.example.com", srcA, "glob", "", "r")),
		"unknown_cat":      exceptionFile(exceptionEntry("fp-c", "s.example.com", "exact", "s.example.com", srcA, "suffix", "spyware", "r")),
		"bad_source_id":    exceptionFile(exceptionEntry("fp-i", "s.example.com", "exact", "s.example.com", "xyz", "suffix", "", "r")),
		"url_domain":       exceptionFile(exceptionEntry("fp-u", "https://s.example.com/x", "exact", "s.example.com", srcA, "suffix", "", "r")),
		"port_domain":      exceptionFile(exceptionEntry("fp-p", "s.example.com:8080", "exact", "s.example.com", srcA, "suffix", "", "r")),
		"wildcard":         exceptionFile(exceptionEntry("fp-w", "*.s.example.com", "suffix", "s.example.com", srcA, "suffix", "", "r")),
		"no_intersect":     exceptionFile(exceptionEntry("fp-n", "a.example.com", "exact", "b.example.com", srcA, "exact", "", "r")),
		"empty_reason":     exceptionFile(exceptionEntry("fp-e", "s.example.com", "exact", "s.example.com", srcA, "suffix", "", "")),
		"trailing_garbage": good + `{"version":1}`,
	}

	for name, body := range cases {
		t.Run("startup_"+name, func(t *testing.T) {
			var svc *Service
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("panic on %s: %v", name, r)
					}
				}()
				svc = newStartupService(t, body)
			}()
			defer svc.Close()
			status := svc.AdblockExceptionStatus()
			if !status.Configured {
				t.Fatal("file path set means configured, even when invalid")
			}
			if status.Count != 0 || status.Revision != "" {
				t.Fatalf("invalid startup must publish empty set, got %+v", status)
			}
			if status.LastReloadOK || status.LastErrorClass == "" {
				t.Fatalf("invalid startup must record an error class, got %+v", status)
			}
		})
	}

	// Runtime: a valid snapshot survives a later invalid reload.
	t.Run("runtime_keeps_old", func(t *testing.T) {
		tempDir := t.TempDir()
		t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")
		excPath := filepath.Join(tempDir, "exceptions.json")
		if err := os.WriteFile(excPath, []byte(good), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(envAdblockExceptionsFile, excPath)
		dbPath := filepath.Join(tempDir, "test.db")
		storeDB, err := store.New(dbPath, 30)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = storeDB.Close() })
		svc := NewService(Options{
			AnalysisConfig:     config.DefaultAnalysisConfig(),
			RedisTimeout:       10 * time.Millisecond,
			Store:              storeDB,
			AdblockFileRoot:    tempDir,
			PolicySemantics:    PolicySemanticsSeparated,
			DisableAdblockSync: true,
		})
		defer svc.Close()

		before := svc.AdblockExceptionStatus()
		if before.Count != 1 || !before.LastReloadOK || before.Revision == "" {
			t.Fatalf("expected one loaded exception, got %+v", before)
		}
		if err := os.WriteFile(excPath, []byte(`{"version":1,"nope":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		svc.reloadAdblockExceptions()
		after := svc.AdblockExceptionStatus()
		if after.Count != 1 || after.Revision != before.Revision {
			t.Fatalf("runtime invalid must keep the old snapshot: before=%+v after=%+v", before, after)
		}
		if after.LastReloadOK || after.LastErrorClass == "" || after.ReloadFailures != 1 {
			t.Fatalf("runtime invalid must record failure: %+v", after)
		}
	})
}

// 11. A valid empty file atomically clears every exception.
func TestValidEmptySnapshotClears(t *testing.T) {
	srcA := canonicalSourceID("https://a.test/hosts")
	domain := "clear.example.com"
	rules := []domaintrie.Rule{
		{Domain: domain, Scope: domaintrie.RuleScopeSuffix, SourceID: srcA, Category: "ads", Action: domaintrie.RuleActionBlock},
	}
	cfg := exceptionFile(exceptionEntry("fp-clear", domain, "exact", domain, srcA, "suffix", "", "INC-clear"))
	service := newAdblockExceptionService(t, Options{}, rules, cfg)

	if got := service.AdblockExceptionStatus().Count; got != 1 {
		t.Fatalf("expected 1 exception, got %d", got)
	}
	if err := os.WriteFile(os.Getenv(envAdblockExceptionsFile), []byte(`{"version":1,"exceptions":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	service.reloadAdblockExceptions()

	status := service.AdblockExceptionStatus()
	if status.Count != 0 || !status.LastReloadOK {
		t.Fatalf("empty file must publish an empty set cleanly: %+v", status)
	}
	if status.Revision == "" || len(status.Revision) != 32 {
		t.Fatalf("configured valid-empty snapshot must carry a non-empty digest revision: %+v", status)
	}
	if !status.Configured {
		t.Fatalf("valid empty file still means configured: %+v", status)
	}
	pol := service.Policy(context.Background(), domain, ClientInfo{})
	if pol.Decision == nil || pol.Decision.Reason != "adblock_match" {
		t.Fatalf("cleared exceptions must restore the content block: %+v", pol.Decision)
	}
}

// 12. Concurrent requests and reloads stay race-free and converge.
func TestExceptionConcurrentRequestsAndReloads(t *testing.T) {
	srcA := canonicalSourceID("https://a.test/hosts")
	domain := "race.example.com"
	rules := []domaintrie.Rule{
		{Domain: domain, Scope: domaintrie.RuleScopeSuffix, SourceID: srcA, Category: "ads", Action: domaintrie.RuleActionBlock},
	}
	one := exceptionFile(exceptionEntry("fp-r1", domain, "exact", domain, srcA, "suffix", "", "r1"))
	two := exceptionFile(
		exceptionEntry("fp-r1", domain, "exact", domain, srcA, "suffix", "", "r1"),
		exceptionEntry("fp-r2", "other.example.com", "exact", "other.example.com", srcA, "suffix", "", "r2"),
	)
	service := newAdblockExceptionService(t, Options{}, rules, one)
	excPath := os.Getenv(envAdblockExceptionsFile)

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				_ = service.Policy(context.Background(), domain, ClientInfo{})
			}
		}()
	}
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func(r int) {
			defer wg.Done()
			body := one
			if r%2 == 1 {
				body = two
			}
			_ = os.WriteFile(excPath, []byte(body), 0o600)
			service.reloadAdblockExceptions()
		}(r)
	}
	wg.Wait()

	status := service.AdblockExceptionStatus()
	if status.Count != 1 && status.Count != 2 {
		t.Fatalf("snapshot must converge to a valid file state, got %+v", status)
	}
}

// 13. Cache v2 provenance round-trips; legacy-cache matches only when explicit.
func TestExceptionCacheV2AndLegacyProvenance(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")
	t.Setenv(envAdblockExceptionsFile, "")
	dbPath := filepath.Join(tempDir, "test.db")
	storeDB, err := store.New(dbPath, 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storeDB.Close() })
	// The package TestMain disables adblock process-wide; re-enable for
	// this service like the other adblock helpers do.
	if err := storeDB.SetSystemConfig(context.Background(), "adblock_enabled", "true"); err != nil {
		t.Fatal(err)
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
		PolicySemantics:    PolicySemanticsSeparated,
		DisableAdblockSync: true,
	})
	t.Cleanup(func() { _ = service.Close() })

	srcA := canonicalSourceID("https://a.test/hosts")
	built := domaintrie.NewTrie()
	built.AddRule(domaintrie.Rule{Domain: "cache.example.com", Scope: domaintrie.RuleScopeSuffix, SourceID: srcA, Category: "telemetry", Action: domaintrie.RuleActionBlock})
	service.saveAdblockCache(built)
	reloaded := domaintrie.NewTrie()
	if !service.loadAdblockCache(reloaded) {
		t.Fatal("expected cache reload")
	}
	service.AdblockTrieOverride(reloaded)

	digestExc := exceptionFile(exceptionEntry("fp-v2", "cache.example.com", "exact", "cache.example.com", srcA, "suffix", "", "INC-v2"))
	excPath := filepath.Join(tempDir, "exceptions.json")
	if err := os.WriteFile(excPath, []byte(digestExc), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envAdblockExceptionsFile, excPath)
	service.reloadAdblockExceptions()

	pol := service.Policy(context.Background(), "cache.example.com", ClientInfo{})
	if pol.Decision == nil || pol.Decision.Reason != "adblock_exception" || pol.Decision.SourceID != srcA {
		t.Fatalf("digest exception must match the reloaded rule: %+v", pol.Decision)
	}

	// Legacy v1 cache reloads as legacy-cache provenance: a digest exception
	// must not match it, an explicit legacy-cache one must.
	service.saveAdblockCacheRaw("legacy.example.com\n")
	legacyTrie := domaintrie.NewTrie()
	if !service.loadAdblockCache(legacyTrie) {
		t.Fatal("expected legacy cache reload")
	}
	service.AdblockTrieOverride(legacyTrie)

	pol = service.Policy(context.Background(), "legacy.example.com", ClientInfo{})
	if pol.Decision == nil || pol.Decision.Reason != "adblock_match" {
		t.Fatalf("digest exception must not match legacy-cache provenance: %+v", pol.Decision)
	}
	legacyExc := exceptionFile(exceptionEntry("fp-leg", "legacy.example.com", "exact", "legacy.example.com", domaintrie.CacheV2LegacySourceID, "suffix", "", "INC-leg"))
	if err := os.WriteFile(excPath, []byte(legacyExc), 0o600); err != nil {
		t.Fatal(err)
	}
	service.reloadAdblockExceptions()
	pol = service.Policy(context.Background(), "legacy.example.com", ClientInfo{})
	if pol.Decision == nil || pol.Decision.Reason != "adblock_exception" {
		t.Fatalf("explicit legacy-cache exception must match: %+v", pol.Decision)
	}
}

// 14. Legacy semantics ignore exceptions entirely.
func TestLegacySemanticsIgnoreExceptions(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")
	srcA := canonicalSourceID("https://a.test/hosts")
	domain := "legacy-ads.example.com"
	cfg := exceptionFile(exceptionEntry("fp-leg2", domain, "exact", domain, srcA, "suffix", "", "INC-leg2"))
	excPath := filepath.Join(tempDir, "exceptions.json")
	if err := os.WriteFile(excPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envAdblockExceptionsFile, excPath)

	dbPath := filepath.Join(tempDir, "test.db")
	storeDB, err := store.New(dbPath, 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storeDB.Close() })
	if err := storeDB.SetSystemConfig(context.Background(), "adblock_enabled", "true"); err != nil {
		t.Fatal(err)
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
		PolicySemantics:    PolicySemanticsLegacy,
		DisableAdblockSync: true,
	})
	t.Cleanup(func() { _ = service.Close() })

	trie := domaintrie.NewTrie()
	trie.AddRule(domaintrie.Rule{Domain: domain, Scope: domaintrie.RuleScopeSuffix, SourceID: srcA, Category: "ads", Action: domaintrie.RuleActionBlock})
	service.AdblockTrieOverride(trie)

	pol := service.Policy(context.Background(), domain, ClientInfo{})
	if pol.Policy != "block" || pol.Result.Verdict != analysis.VerdictMalicious || pol.Result.Score != 100 {
		t.Fatalf("legacy must keep fused block: %+v", pol)
	}
	if pol.Decision != nil {
		t.Fatalf("legacy must not carry any decision: %+v", pol.Decision)
	}
}

// Correction 1 (round 2): strict trailing EOF after the top-level object.
func TestExceptionConfigStrictTrailingEOF(t *testing.T) {
	srcA := canonicalSourceID("https://a.test/hosts")
	valid := exceptionFile(exceptionEntry("fp-eof", "eof.example.com", "exact", "eof.example.com", srcA, "suffix", "", "INC-eof"))
	cases := map[string]struct {
		body  string
		valid bool
	}{
		"bare object":         {valid, true},
		"trailing whitespace": {valid + "  \n\t\r\n", true},
		"second object":       {valid + `{"version":1}`, false},
		"trailing number":     {valid + ` 42`, false},
		"trailing string":     {valid + `"tail"`, false},
		"trailing null":       {valid + `null`, false},
		"trailing true":       {valid + `true`, false},
		"trailing bracket":    {valid + `]`, false},
		"trailing brace":      {valid + `}`, false},
		"trailing comma":      {valid + `,`, false},
		"trailing word":       {valid + ` garbage`, false},
		"line comment":        {valid + `// comment`, false},
		"block comment":       {valid + `/* comment */`, false},
		"empty body":          {``, false},
		"whitespace only":     {"  \n\t ", false},
		"truncated object":    {`{"version":1,"exceptions":[`, false},
		"second array":        {valid + `[1,2]`, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := validateAdblockExceptions([]byte(tc.body))
			if tc.valid && err != nil {
				t.Fatalf("must accept: %v", err)
			}
			if !tc.valid && err == nil {
				t.Fatal("must reject")
			}
		})
	}
}

// Correction 2: length-prefix framing keeps embedded control bytes
// unambiguous. The pair below collides under the old NUL/newline-joined
// encoding; it must digest differently now.
func TestExceptionRevisionFramingUnambiguous(t *testing.T) {
	src := strings.Repeat("c", 32)
	mk := func(id, reason string) adblockException {
		return adblockException{
			ID: "fp-" + id, Domain: "q.example.com", Scope: domaintrie.RuleScopeExact,
			MatchedRule: "q.example.com", SourceID: src, MatchType: domaintrie.RuleScopeSuffix,
			Category: "", Reason: reason,
		}
	}
	// Old-style joined stream for setOne equals that of setTwo by
	// construction: the first entry's reason embeds a newline plus the full
	// second line.
	oldLine := func(e adblockException) string {
		return strings.Join([]string{
			e.ID, e.Domain, string(e.Scope), e.MatchedRule, e.SourceID, string(e.MatchType), e.Category, e.Reason,
		}, "\x00")
	}
	second := mk("b", "end")
	setOne := []adblockException{mk("a", "tail\n"+oldLine(second))}
	// IDs sort fp-a before fp-b, matching the old encoder's sorted order.
	setTwo := []adblockException{mk("a", "tail"), second}

	oldStream := func(set []adblockException) string {
		lines := make([]string, 0, len(set))
		for _, e := range set {
			lines = append(lines, oldLine(e))
		}
		return strings.Join(lines, "\n") + "\n"
	}
	if oldStream(setOne) != oldStream(setTwo) {
		t.Fatal("test setup must reproduce the old-encoder collision")
	}

	revOne := buildAdblockExceptionSnapshot(setOne).revision
	revTwo := buildAdblockExceptionSnapshot(setTwo).revision
	if revOne == revTwo {
		t.Fatal("framed revisions must differ for different snapshots")
	}

	// Embedded controls load, match and never panic. The JSON uses \u0000
	// because Go %q-style \x00 escapes are not valid JSON.
	cfg := `{"version":1,"exceptions":[{"id":"fp-ctrl","domain":"q.example.com",` +
		`"scope":"exact","matched_rule":"q.example.com","source_id":"` + src + `",` +
		`"match_type":"suffix","reason":"line1\nline2` + "\\u0000" + `tail"}]}`
	entries, err := validateAdblockExceptions([]byte(cfg))
	if err != nil {
		t.Fatalf("control bytes in reason must load: %v", err)
	}
	snap := buildAdblockExceptionSnapshot(entries)
	rule := &domaintrie.Rule{Domain: "q.example.com", Scope: domaintrie.RuleScopeSuffix, SourceID: src, Category: "ads"}
	if id, ok := snap.match("q.example.com", rule); !ok || id != "fp-ctrl" {
		t.Fatalf("control-byte entry must still match, got %q %v", id, ok)
	}
}

// Correction 2: every semantic field and the reason moves the revision;
// identical semantics hash identically across runs.
func TestExceptionRevisionFieldSensitivity(t *testing.T) {
	srcA := canonicalSourceID("https://a.test/hosts")
	domain := "sens.example.com"
	base := adblockException{
		ID: "fp-sens", Domain: domain, Scope: domaintrie.RuleScopeExact,
		MatchedRule: domain, SourceID: srcA, MatchType: domaintrie.RuleScopeSuffix,
		Category: "ads", Reason: "INC-sens",
	}
	revOf := func(e adblockException) string {
		return buildAdblockExceptionSnapshot([]adblockException{e}).revision
	}
	want := revOf(base)
	if want == "" {
		t.Fatal("revision must be non-empty")
	}
	if revOf(base) != want {
		t.Fatal("same semantics must hash identically across runs")
	}
	mutations := map[string]adblockException{
		"id": func() adblockException { e := base; e.ID = "fp-other"; return e }(),
		"domain": func() adblockException {
			e := base
			e.Domain = "other.example.com"
			e.MatchedRule = "other.example.com"
			return e
		}(),
		"scope": func() adblockException { e := base; e.Scope = domaintrie.RuleScopeSuffix; return e }(),
		"matched_rule": func() adblockException {
			e := base
			e.Domain = "other.example.com"
			e.MatchedRule = "other.example.com"
			e.Scope = domaintrie.RuleScopeSuffix
			return e
		}(),
		"source": func() adblockException {
			e := base
			e.SourceID = canonicalSourceID("https://other.test/hosts")
			return e
		}(),
		"match_type": func() adblockException { e := base; e.MatchType = domaintrie.RuleScopeExact; return e }(),
		"category":   func() adblockException { e := base; e.Category = ""; return e }(),
		"reason":     func() adblockException { e := base; e.Reason = "INC-changed"; return e }(),
	}
	for name, mutated := range mutations {
		t.Run(name, func(t *testing.T) {
			if revOf(mutated) == want {
				t.Fatalf("changing %s must change the revision", name)
			}
		})
	}
}

// Correction 1: reason canonicalization feeds the revision without exposure.
func TestExceptionReasonCanonicalization(t *testing.T) {
	srcA := canonicalSourceID("https://a.test/hosts")
	base := func(reason string) string {
		return exceptionFile(exceptionEntry("fp-r", "r.example.com", "exact", "r.example.com", srcA, "suffix", "", reason))
	}

	// Whitespace-only reasons are rejected.
	for _, bad := range []string{"", "   ", "\t\n  "} {
		if _, err := validateAdblockExceptions([]byte(base(bad))); err == nil {
			t.Fatalf("reason %q must be rejected", bad)
		}
	}
	// Reason over the byte limit after trim is rejected; exactly at the limit
	// is accepted. Limits are bytes: a 256-byte reason of 2-byte runes fails.
	if _, err := validateAdblockExceptions([]byte(base(strings.Repeat("r", 256)))); err != nil {
		t.Fatalf("256-byte reason must be accepted: %v", err)
	}
	if _, err := validateAdblockExceptions([]byte(base(strings.Repeat("r", 257)))); err == nil {
		t.Fatal("257-byte reason must be rejected")
	}
	if _, err := validateAdblockExceptions([]byte(base(strings.Repeat("é", 129)))); err == nil {
		t.Fatal("129-rune reason exceeding 256 bytes must be rejected by bytes")
	}

	padded, err := validateAdblockExceptions([]byte(base("  INC-trimmed  ")))
	if err != nil {
		t.Fatalf("padded reason must load: %v", err)
	}
	trimmed, err := validateAdblockExceptions([]byte(base("INC-trimmed")))
	if err != nil {
		t.Fatal(err)
	}
	if padded[0].Reason != "INC-trimmed" {
		t.Fatalf("reason must be stored trimmed, got %q", padded[0].Reason)
	}
	if buildAdblockExceptionSnapshot(padded).revision != buildAdblockExceptionSnapshot(trimmed).revision {
		t.Fatal("padding-only difference must not change the revision")
	}

	// A reason-only change must change the revision.
	other, err := validateAdblockExceptions([]byte(base("INC-different")))
	if err != nil {
		t.Fatal(err)
	}
	if buildAdblockExceptionSnapshot(trimmed).revision == buildAdblockExceptionSnapshot(other).revision {
		t.Fatal("reason-only change must change the revision")
	}

	// Entry order never affects the revision.
	two := func(a, b string) string { return exceptionFile(a, b) }
	e1 := exceptionEntry("fp-1", "one.example.com", "exact", "one.example.com", srcA, "suffix", "ads", "first")
	e2 := exceptionEntry("fp-2", "two.example.com", "exact", "two.example.com", srcA, "suffix", "", "second")
	fwd, err := validateAdblockExceptions([]byte(two(e1, e2)))
	if err != nil {
		t.Fatal(err)
	}
	rev, err := validateAdblockExceptions([]byte(two(e2, e1)))
	if err != nil {
		t.Fatal(err)
	}
	if buildAdblockExceptionSnapshot(fwd).revision != buildAdblockExceptionSnapshot(rev).revision {
		t.Fatal("entry order must not change the revision")
	}
}

// Correction 1: a valid empty config carries a non-empty digest revision,
// distinguishable from the disabled state's empty revision.
func TestValidEmptySnapshotRevision(t *testing.T) {
	entries, err := validateAdblockExceptions([]byte(`{"version":1,"exceptions":[]}`))
	if err != nil {
		t.Fatalf("empty config must validate: %v", err)
	}
	snap := buildAdblockExceptionSnapshot(entries)
	if snap.count != 0 {
		t.Fatalf("expected zero entries, got %d", snap.count)
	}
	if snap.revision == "" || len(snap.revision) != 32 {
		t.Fatalf("valid-empty snapshot must carry a digest revision, got %q", snap.revision)
	}
	if snap.revision == newEmptyAdblockExceptionSnapshot().revision {
		t.Fatal("valid-empty revision must differ from the disabled empty revision")
	}
	if _, ok := snap.match("anything.example.com", &domaintrie.Rule{Domain: "anything.example.com"}); ok {
		t.Fatal("empty snapshot must never match")
	}
}

// Correction 3: digest source IDs canonicalize to lowercase; reserved labels
// match exactly and are never case-folded.
func TestExceptionSourceIDCanonicalization(t *testing.T) {
	lower := canonicalSourceID("https://a.test/hosts")
	upper := strings.ToUpper(lower)
	mkEntry := func(sourceID string) string {
		return exceptionEntry("fp-s", "s.example.com", "exact", "s.example.com", sourceID, "suffix", "", "INC-s")
	}

	// An uppercase digest loads and canonicalizes to lowercase.
	entries, err := validateAdblockExceptions([]byte(exceptionFile(mkEntry(upper))))
	if err != nil {
		t.Fatalf("uppercase digest must load: %v", err)
	}
	if entries[0].SourceID != lower {
		t.Fatalf("digest must canonicalize to lowercase, got %q", entries[0].SourceID)
	}
	// ... and matches a real lowercase Rule.SourceID.
	snap := buildAdblockExceptionSnapshot(entries)
	rule := &domaintrie.Rule{Domain: "s.example.com", Scope: domaintrie.RuleScopeSuffix, SourceID: lower, Category: "ads"}
	if id, ok := snap.match("s.example.com", rule); !ok || id != "fp-s" {
		t.Fatalf("canonicalized exception must match the rule, got %q %v", id, ok)
	}

	// Uppercase and lowercase spellings of one selector are duplicates.
	dupCfg := exceptionFile(mkEntry(lower), exceptionEntry("fp-t", "s.example.com", "exact", "s.example.com", upper, "suffix", "", "INC-t"))
	if _, err := validateAdblockExceptions([]byte(dupCfg)); err == nil {
		t.Fatal("case-variant duplicate selector must be rejected")
	}

	// ... and they digest identically.
	revLower := buildAdblockExceptionSnapshot(mustValidateExceptions(t, exceptionFile(mkEntry(lower)))).revision
	revUpper := buildAdblockExceptionSnapshot(mustValidateExceptions(t, exceptionFile(mkEntry(upper)))).revision
	if revLower != revUpper {
		t.Fatal("revision must be identical across digest case variants")
	}

	// Malformed IDs stay rejected.
	for _, bad := range []string{"xyz", "0123456789abcdef0123456789abcde", "0123456789abcdef0123456789abcdef0", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", " LEGACY "} {
		badCfg := exceptionFile(exceptionEntry("fp-b", "s.example.com", "exact", "s.example.com", bad, "suffix", "", "INC-b"))
		if _, err := validateAdblockExceptions([]byte(badCfg)); err == nil {
			t.Fatalf("source_id %q must be rejected", bad)
		}
	}

	// Reserved labels work exactly; case variants do not.
	for _, reserved := range []string{domaintrie.LegacyRuleSourceID, domaintrie.CacheV2LegacySourceID} {
		reservedEntries, err := validateAdblockExceptions([]byte(exceptionFile(mkEntry(reserved))))
		if err != nil {
			t.Fatalf("reserved %q must load: %v", reserved, err)
		}
		if reservedEntries[0].SourceID != reserved {
			t.Fatalf("reserved %q must be kept exactly, got %q", reserved, reservedEntries[0].SourceID)
		}
	}
	upperReserved := exceptionFile(exceptionEntry("fp-u", "s.example.com", "exact", "s.example.com", "LEGACY", "suffix", "", "INC-u"))
	if _, err := validateAdblockExceptions([]byte(upperReserved)); err == nil {
		t.Fatal("LEGACY must not case-fold to the reserved label")
	}
}

func mustValidateExceptions(t *testing.T, body string) []adblockException {
	t.Helper()
	entries, err := validateAdblockExceptions([]byte(body))
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	return entries
}

// newWorstBucketSnapshot builds a validator-valid config of exactly 1024
// exceptions in one exact-scope queried-domain bucket, then validates it
// through the production validator. Every entry satisfies the intersection
// invariant (exact query + exact rule on the same domain, or exact query +
// suffix rule on the domain or its parent), IDs and selectors are unique, and
// the rules below genuinely correspond to the validated selectors.
func newWorstBucketSnapshot() (*adblockExceptionSnapshot, domaintrie.Rule, domaintrie.Rule, domaintrie.Rule) {
	const domain = "victim.example.com"
	const parent = "example.com"
	hitSource := strings.Repeat("a", 32)
	wildSource := strings.Repeat("b", 32)
	categories := []string{"ads", "tracking", "telemetry", "nuisance"}
	raw := make([]string, 0, 1024)
	for i := 0; i < 1022; i++ {
		matched := domain
		matchType := "exact"
		if i%2 == 1 {
			matched = parent
			matchType = "suffix"
		} else if i%4 == 2 {
			matchType = "suffix"
		}
		raw = append(raw, exceptionEntry(
			fmt.Sprintf("fp-worst-%d", i), domain, "exact", matched,
			fmt.Sprintf("%032x", i+1), matchType, categories[i%len(categories)],
			fmt.Sprintf("w%d", i),
		))
	}
	// Wildcard fallback entry.
	raw = append(raw, exceptionEntry(
		"fp-worst-wild", domain, "exact", parent, wildSource, "suffix", "", "w-wild",
	))
	// Last-entry specific hit.
	raw = append(raw, exceptionEntry(
		"fp-worst-hit", domain, "exact", domain, hitSource, "exact", "telemetry", "w-hit",
	))
	entries, err := validateAdblockExceptions([]byte(exceptionFile(raw...)))
	if err != nil {
		panic(fmt.Sprintf("worst-bucket fixture must pass production validation: %v", err))
	}
	if len(entries) != 1024 {
		panic(fmt.Sprintf("worst bucket must hold 1024 entries, got %d", len(entries)))
	}
	snap := buildAdblockExceptionSnapshot(entries)
	if snap.count != 1024 {
		panic(fmt.Sprintf("worst bucket snapshot must count 1024, got %d", snap.count))
	}
	bucket, ok := snap.exact[domain]
	if !ok || len(bucket.specific)+len(bucket.wildcard) != 1024 {
		panic("worst bucket must index all 1024 selectors under one outer key")
	}
	hit := domaintrie.Rule{Domain: domain, Scope: domaintrie.RuleScopeExact, SourceID: hitSource, Category: "telemetry", Action: domaintrie.RuleActionBlock}
	miss := domaintrie.Rule{Domain: domain, Scope: domaintrie.RuleScopeExact, SourceID: strings.Repeat("f", 32), Category: "ads", Action: domaintrie.RuleActionBlock}
	wild := domaintrie.Rule{Domain: parent, Scope: domaintrie.RuleScopeSuffix, SourceID: wildSource, Category: "ads", Action: domaintrie.RuleActionBlock}
	return snap, hit, miss, wild
}

// Correction 2: worst-bucket lookups allocate nothing measurable.
func TestWorstBucketLookupNoAllocs(t *testing.T) {
	snap, hit, miss, wild := newWorstBucketSnapshot()
	queries := map[string]struct {
		query string
		rule  domaintrie.Rule
		want  bool
	}{
		"specific hit":      {"victim.example.com", hit, true},
		"wildcard fallback": {"victim.example.com", wild, true},
		"provenance miss":   {"victim.example.com", miss, false},
	}
	for name, tc := range queries {
		rule := tc.rule
		if allocs := testing.AllocsPerRun(200, func() {
			_, _ = snap.match(tc.query, &rule)
		}); allocs != 0 {
			t.Fatalf("%s allocated %v times", name, allocs)
		}
		got, ok := snap.match(tc.query, &rule)
		if ok != tc.want {
			t.Fatalf("%s: got %v want %v", name, ok, tc.want)
		}
		if tc.want && got == "" {
			t.Fatalf("%s: expected an exception id", name)
		}
	}
}

// 16b. ASCII matcher lookups allocate nothing measurable.
func TestAdblockExceptionLookupNoAllocs(t *testing.T) {
	rule := domaintrie.Rule{
		Domain:   "bench-shared.example",
		Scope:    domaintrie.RuleScopeSuffix,
		SourceID: "0123456789abcdef0123456789abcdef",
		Category: "ads",
		Action:   domaintrie.RuleActionBlock,
	}
	snap := buildAdblockExceptionSnapshot([]adblockException{
		{ID: "e1", Domain: "host1.bench-shared.example", Scope: domaintrie.RuleScopeExact, MatchedRule: rule.Domain, SourceID: rule.SourceID, MatchType: rule.Scope},
		{ID: "s1", Domain: "zone1.bench-other.example", Scope: domaintrie.RuleScopeSuffix, MatchedRule: rule.Domain, SourceID: rule.SourceID, MatchType: rule.Scope},
	})
	queries := map[string]string{
		"exact":  "host1.bench-shared.example",
		"suffix": "deep.zone1.bench-other.example",
		"miss":   "unrelated-miss.example.org",
	}
	for name, query := range queries {
		if allocs := testing.AllocsPerRun(200, func() {
			_, _ = snap.match(query, &rule)
		}); allocs != 0 {
			t.Fatalf("%s lookup allocated %v times", name, allocs)
		}
	}
}

// 15. A configured-but-unmatched exception keeps the fast path local-only.
func TestUnmatchedExceptionKeepsFastPathLocal(t *testing.T) {
	srcA := canonicalSourceID("https://a.test/hosts")
	domain := "fast.example.com"
	rules := []domaintrie.Rule{
		{Domain: domain, Scope: domaintrie.RuleScopeSuffix, SourceID: srcA, Category: "ads", Action: domaintrie.RuleActionBlock},
	}
	cfg := exceptionFile(exceptionEntry("fp-far", "elsewhere.example.com", "exact", "elsewhere.example.com", srcA, "suffix", "", "INC-far"))
	service := newAdblockExceptionService(t, Options{}, rules, cfg)

	fake := &panickingBrandStore{calls: &atomic.Int64{}}
	service.analyzerMu.Lock()
	service.analyzer = analysis.NewAnalyzerWithBrandStore(config.DefaultAnalysisConfig(), fake)
	service.analyzerMu.Unlock()

	pol := service.Policy(context.Background(), domain, ClientInfo{})
	if pol.Policy != "block" || pol.Decision == nil || pol.Decision.Reason != "adblock_match" {
		t.Fatalf("expected fast-path block, got %s %+v", pol.Policy, pol.Decision)
	}
	if got := fake.calls.Load(); got != 0 {
		t.Fatalf("fast path must not touch the brand store, got %d calls", got)
	}
}
