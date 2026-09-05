package risk

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
	"safe-zone/internal/domaintrie"
	"safe-zone/internal/store"
)

// newShadowTestService builds a separated-semantics service with shadow
// observation enabled, the given typed rules and an optional exception
// config. The global match mode stays suffix unless the caller sets
// SAFE_ZONE_ADBLOCK_MATCH_MODE beforehand.
func newShadowTestService(t *testing.T, rules []domaintrie.Rule, exceptionsJSON string) *Service {
	t.Helper()
	return newAdblockExceptionService(t, Options{AdblockShadowExactEnabled: true}, rules, exceptionsJSON)
}

func shadowRule(domain string, scope domaintrie.RuleScope, origin domaintrie.ScopeOrigin) domaintrie.Rule {
	return domaintrie.Rule{
		Domain:   domain,
		Scope:    scope,
		SourceID: "0123456789abcdef0123456789abcdef",
		Category: "ads",
		Action:   domaintrie.RuleActionBlock,
		Origin:   origin,
	}
}

func mustShadowStatus(t *testing.T, svc *Service) AdblockShadowExactStatus {
	t.Helper()
	return svc.AdblockShadowExactStatus()
}

// Origin producers: resolve assigns GlobalDefault unless an explicit valid
// scope pins the source.
func TestShadowResolveOriginVariants(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")
	storeDB, err := store.New(filepath.Join(tempDir, "pol.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storeDB.Close() })
	svc := &Service{adblockDataRoot: tempDir, store: storeDB}
	svc.adblockMatchMode.Store(string(adblockMatchModeSuffix))
	svc.adblockSourcePolicies = parseAdblockSourcePolicies(`{
		"https://exact.test/hosts": {"category":"ads","scope":"exact"},
		"https://suffix.test/hosts": {"category":"ads","scope":"suffix"},
		"https://catonly.test/hosts": {"category":"tracking"},
		"https://bad.test/hosts": {"scope":"glob"}
	}`)

	if _, _, origin := svc.resolveAdblockSourcePolicy("https://missing.test/hosts"); origin != domaintrie.OriginGlobalDefault {
		t.Fatalf("unconfigured source must be GlobalDefault, got %v", origin)
	}
	if _, _, origin := svc.resolveAdblockSourcePolicy("https://catonly.test/hosts"); origin != domaintrie.OriginGlobalDefault {
		t.Fatalf("category-only policy must stay GlobalDefault, got %v", origin)
	}
	if _, _, origin := svc.resolveAdblockSourcePolicy("https://bad.test/hosts"); origin != domaintrie.OriginGlobalDefault {
		t.Fatalf("invalid scope fallback must stay GlobalDefault, got %v", origin)
	}
	if cat, scope, origin := svc.resolveAdblockSourcePolicy("https://exact.test/hosts"); cat != "ads" || scope != domaintrie.RuleScopeExact || origin != domaintrie.OriginSourcePolicyExact {
		t.Fatalf("explicit exact must pin origin, got %s/%s/%v", cat, scope, origin)
	}
	if _, scope, origin := svc.resolveAdblockSourcePolicy("https://suffix.test/hosts"); scope != domaintrie.RuleScopeSuffix || origin != domaintrie.OriginSourcePolicySuffix {
		t.Fatalf("explicit suffix must pin origin, got %s/%v", scope, origin)
	}
}

// Parsing threads the resolved origin; wildcard lines override it.
func TestShadowParseThreadsOrigin(t *testing.T) {
	svc := newParseTestService(t)
	trie := domaintrie.NewTrie()
	body := "0.0.0.0 plain.example.com\n*.wild.example.com\n"
	if err := svc.parseAdblockSource(strings.NewReader(body), trie, "src", "ads", domaintrie.RuleScopeSuffix, domaintrie.OriginSourcePolicySuffix); err != nil {
		t.Fatal(err)
	}
	plain, ok := trie.MatchRule("plain.example.com")
	if !ok || plain.Origin != domaintrie.OriginSourcePolicySuffix {
		t.Fatalf("parsed origin must be preserved, got %+v ok=%v", plain, ok)
	}
	wild, ok := trie.MatchRule("sub.wild.example.com")
	if !ok || wild.Origin != domaintrie.OriginWildcard || wild.Scope != domaintrie.RuleScopeSuffix {
		t.Fatalf("wildcard must override origin and scope, got %+v ok=%v", wild, ok)
	}
}

// First-wins keeps the earlier source's origin too.
func TestShadowMergePreservesOrigin(t *testing.T) {
	svc := newParseTestService(t)
	trie := domaintrie.NewTrie()
	body := "0.0.0.0 dup.example.com\n"
	if err := svc.parseAdblockSource(strings.NewReader(body), trie, "a", "ads", domaintrie.RuleScopeSuffix, domaintrie.OriginGlobalDefault); err != nil {
		t.Fatal(err)
	}
	if err := svc.parseAdblockSource(strings.NewReader(body), trie, "b", "tracking", domaintrie.RuleScopeSuffix, domaintrie.OriginSourcePolicySuffix); err != nil {
		t.Fatal(err)
	}
	rule, ok := trie.MatchRule("dup.example.com")
	if !ok || rule.SourceID != "a" || rule.Origin != domaintrie.OriginGlobalDefault {
		t.Fatalf("first source must win including origin, got %+v ok=%v", rule, ok)
	}
}

// Per-source raw cache reparse carries the current policy origin.
func TestShadowPerSourceCacheReparseOrigin(t *testing.T) {
	svc := newParseTestService(t)
	source := "https://example.com/reparse-origin"
	srcID := canonicalSourceID(source)
	dest := domaintrie.NewTrie()
	if err := svc.saveAdblockSourceCache(source,
		strings.NewReader("0.0.0.0 reparse.example.com\n"),
		dest, srcID, "ads", domaintrie.RuleScopeExact, domaintrie.OriginSourcePolicyExact); err != nil {
		t.Fatal(err)
	}
	loaded := domaintrie.NewTrie()
	if !svc.loadAdblockSourceCache(source, loaded, srcID, "ads", domaintrie.RuleScopeExact, domaintrie.OriginSourcePolicyExact) {
		t.Fatal("expected per-source cache to reload")
	}
	rule, ok := loaded.MatchRule("reparse.example.com")
	if !ok || rule.Origin != domaintrie.OriginSourcePolicyExact || rule.Scope != domaintrie.RuleScopeExact {
		t.Fatalf("reparse must carry the policy origin, got %+v ok=%v", rule, ok)
	}
}

// Legacy v1 global cache loads as OriginLegacyCache.
func TestShadowLegacyCacheOrigin(t *testing.T) {
	svc := newParseTestService(t)
	svc.saveAdblockCacheRaw("legacy-origin.example.com\n")
	loaded := domaintrie.NewTrie()
	if !svc.loadAdblockCache(loaded) {
		t.Fatal("expected legacy cache to load")
	}
	rule, ok := loaded.MatchRule("sub.legacy-origin.example.com")
	if !ok || rule.Origin != domaintrie.OriginLegacyCache {
		t.Fatalf("legacy cache must mark OriginLegacyCache, got %+v ok=%v", rule, ok)
	}
}

// Global v2 round-trip keeps enforcement identical but resets origin to
// unknown: the format persists no origin.
func TestShadowGlobalCacheRoundTripUnknown(t *testing.T) {
	svc := newParseTestService(t)
	built := domaintrie.NewTrie()
	built.AddRule(domaintrie.Rule{Domain: "rt.example.com", Scope: domaintrie.RuleScopeSuffix, SourceID: "src", Category: "ads", Action: domaintrie.RuleActionBlock, Origin: domaintrie.OriginGlobalDefault})
	svc.saveAdblockCache(built)
	loaded := domaintrie.NewTrie()
	if !svc.loadAdblockCache(loaded) {
		t.Fatal("expected cache reload")
	}
	rule, ok := loaded.MatchRule("sub.rt.example.com")
	if !ok {
		t.Fatal("enforcement must survive the round-trip")
	}
	if rule.Origin != domaintrie.OriginCacheV2Unknown {
		t.Fatalf("round-trip must reset origin to unknown, got %+v", rule)
	}
}

// Golden v2 bytes: header plus exactly five tab-separated fields per record,
// in deterministic reverse-label order. Origin is never serialized.
func TestShadowCacheV2GoldenBytes(t *testing.T) {
	svc := newParseTestService(t)
	built := domaintrie.NewTrie()
	built.AddRule(domaintrie.Rule{Domain: "b.example.com", Scope: domaintrie.RuleScopeExact, SourceID: "src-a", Category: "ads", Action: domaintrie.RuleActionBlock, Origin: domaintrie.OriginSourcePolicyExact})
	built.AddRule(domaintrie.Rule{Domain: "a.example.com", Scope: domaintrie.RuleScopeSuffix, SourceID: "src-b", Category: "tracking", Action: domaintrie.RuleActionBlock, Origin: domaintrie.OriginWildcard})
	svc.saveAdblockCache(built)

	raw, err := os.ReadFile(svc.adblockCachePath())
	if err != nil {
		t.Fatal(err)
	}
	want := domaintrie.CacheV2Header + "\n" +
		"a.example.com\tsuffix\ttracking\tblock\tsrc-b\n" +
		"b.example.com\texact\tads\tblock\tsrc-a\n"
	if string(raw) != want {
		t.Fatalf("v2 bytes changed:\n got %q\nwant %q", raw, want)
	}
	// The golden output parses under the strict five-field contract.
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")[1:] {
		if _, ok := domaintrie.ParseCacheV2Line(line); !ok {
			t.Fatalf("golden record must parse: %q", line)
		}
	}
}

// An old five-field fixture loads with identical enforcement; a six-field
// record is rejected exactly like before.
func TestShadowOldFixtureAndSixFieldRejected(t *testing.T) {
	svc := newParseTestService(t)
	svc.saveAdblockCacheRaw(domaintrie.CacheV2Header + "\n" +
		"old.example.com\tsuffix\tads\tblock\tsrc-old\n")
	loaded := domaintrie.NewTrie()
	if !svc.loadAdblockCache(loaded) {
		t.Fatal("expected old fixture to load")
	}
	rule, ok := loaded.MatchRule("sub.old.example.com")
	if !ok || rule.Domain != "old.example.com" || rule.Scope != domaintrie.RuleScopeSuffix {
		t.Fatalf("old fixture enforcement changed: %+v ok=%v", rule, ok)
	}
	if rule.Origin != domaintrie.OriginCacheV2Unknown {
		t.Fatalf("old fixture must load as unknown origin, got %+v", rule)
	}
	if _, ok := domaintrie.ParseCacheV2Line("old.example.com\tsuffix\tads\tblock\tsrc-old\textra"); ok {
		t.Fatal("six-field record must stay rejected")
	}
}

// Startup-only flag contract: Options OR env enables the feature, and later
// env changes never move a constructed service.
func TestShadowFlagConfigContract(t *testing.T) {
	build := func(t *testing.T, envVal string, option bool) *Service {
		t.Helper()
		t.Setenv("SAFE_ZONE_ADBLOCK_SHADOW_EXACT_ENABLED", envVal)
		svc := NewService(Options{
			AnalysisConfig:            config.DefaultAnalysisConfig(),
			AdblockShadowExactEnabled: option,
			DisableAdblockSync:        true,
		})
		t.Cleanup(func() { _ = svc.Close() })
		return svc
	}

	if got := build(t, "false", false).AdblockShadowExactStatus(); got.Enabled || got.Active {
		t.Fatalf("env=false + option=false must be disabled, got %+v", got)
	}
	if got := build(t, "true", false).AdblockShadowExactStatus(); !got.Enabled {
		t.Fatalf("env=true + option=false must be enabled, got %+v", got)
	}
	if got := build(t, "false", true).AdblockShadowExactStatus(); !got.Enabled {
		t.Fatalf("env=false + option=true must be enabled, got %+v", got)
	}

	// Startup-only: flipping env after construction changes nothing.
	svc := build(t, "false", false)
	t.Setenv("SAFE_ZONE_ADBLOCK_SHADOW_EXACT_ENABLED", "true")
	if got := svc.AdblockShadowExactStatus(); got.Enabled || got.Active {
		t.Fatalf("post-construction env change must not enable, got %+v", got)
	}
}

// Disabled shadow records nothing and leaves Policy bytes identical.
func TestShadowDisabledNoObservation(t *testing.T) {
	rules := []domaintrie.Rule{
		shadowRule("sh.example.com", domaintrie.RuleScopeSuffix, domaintrie.OriginGlobalDefault),
	}
	off := newAdblockExceptionService(t, Options{}, rules, "")
	on := newShadowTestService(t, rules, "")

	for _, q := range []string{"sh.example.com", "sub.sh.example.com"} {
		offPol := off.Policy(context.Background(), q, ClientInfo{})
		onPol := on.Policy(context.Background(), q, ClientInfo{})
		offBytes, _ := json.Marshal(offPol)
		onBytes, _ := json.Marshal(onPol)
		if string(offBytes) != string(onBytes) {
			t.Fatalf("shadow must not change Policy bytes for %s:\noff=%s\non=%s", q, offBytes, onBytes)
		}
	}
	status := mustShadowStatus(t, off)
	if status.Enabled || status.Active || status.Observations != 0 {
		t.Fatalf("disabled shadow must stay silent: %+v", status)
	}
	if got := mustShadowStatus(t, on); got.Observations != 2 {
		t.Fatalf("enabled shadow must observe both hits, got %+v", got)
	}
}

// Active only when enabled + separated + global suffix.
func TestShadowActiveConditions(t *testing.T) {
	t.Setenv(envAdblockMatchMode, "suffix")
	rules := []domaintrie.Rule{
		shadowRule("cond.example.com", domaintrie.RuleScopeSuffix, domaintrie.OriginGlobalDefault),
	}
	active := newShadowTestService(t, rules, "")
	if got := mustShadowStatus(t, active); !got.Enabled || !got.Active {
		t.Fatalf("expected enabled+active, got %+v", got)
	}

	t.Run("global exact inactive", func(t *testing.T) {
		t.Setenv(envAdblockMatchMode, "exact")
		svc := newShadowTestService(t, rules, "")
		if got := mustShadowStatus(t, svc); !got.Enabled || got.Active {
			t.Fatalf("expected enabled+inactive, got %+v", got)
		}
		pol := svc.Policy(context.Background(), "sub.cond.example.com", ClientInfo{})
		if pol.Decision == nil {
			t.Fatal("expected normal enforcement without shadow")
		}
		if got := mustShadowStatus(t, svc); got.Observations != 0 {
			t.Fatalf("inactive shadow must not observe, got %+v", got)
		}
	})

	t.Run("legacy inactive", func(t *testing.T) {
		tempDir := t.TempDir()
		t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")
		t.Setenv(envAdblockExceptionsFile, "")
		dbPath := filepath.Join(tempDir, "test.db")
		storeDB, err := store.New(dbPath, 30)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = storeDB.Close() })
		if err := storeDB.SetSystemConfig(context.Background(), "adblock_enabled", "true"); err != nil {
			t.Fatal(err)
		}
		svc := NewService(Options{
			AnalysisConfig:            config.DefaultAnalysisConfig(),
			RedisTimeout:              10 * time.Millisecond,
			TTLAllowed:                time.Hour,
			TTLSuspicious:             time.Hour,
			TTLBlocked:                time.Hour,
			RecentLimit:               10,
			Store:                     storeDB,
			AdblockFileRoot:           tempDir,
			PolicySemantics:           PolicySemanticsLegacy,
			AdblockShadowExactEnabled: true,
			DisableAdblockSync:        true,
		})
		t.Cleanup(func() { _ = svc.Close() })
		trie := domaintrie.NewTrie()
		for _, r := range rules {
			trie.AddRule(r)
		}
		svc.AdblockTrieOverride(trie)

		if got := mustShadowStatus(t, svc); !got.Enabled || got.Active {
			t.Fatalf("expected enabled+inactive under legacy, got %+v", got)
		}
		pol := svc.Policy(context.Background(), "sub.cond.example.com", ClientInfo{})
		if pol.Policy != "block" || pol.Decision != nil {
			t.Fatalf("legacy must keep fused block without decision: %+v", pol)
		}
		if got := mustShadowStatus(t, svc); got.Observations != 0 || got.UnavailableOriginUnknown != 0 {
			t.Fatalf("legacy must not observe at all, got %+v", got)
		}
	})
}

// One primary outcome per classification, exactly as locked.
func TestShadowClassifications(t *testing.T) {
	t.Setenv(envAdblockMatchMode, "suffix")
	cases := map[string]struct {
		rule     domaintrie.Rule
		query    string
		check    func(AdblockShadowExactStatus) uint64
		wantName string
	}{
		"global apex still blocks": {
			rule:     shadowRule("apex-cl.example.com", domaintrie.RuleScopeSuffix, domaintrie.OriginGlobalDefault),
			query:    "apex-cl.example.com",
			check:    func(s AdblockShadowExactStatus) uint64 { return s.WouldStillBlockContent },
			wantName: "would_still_block_content",
		},
		"global descendant would allow": {
			rule:     shadowRule("base-cl.example.com", domaintrie.RuleScopeSuffix, domaintrie.OriginGlobalDefault),
			query:    "sub.base-cl.example.com",
			check:    func(s AdblockShadowExactStatus) uint64 { return s.WouldAllowContent },
			wantName: "would_allow_content",
		},
		"global exact apex still blocks": {
			rule:     shadowRule("exact-cl.example.com", domaintrie.RuleScopeExact, domaintrie.OriginGlobalDefault),
			query:    "exact-cl.example.com",
			check:    func(s AdblockShadowExactStatus) uint64 { return s.WouldStillBlockContent },
			wantName: "would_still_block_content",
		},
		"explicit exact preserved": {
			rule:     shadowRule("pex-cl.example.com", domaintrie.RuleScopeExact, domaintrie.OriginSourcePolicyExact),
			query:    "pex-cl.example.com",
			check:    func(s AdblockShadowExactStatus) uint64 { return s.ExplicitScopePreservedBlock },
			wantName: "explicit_scope_preserved_block",
		},
		"explicit suffix preserved": {
			rule:     shadowRule("psx-cl.example.com", domaintrie.RuleScopeSuffix, domaintrie.OriginSourcePolicySuffix),
			query:    "sub.psx-cl.example.com",
			check:    func(s AdblockShadowExactStatus) uint64 { return s.ExplicitScopePreservedBlock },
			wantName: "explicit_scope_preserved_block",
		},
		"wildcard preserved": {
			rule:     domaintrie.Rule{Domain: "wild-cl.example.com", Scope: domaintrie.RuleScopeSuffix, SourceID: "0123456789abcdef0123456789abcdef", Category: "ads", Action: domaintrie.RuleActionBlock, Origin: domaintrie.OriginWildcard},
			query:    "sub.wild-cl.example.com",
			check:    func(s AdblockShadowExactStatus) uint64 { return s.ExplicitScopePreservedBlock },
			wantName: "explicit_scope_preserved_block",
		},
		"unspecified unavailable": {
			rule:     shadowRule("uns-cl.example.com", domaintrie.RuleScopeSuffix, domaintrie.OriginUnspecified),
			query:    "sub.uns-cl.example.com",
			check:    func(s AdblockShadowExactStatus) uint64 { return s.UnavailableOriginUnknown },
			wantName: "unavailable_origin_unknown",
		},
		"legacy add unavailable": {
			rule:     shadowRule("leg-cl.example.com", domaintrie.RuleScopeSuffix, domaintrie.OriginLegacyAdd),
			query:    "leg-cl.example.com",
			check:    func(s AdblockShadowExactStatus) uint64 { return s.UnavailableOriginUnknown },
			wantName: "unavailable_origin_unknown",
		},
		"cache v2 unknown unavailable": {
			rule:     shadowRule("v2u-cl.example.com", domaintrie.RuleScopeSuffix, domaintrie.OriginCacheV2Unknown),
			query:    "sub.v2u-cl.example.com",
			check:    func(s AdblockShadowExactStatus) uint64 { return s.UnavailableOriginUnknown },
			wantName: "unavailable_origin_unknown",
		},
		"legacy cache unavailable": {
			rule:     shadowRule("lc-cl.example.com", domaintrie.RuleScopeSuffix, domaintrie.OriginLegacyCache),
			query:    "lc-cl.example.com",
			check:    func(s AdblockShadowExactStatus) uint64 { return s.UnavailableOriginUnknown },
			wantName: "unavailable_origin_unknown",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			svc := newShadowTestService(t, []domaintrie.Rule{tc.rule}, "")
			_ = svc.Policy(context.Background(), tc.query, ClientInfo{})
			status := mustShadowStatus(t, svc)
			if status.Observations != 1 {
				t.Fatalf("exactly one primary outcome required, got %+v", status)
			}
			if got := tc.check(status); got != 1 {
				t.Fatalf("expected %s=1, got %+v", tc.wantName, status)
			}
		})
	}
}

// A subdomain of an exact rule is not a hit at all: no observation, and no
// synthetic descendant case is manufactured for exact rules.
func TestShadowExactRuleDescendantNoObservation(t *testing.T) {
	t.Setenv(envAdblockMatchMode, "suffix")
	svc := newShadowTestService(t, []domaintrie.Rule{
		shadowRule("only.example.com", domaintrie.RuleScopeExact, domaintrie.OriginGlobalDefault),
	}, "")
	pol := svc.Policy(context.Background(), "sub.only.example.com", ClientInfo{})
	if pol.Decision != nil {
		t.Fatalf("no adblock hit expected, got %+v", pol.Decision)
	}
	if got := mustShadowStatus(t, svc); got.Observations != 0 {
		t.Fatalf("non-hit must not observe, got %+v", got)
	}
}

// Override and whitelist return before the trie: no observation.
func TestShadowOverrideWhitelistNoObservation(t *testing.T) {
	t.Setenv(envAdblockMatchMode, "suffix")
	svc := newShadowTestService(t, []domaintrie.Rule{
		shadowRule("gated.example.com", domaintrie.RuleScopeSuffix, domaintrie.OriginGlobalDefault),
	}, "")

	if err := svc.UpsertOverride("gated.example.com", "block", "admin"); err != nil {
		t.Fatal(err)
	}
	if pol := svc.Policy(context.Background(), "gated.example.com", ClientInfo{}); pol.Policy != "block" {
		t.Fatalf("expected admin block, got %s", pol.Policy)
	}
	if err := svc.DeleteOverride("gated.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.UpdateWhitelist(context.Background(), []string{"gated.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.whitelist.LoadFromDB(); err != nil {
		t.Fatal(err)
	}
	if pol := svc.Policy(context.Background(), "gated.example.com", ClientInfo{}); pol.Policy != "allow" {
		t.Fatalf("expected whitelist allow, got %s", pol.Policy)
	}
	if got := mustShadowStatus(t, svc); got.Observations != 0 {
		t.Fatalf("pre-trie returns must not observe, got %+v", got)
	}
}

// Exception overlap rides along without double-counting the primary outcome.
func TestShadowExceptionOverlap(t *testing.T) {
	t.Setenv(envAdblockMatchMode, "suffix")
	srcA := canonicalSourceID("https://a.test/hosts")
	domain := "overlap.example.com"
	rules := []domaintrie.Rule{
		{Domain: domain, Scope: domaintrie.RuleScopeSuffix, SourceID: srcA, Category: "ads", Action: domaintrie.RuleActionBlock, Origin: domaintrie.OriginGlobalDefault},
	}
	cfg := exceptionFile(exceptionEntry("fp-overlap", domain, "exact", domain, srcA, "suffix", "", "INC-overlap"))
	svc := newAdblockExceptionService(t, Options{AdblockShadowExactEnabled: true}, rules, cfg)

	pol := svc.Policy(context.Background(), domain, ClientInfo{})
	if pol.Decision == nil || pol.Decision.Reason != "adblock_exception" {
		t.Fatalf("expected exception decision, got %+v", pol.Decision)
	}
	status := mustShadowStatus(t, svc)
	if status.WouldStillBlockContent != 1 || status.Observations != 1 {
		t.Fatalf("exactly one primary outcome required, got %+v", status)
	}
	if status.ExceptionOverlap != 1 {
		t.Fatalf("overlap counter required, got %+v", status)
	}
}

// Exception path still runs the full pipeline; malicious still blocks.
func TestShadowExceptionMaliciousStillBlocks(t *testing.T) {
	t.Setenv(envAdblockMatchMode, "suffix")
	srcA := canonicalSourceID("https://a.test/hosts")
	domain := "secure-login-verify-account.example.com"
	rules := []domaintrie.Rule{
		{Domain: domain, Scope: domaintrie.RuleScopeSuffix, SourceID: srcA, Category: "tracking", Action: domaintrie.RuleActionBlock, Origin: domaintrie.OriginGlobalDefault},
	}
	cfg := exceptionFile(exceptionEntry("fp-mal", domain, "exact", domain, srcA, "suffix", "", "INC-mal"))
	svc := newAdblockExceptionService(t, Options{AdblockShadowExactEnabled: true}, rules, cfg)

	pol := svc.Policy(context.Background(), domain, ClientInfo{})
	if pol.Policy != "block" || pol.Result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("security block must win: %+v", pol)
	}
	if pol.Decision == nil || pol.Decision.Reason != "adblock_exception" {
		t.Fatalf("expected exception decision, got %+v", pol.Decision)
	}
	status := mustShadowStatus(t, svc)
	if status.Observations != 1 || status.ExceptionOverlap != 1 {
		t.Fatalf("expected observed overlap, got %+v", status)
	}
}

// Non-exception hits keep the legacy fast-path decision shape.
func TestShadowFastPathUnchanged(t *testing.T) {
	t.Setenv(envAdblockMatchMode, "suffix")
	svc := newShadowTestService(t, []domaintrie.Rule{
		shadowRule("fast-sh.example.com", domaintrie.RuleScopeSuffix, domaintrie.OriginGlobalDefault),
	}, "")
	pol := svc.Policy(context.Background(), "sub.fast-sh.example.com", ClientInfo{})
	if pol.Policy != "block" || pol.Decision == nil || pol.Decision.Reason != "adblock_match" {
		t.Fatalf("expected fast-path block, got %s %+v", pol.Policy, pol.Decision)
	}
	if got := mustShadowStatus(t, svc); got.WouldAllowContent != 1 {
		t.Fatalf("hit must still be observed, got %+v", got)
	}
}

// Concurrent requests, status reads and reloads stay race-free.
func TestShadowConcurrentRaceFree(t *testing.T) {
	t.Setenv(envAdblockMatchMode, "suffix")
	svc := newShadowTestService(t, []domaintrie.Rule{
		shadowRule("race-sh.example.com", domaintrie.RuleScopeSuffix, domaintrie.OriginGlobalDefault),
	}, "")
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				_ = svc.Policy(context.Background(), "sub.race-sh.example.com", ClientInfo{})
				_ = svc.AdblockStatus()
			}
		}()
	}
	wg.Wait()
	status := mustShadowStatus(t, svc)
	if status.Observations != 200 {
		t.Fatalf("expected 200 observations, got %+v", status)
	}
	if status.Observations != status.WouldAllowContent {
		t.Fatalf("all hits are descendant global-default: %+v", status)
	}
}

// Status carries no user-data cardinality and the total invariant holds.
func TestShadowStatusNoLeak(t *testing.T) {
	t.Setenv(envAdblockMatchMode, "suffix")
	srcA := canonicalSourceID("https://a.test/hosts")
	domain := "leakcheck.example.com"
	rules := []domaintrie.Rule{
		{Domain: domain, Scope: domaintrie.RuleScopeSuffix, SourceID: srcA, Category: "ads", Action: domaintrie.RuleActionBlock, Origin: domaintrie.OriginGlobalDefault},
	}
	cfg := exceptionFile(exceptionEntry("fp-leak-unique", domain, "exact", domain, srcA, "suffix", "", "INC-leak-unique-reason"))
	svc := newAdblockExceptionService(t, Options{AdblockShadowExactEnabled: true}, rules, cfg)

	_ = svc.Policy(context.Background(), domain, ClientInfo{})
	status := svc.AdblockStatus()
	raw, err := json.Marshal(status.ShadowExact)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{domain, srcA, "fp-leak-unique", "INC-leak-unique-reason"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("status must not leak %q: %s", leak, raw)
		}
	}
	if status.ShadowExact.Observations != status.ShadowExact.WouldStillBlockContent+
		status.ShadowExact.WouldAllowContent+
		status.ShadowExact.ExplicitScopePreservedBlock+
		status.ShadowExact.UnavailableOriginUnknown {
		t.Fatalf("observations must equal the primary sum: %+v", status.ShadowExact)
	}
	if status.ShadowExact.TargetScope != "exact" || !status.ShadowExact.Enabled || !status.ShadowExact.Active {
		t.Fatalf("unexpected shadow status shape: %+v", status.ShadowExact)
	}
}
