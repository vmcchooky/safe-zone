package risk

import (
	"context"
	"fmt"
	"testing"
	"time"

	"safe-zone/internal/config"
	"safe-zone/internal/domaintrie"
	"safe-zone/internal/store"
)

func BenchmarkAnalyzeNoRedis(b *testing.B) {
	service := NewService(Options{
		RedisTimeout:   10 * time.Millisecond,
		TTLAllowed:     time.Hour,
		TTLSuspicious:  time.Hour,
		TTLBlocked:     time.Hour,
		AnalysisConfig: config.DefaultAnalysisConfig(),
	})
	defer service.Close()

	ctx := context.Background()
	client := ClientInfo{}
	b.ReportAllocs()
	for b.Loop() {
		_ = service.Analyze(ctx, "secure-login-wallet-example.com", client)
	}
}

// newExceptionBenchSnapshot builds a snapshot with n exact and n suffix
// entries over synthetic domains, all bound to one shared rule shape.
func newExceptionBenchSnapshot(b *testing.B, n int) (*adblockExceptionSnapshot, domaintrie.Rule) {
	b.Helper()
	rule := domaintrie.Rule{
		Domain:   "bench-shared.example",
		Scope:    domaintrie.RuleScopeSuffix,
		SourceID: "0123456789abcdef0123456789abcdef",
		Category: "ads",
		Action:   domaintrie.RuleActionBlock,
	}
	entries := make([]adblockException, 0, 2*n)
	for i := 0; i < n; i++ {
		domain := fmt.Sprintf("host%d.bench-shared.example", i)
		entries = append(entries, adblockException{
			ID:          fmt.Sprintf("exact-%d", i),
			Domain:      domain,
			Scope:       domaintrie.RuleScopeExact,
			MatchedRule: rule.Domain,
			SourceID:    rule.SourceID,
			MatchType:   rule.Scope,
		})
		suffix := fmt.Sprintf("zone%d.bench-other.example", i)
		entries = append(entries, adblockException{
			ID:          fmt.Sprintf("suffix-%d", i),
			Domain:      suffix,
			Scope:       domaintrie.RuleScopeSuffix,
			MatchedRule: rule.Domain,
			SourceID:    rule.SourceID,
			MatchType:   rule.Scope,
		})
	}
	return buildAdblockExceptionSnapshot(entries), rule
}

func BenchmarkAdblockExceptionMiss(b *testing.B) {
	snap, rule := newExceptionBenchSnapshot(b, 1000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := snap.match("unrelated-miss.example.org", &rule); ok {
			b.Fatal("unexpected match")
		}
	}
}

func BenchmarkAdblockExceptionExactHit(b *testing.B) {
	snap, rule := newExceptionBenchSnapshot(b, 1000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := snap.match("host42.bench-shared.example", &rule); !ok {
			b.Fatal("expected match")
		}
	}
}

func BenchmarkAdblockExceptionSuffixHit(b *testing.B) {
	snap, rule := newExceptionBenchSnapshot(b, 1000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := snap.match("deep.host7.zone7.bench-other.example", &rule); !ok {
			b.Fatal("expected match")
		}
	}
}

// Worst-bucket benchmarks share one 1024-entry exact bucket so the old
// linear scan would have walked ~1024 entries per lookup. The composite-key
// index resolves each bucket with at most two map lookups.
func BenchmarkAdblockExceptionWorstBucketSpecificHit(b *testing.B) {
	snap, hit, _, _ := newWorstBucketSnapshot()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := snap.match("victim.example.com", &hit); !ok {
			b.Fatal("expected match")
		}
	}
}

func BenchmarkAdblockExceptionWorstBucketWildcardFallback(b *testing.B) {
	snap, _, _, wild := newWorstBucketSnapshot()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := snap.match("victim.example.com", &wild); !ok {
			b.Fatal("expected match")
		}
	}
}

func BenchmarkAdblockExceptionWorstBucketProvenanceMiss(b *testing.B) {
	snap, _, miss, _ := newWorstBucketSnapshot()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := snap.match("victim.example.com", &miss); ok {
			b.Fatal("unexpected match")
		}
	}
}

// newMatchDetailBenchTrie builds a trie with exact, suffix, wildcard and
// deep-suffix rules for MatchRuleDetail benchmarks.
func newMatchDetailBenchTrie(b *testing.B) *domaintrie.Trie {
	b.Helper()
	trie := domaintrie.NewTrie()
	trie.AddRule(domaintrie.Rule{Domain: "exact-bench.example.com", Scope: domaintrie.RuleScopeExact, SourceID: "s", Category: "ads", Action: domaintrie.RuleActionBlock, Origin: domaintrie.OriginGlobalDefault})
	trie.AddRule(domaintrie.Rule{Domain: "suffix-bench.example.com", Scope: domaintrie.RuleScopeSuffix, SourceID: "s", Category: "ads", Action: domaintrie.RuleActionBlock, Origin: domaintrie.OriginGlobalDefault})
	trie.AddRule(domaintrie.Rule{Domain: "*.wild-bench.example.com", Scope: domaintrie.RuleScopeSuffix, SourceID: "s", Category: "ads", Action: domaintrie.RuleActionBlock, Origin: domaintrie.OriginGlobalDefault})
	trie.AddRule(domaintrie.Rule{Domain: "deep.a.b.c-bench.example.com", Scope: domaintrie.RuleScopeSuffix, SourceID: "s", Category: "ads", Action: domaintrie.RuleActionBlock, Origin: domaintrie.OriginGlobalDefault})
	return trie
}

func BenchmarkMatchRuleDetailExact(b *testing.B) {
	trie := newMatchDetailBenchTrie(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detail := trie.MatchRuleDetail("exact-bench.example.com")
		if !detail.Matched || detail.Query != detail.Rule.Domain {
			b.Fatal("expected exact apex match")
		}
	}
}

func BenchmarkMatchRuleDetailSuffixApex(b *testing.B) {
	trie := newMatchDetailBenchTrie(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detail := trie.MatchRuleDetail("suffix-bench.example.com")
		if !detail.Matched || detail.Query != detail.Rule.Domain {
			b.Fatal("expected suffix apex match")
		}
	}
}

func BenchmarkMatchRuleDetailSuffixDescendant(b *testing.B) {
	trie := newMatchDetailBenchTrie(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detail := trie.MatchRuleDetail("deep.sub.suffix-bench.example.com")
		if !detail.Matched || detail.Query == detail.Rule.Domain {
			b.Fatal("expected suffix descendant match")
		}
	}
}

func BenchmarkMatchRuleDetailWildcard(b *testing.B) {
	trie := newMatchDetailBenchTrie(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detail := trie.MatchRuleDetail("anything.wild-bench.example.com")
		if !detail.Matched || detail.Rule.Origin != domaintrie.OriginWildcard {
			b.Fatal("expected wildcard match")
		}
	}
}

func BenchmarkMatchRuleDetailMiss(b *testing.B) {
	trie := newMatchDetailBenchTrie(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if detail := trie.MatchRuleDetail("unrelated-miss.example.org"); detail.Matched {
			b.Fatal("unexpected match")
		}
	}
}

// newShadowBenchService builds a service with one global-default suffix rule
// for observe benchmarks. The caller selects the shadow flag.
func newShadowBenchService(b *testing.B, enabled bool) *Service {
	b.Helper()
	tempDir := b.TempDir()
	b.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")
	b.Setenv(envAdblockExceptionsFile, "")
	b.Setenv(envAdblockMatchMode, "suffix")
	b.Setenv("SAFE_ZONE_ADBLOCK_ENABLED", "true")

	storeDB, err := store.New(tempDir+"/bench.db", 30)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = storeDB.Close() })
	service := NewService(Options{
		AnalysisConfig:            config.DefaultAnalysisConfig(),
		RedisTimeout:              10 * time.Millisecond,
		TTLAllowed:                time.Hour,
		TTLSuspicious:             time.Hour,
		TTLBlocked:                time.Hour,
		RecentLimit:               10,
		Store:                     storeDB,
		AdblockFileRoot:           tempDir,
		PolicySemantics:           PolicySemanticsSeparated,
		AdblockShadowExactEnabled: enabled,
		DisableAdblockSync:        true,
	})
	b.Cleanup(func() { _ = service.Close() })

	trie := domaintrie.NewTrie()
	trie.AddRule(domaintrie.Rule{Domain: "bench-shadow.example.com", Scope: domaintrie.RuleScopeSuffix, SourceID: "s", Category: "ads", Action: domaintrie.RuleActionBlock, Origin: domaintrie.OriginGlobalDefault})
	service.AdblockTrieOverride(trie)
	return service
}

func BenchmarkShadowObserveDisabled(b *testing.B) {
	service := newShadowBenchService(b, false)
	detail := service.adblockTrie.Load().MatchRuleDetail("sub.bench-shadow.example.com")
	if !detail.Matched {
		b.Fatal("bench fixture must match")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.observeShadowExact(detail, false)
	}
	if got := service.AdblockShadowExactStatus().Observations; got != 0 {
		b.Fatalf("disabled shadow must not observe, got %d", got)
	}
}

func BenchmarkShadowObserveActive(b *testing.B) {
	service := newShadowBenchService(b, true)
	detail := service.adblockTrie.Load().MatchRuleDetail("sub.bench-shadow.example.com")
	if !detail.Matched {
		b.Fatal("bench fixture must match")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.observeShadowExact(detail, false)
	}
}
