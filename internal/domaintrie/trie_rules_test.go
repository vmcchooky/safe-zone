package domaintrie

import (
	"bytes"
	"strings"
	"testing"
)

func TestMatchRuleExactDoesNotMatchSubdomain(t *testing.T) {
	trie := NewTrie()
	trie.AddRule(Rule{Domain: "ads.example.com", Scope: RuleScopeExact, SourceID: "s1", Category: "ads", Action: RuleActionBlock})

	if _, ok := trie.MatchRule("ads.example.com"); !ok {
		t.Fatal("exact rule must match its own domain")
	}
	if _, ok := trie.MatchRule("sub.ads.example.com"); ok {
		t.Fatal("exact rule must not match a subdomain")
	}
	if trie.Match("sub.ads.example.com") {
		t.Fatal("Match compatibility must not report a subdomain for an exact rule")
	}
}

func TestMatchRuleSuffixMatchesDomainAndSubdomain(t *testing.T) {
	trie := NewTrie()
	trie.AddRule(Rule{Domain: "ads.example.com", Scope: RuleScopeSuffix, SourceID: "s1", Category: "ads", Action: RuleActionBlock})

	rule, ok := trie.MatchRule("ads.example.com")
	if !ok || rule.Domain != "ads.example.com" || rule.Scope != RuleScopeSuffix {
		t.Fatalf("suffix rule must match its own domain, got %+v ok=%v", rule, ok)
	}
	rule, ok = trie.MatchRule("deep.sub.ads.example.com")
	if !ok || rule.Domain != "ads.example.com" || rule.Scope != RuleScopeSuffix {
		t.Fatalf("suffix rule must match subdomains, got %+v ok=%v", rule, ok)
	}
}

func TestMatchRuleExactBeatsSuffixOnSameDomain(t *testing.T) {
	trie := NewTrie()
	trie.AddRule(Rule{Domain: "example.com", Scope: RuleScopeSuffix, SourceID: "b", Category: "nuisance", Action: RuleActionBlock})
	trie.AddRule(Rule{Domain: "sub.example.com", Scope: RuleScopeExact, SourceID: "a", Category: "ads", Action: RuleActionBlock})

	rule, ok := trie.MatchRule("sub.example.com")
	if !ok || rule.Scope != RuleScopeExact || rule.Domain != "sub.example.com" {
		t.Fatalf("exact rule of the queried domain must beat its parent suffix, got %+v ok=%v", rule, ok)
	}

	rule, ok = trie.MatchRule("other.example.com")
	if !ok || rule.Scope != RuleScopeSuffix || rule.Domain != "example.com" {
		t.Fatalf("sibling without exact rule must fall back to parent suffix, got %+v ok=%v", rule, ok)
	}
}

func TestMatchRuleDeepestSuffixWins(t *testing.T) {
	trie := NewTrie()
	trie.AddRule(Rule{Domain: "example.com", Scope: RuleScopeSuffix, SourceID: "parent", Category: "nuisance", Action: RuleActionBlock})
	trie.AddRule(Rule{Domain: "ads.example.com", Scope: RuleScopeSuffix, SourceID: "child", Category: "ads", Action: RuleActionBlock})

	rule, ok := trie.MatchRule("x.ads.example.com")
	if !ok || rule.Domain != "ads.example.com" || rule.SourceID != "child" {
		t.Fatalf("deepest suffix must win, got %+v ok=%v", rule, ok)
	}
}

func TestMatchRuleDuplicateFirstSourceWins(t *testing.T) {
	trie := NewTrie()
	// Sources are ingested in SAFE_ZONE_ADBLOCK_SOURCES order; the earlier
	// source must deterministically keep the slot.
	trie.AddRule(Rule{Domain: "ads.example.com", Scope: RuleScopeSuffix, SourceID: "source-a", Category: "ads", Action: RuleActionBlock})
	trie.AddRule(Rule{Domain: "ads.example.com", Scope: RuleScopeSuffix, SourceID: "source-b", Category: "tracking", Action: RuleActionBlock})
	trie.AddRule(Rule{Domain: "ads.example.com", Scope: RuleScopeExact, SourceID: "source-c", Category: "telemetry", Action: RuleActionBlock})

	rule, ok := trie.MatchRule("ads.example.com")
	if !ok || rule.SourceID != "source-c" || rule.Scope != RuleScopeExact {
		t.Fatalf("exact slot is independent of suffix slot, got %+v ok=%v", rule, ok)
	}

	trie2 := NewTrie()
	trie2.AddRule(Rule{Domain: "ads.example.com", Scope: RuleScopeSuffix, SourceID: "source-a", Category: "ads", Action: RuleActionBlock})
	trie2.AddRule(Rule{Domain: "ads.example.com", Scope: RuleScopeSuffix, SourceID: "source-b", Category: "tracking", Action: RuleActionBlock})
	rule, ok = trie2.MatchRule("ads.example.com")
	if !ok || rule.SourceID != "source-a" {
		t.Fatalf("first source must win deterministically, got %+v ok=%v", rule, ok)
	}
}

func TestMatchRuleSiblingBoundary(t *testing.T) {
	trie := NewTrie()
	trie.AddRule(Rule{Domain: "example.com", Scope: RuleScopeSuffix, SourceID: "s1", Category: "unknown", Action: RuleActionBlock})

	if _, ok := trie.MatchRule("evil-example.com"); ok {
		t.Fatal("evil-example.com must not match suffix example.com")
	}
	if _, ok := trie.MatchRule("notexample.com"); ok {
		t.Fatal("notexample.com must not match suffix example.com")
	}
}

func TestMatchRuleRejectsPublicSuffix(t *testing.T) {
	trie := NewTrie()
	if trie.AddRule(Rule{Domain: "com", Scope: RuleScopeSuffix, SourceID: "s1"}) {
		t.Fatal("bare TLD must be rejected")
	}
	if trie.AddRule(Rule{Domain: "com.vn", Scope: RuleScopeSuffix, SourceID: "s1"}) {
		t.Fatal("multi-label public suffix must be rejected")
	}
	if trie.AddRule(Rule{Domain: "sub.*.com", Scope: RuleScopeSuffix, SourceID: "s1"}) {
		t.Fatal("interior wildcard must be rejected")
	}
	if trie.AddRule(Rule{Domain: "*.sub.*.com", Scope: RuleScopeSuffix, SourceID: "s1"}) {
		t.Fatal("interior wildcard behind a prefix wildcard must be rejected")
	}
	if trie.Count() != 0 {
		t.Fatalf("rejected rules must not be stored, got %d", trie.Count())
	}
}

func TestMatchRuleWildcardPrefixForcesSuffix(t *testing.T) {
	trie := NewTrie()
	// Even when a source policy says exact, a wildcard prefix entry describes
	// a suffix rule.
	if !trie.AddRule(Rule{Domain: "*.ads.example.com", Scope: RuleScopeExact, SourceID: "s1", Category: "ads", Action: RuleActionBlock}) {
		t.Fatal("wildcard prefix entry must be accepted")
	}
	rule, ok := trie.MatchRule("anything.ads.example.com")
	if !ok || rule.Scope != RuleScopeSuffix || rule.Domain != "ads.example.com" {
		t.Fatalf("wildcard must force suffix scope on the normalized domain, got %+v ok=%v", rule, ok)
	}
}

func TestMatchRuleTrailingDotCaseAndPunycode(t *testing.T) {
	trie := NewTrie()
	trie.AddRule(Rule{Domain: "Ads.Example.com.", Scope: RuleScopeExact, SourceID: "s1", Category: "ads", Action: RuleActionBlock})

	rule, ok := trie.MatchRule("ads.example.com")
	if !ok || rule.Domain != "ads.example.com" {
		t.Fatalf("stored rule must be normalized, got %+v ok=%v", rule, ok)
	}
	if _, ok := trie.MatchRule("ADS.EXAMPLE.COM."); !ok {
		t.Fatal("case/trailing-dot query must match")
	}

	trie2 := NewTrie()
	trie2.AddRule(Rule{Domain: "münchen.de", Scope: RuleScopeExact, SourceID: "s1"})
	if _, ok := trie2.MatchRule("xn--mnchen-3ya.de"); !ok {
		t.Fatal("punycode query must match unicode-added rule (IDN parity)")
	}
}

func TestAddLegacyCompatibilityStillSuffix(t *testing.T) {
	trie := NewTrie()
	trie.Add("ads.example.com")

	if _, ok := trie.MatchRule("sub.ads.example.com"); !ok {
		t.Fatal("legacy Add must keep suffix semantics")
	}
	rule, ok := trie.MatchRule("ads.example.com")
	if !ok || rule.SourceID != LegacyRuleSourceID || rule.Scope != RuleScopeSuffix || rule.Action != RuleActionBlock || rule.Category != DefaultRuleCategory {
		t.Fatalf("legacy Add must carry legacy provenance, got %+v", rule)
	}
	if trie.ExactCount() != 0 || trie.SuffixCount() != 1 || trie.Count() != 1 {
		t.Fatalf("unexpected counts exact=%d suffix=%d total=%d", trie.ExactCount(), trie.SuffixCount(), trie.Count())
	}
}

func TestAddRuleUnknownCategoryAndScopeFallback(t *testing.T) {
	trie := NewTrie()
	// Unknown scope falls back to suffix (legacy semantics).
	if !trie.AddRule(Rule{Domain: "a.example.com", Scope: "bogus", SourceID: "s1", Category: "weird", Action: RuleActionBlock}) {
		t.Fatal("rule with unknown scope should still be stored")
	}
	rule, ok := trie.MatchRule("a.example.com")
	if !ok || rule.Scope != RuleScopeSuffix || rule.Category != DefaultRuleCategory {
		t.Fatalf("unknown scope/category must normalize, got %+v ok=%v", rule, ok)
	}
	// Empty action falls back to block.
	if !trie.AddRule(Rule{Domain: "b.example.com", Scope: RuleScopeExact, SourceID: "s1", Action: ""}) {
		t.Fatal("rule with empty action should be stored")
	}
	rule, _ = trie.MatchRule("b.example.com")
	if rule.Action != RuleActionBlock {
		t.Fatalf("empty action must normalize to block, got %q", rule.Action)
	}
}

func TestCacheV2RoundTrip(t *testing.T) {
	trie := NewTrie()
	trie.AddRule(Rule{Domain: "exact.example.com", Scope: RuleScopeExact, SourceID: "src-a", Category: "ads", Action: RuleActionBlock})
	trie.AddRule(Rule{Domain: "suffix.example.com", Scope: RuleScopeSuffix, SourceID: "src-b", Category: "telemetry", Action: RuleActionBlock})
	trie.AddRule(Rule{Domain: "both.example.com", Scope: RuleScopeSuffix, SourceID: "src-c", Category: "nuisance", Action: RuleActionBlock})
	trie.AddRule(Rule{Domain: "both.example.com", Scope: RuleScopeExact, SourceID: "src-d", Category: "tracking", Action: RuleActionBlock})

	var buf bytes.Buffer
	if _, err := trie.WriteToV2(&buf); err != nil {
		t.Fatalf("WriteToV2: %v", err)
	}
	output := buf.String()
	if !strings.HasPrefix(output, CacheV2Header+"\n") {
		t.Fatalf("missing v2 header: %q", output)
	}

	reloaded := NewTrie()
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	if lines[0] != CacheV2Header {
		t.Fatalf("header mismatch: %q", lines[0])
	}
	for _, line := range lines[1:] {
		rule, ok := ParseCacheV2Line(line)
		if !ok {
			t.Fatalf("failed to parse generated record %q", line)
		}
		reloaded.AddRule(rule)
	}

	if reloaded.Count() != trie.Count() || reloaded.ExactCount() != trie.ExactCount() || reloaded.SuffixCount() != trie.SuffixCount() {
		t.Fatalf("counts diverged: before %d/%d/%d after %d/%d/%d",
			trie.ExactCount(), trie.SuffixCount(), trie.Count(),
			reloaded.ExactCount(), reloaded.SuffixCount(), reloaded.Count())
	}
	rule, ok := reloaded.MatchRule("sub.suffix.example.com")
	if !ok || rule.Category != "telemetry" || rule.SourceID != "src-b" {
		t.Fatalf("suffix metadata lost on round-trip: %+v ok=%v", rule, ok)
	}
	rule, ok = reloaded.MatchRule("both.example.com")
	if !ok || rule.Category != "tracking" || rule.SourceID != "src-d" || rule.Scope != RuleScopeExact {
		t.Fatalf("exact slot metadata lost on round-trip: %+v ok=%v", rule, ok)
	}
	if _, ok := reloaded.MatchRule("other.exact.example.com"); ok {
		t.Fatal("exact scope must survive the round-trip")
	}
}

func TestParseCacheV2LineMalformed(t *testing.T) {
	malformed := []string{
		"",
		"only-domain.com",
		"a.com\twrongscope\tunknown\tblock\tsrc",
		"a.com\texact\tbogus-category\tblock\tsrc",
		"a.com\texact\tunknown\tallow\tsrc",
		"\texact\tunknown\tblock\tsrc",
		"a.com\texact\tunknown\tblock\t",
		"a.com\texact\tunknown\tblock\tsrc\textra",
	}
	for _, line := range malformed {
		if _, ok := ParseCacheV2Line(line); ok {
			t.Fatalf("line %q must be rejected", line)
		}
	}
}

func TestAddRuleRejectsNonBlockAction(t *testing.T) {
	trie := NewTrie()
	if trie.AddRule(Rule{Domain: "ads.example.com", Scope: RuleScopeSuffix, SourceID: "s", Category: "ads", Action: "allow"}) {
		t.Fatal("non-block action must be rejected")
	}
	if trie.AddRule(Rule{Domain: "ads.example.com", Scope: RuleScopeSuffix, SourceID: "s", Category: "ads", Action: "BLOCK "}) == false {
		t.Fatal("case/space-insensitive block must still be accepted")
	}
	// Empty stays compatible with block.
	if !trie.AddRule(Rule{Domain: "other.example.com", Scope: RuleScopeExact, SourceID: "s", Action: ""}) {
		t.Fatal("empty action must normalize to block")
	}
	rule, ok := trie.MatchRule("other.example.com")
	if !ok || rule.Action != RuleActionBlock {
		t.Fatalf("empty action must normalize to block, got %+v ok=%v", rule, ok)
	}
	if _, ok := trie.MatchRule("ads.example.com"); !ok {
		t.Fatal("block rule must match")
	}
	if trie.Count() != 2 {
		t.Fatalf("rejected allow must not be stored, got %d", trie.Count())
	}
}

func TestMergeFromPreservesFirstWinsAndBothScopes(t *testing.T) {
	dst := NewTrie()
	stagingA := NewTrie()
	stagingA.AddRule(Rule{Domain: "ads.example.com", Scope: RuleScopeSuffix, SourceID: "a", Category: "ads", Action: RuleActionBlock})
	stagingA.AddRule(Rule{Domain: "ads.example.com", Scope: RuleScopeExact, SourceID: "a-exact", Category: "ads", Action: RuleActionBlock})
	stagingB := NewTrie()
	stagingB.AddRule(Rule{Domain: "ads.example.com", Scope: RuleScopeSuffix, SourceID: "b", Category: "tracking", Action: RuleActionBlock})
	stagingB.AddRule(Rule{Domain: "ads.example.com", Scope: RuleScopeExact, SourceID: "b-exact", Category: "tracking", Action: RuleActionBlock})
	stagingB.AddRule(Rule{Domain: "new.example.com", Scope: RuleScopeSuffix, SourceID: "b", Category: "tracking", Action: RuleActionBlock})

	if n := dst.MergeFrom(stagingA); n != 2 {
		t.Fatalf("expected 2 merged, got %d", n)
	}
	if n := dst.MergeFrom(stagingB); n != 1 {
		t.Fatalf("only the new domain should merge, got %d", n)
	}
	// Exact slot keeps first source; suffix slot keeps first source.
	exactTrie := NewTrie()
	exactTrie.AddRule(Rule{Domain: "ads.example.com", Scope: RuleScopeExact, SourceID: "a-exact", Category: "ads", Action: RuleActionBlock})
	rule, ok := dst.MatchRule("ads.example.com")
	if !ok || rule.Scope != RuleScopeExact || rule.SourceID != "a-exact" {
		t.Fatalf("exact slot must keep first source, got %+v ok=%v", rule, ok)
	}
	rule, ok = dst.MatchRule("sub.ads.example.com")
	if !ok || rule.SourceID != "a" {
		t.Fatalf("suffix slot must keep first source, got %+v ok=%v", rule, ok)
	}
	if !dst.Match("sub.new.example.com") {
		t.Fatal("new domain from later source must merge")
	}
	_ = exactTrie
}

func TestMatchRuleNilTrieSafe(t *testing.T) {
	var nilTrie *Trie
	if _, ok := nilTrie.MatchRule("example.com"); ok {
		t.Fatal("nil trie must not match")
	}
	if nilTrie.Match("example.com") {
		t.Fatal("nil trie Match must be false")
	}
	if nilTrie.Count() != 0 {
		t.Fatal("nil trie Count must be 0")
	}
	if detail := nilTrie.MatchRuleDetail("example.com"); detail.Matched {
		t.Fatal("nil trie MatchRuleDetail must not match")
	}
}

func TestMatchRuleDetailParityWithMatchRule(t *testing.T) {
	trie := NewTrie()
	trie.AddRule(Rule{Domain: "exact.example.com", Scope: RuleScopeExact, SourceID: "s1", Category: "ads", Action: RuleActionBlock})
	trie.AddRule(Rule{Domain: "suffix.example.com", Scope: RuleScopeSuffix, SourceID: "s2", Category: "telemetry", Action: RuleActionBlock})
	trie.AddRule(Rule{Domain: "example.com", Scope: RuleScopeSuffix, SourceID: "s3", Category: "nuisance", Action: RuleActionBlock})

	queries := []string{
		"exact.example.com",
		"sub.exact.example.com",
		"suffix.example.com",
		"deep.sub.suffix.example.com",
		"example.com",
		"other.example.com",
		"unrelated.example.org",
		"",
		"  SUFFIX.EXAMPLE.COM.  ",
	}
	for _, q := range queries {
		wantRule, wantOK := trie.MatchRule(q)
		detail := trie.MatchRuleDetail(q)
		if detail.Matched != wantOK {
			t.Fatalf("query %q: MatchRuleDetail matched=%v, MatchRule matched=%v", q, detail.Matched, wantOK)
		}
		if wantOK && detail.Rule != wantRule {
			t.Fatalf("query %q: detail rule %+v != MatchRule %+v", q, detail.Rule, wantRule)
		}
		if wantOK && detail.Query == "" {
			t.Fatalf("query %q: matched detail must carry the canonical query", q)
		}
		if !wantOK && detail.Query != "" {
			t.Fatalf("query %q: unmatched detail must leave Query empty", q)
		}
	}
}

func TestMatchRuleDetailUnicodePunycode(t *testing.T) {
	trie := NewTrie()
	// Unicode input at insert time stores the punycode rule.
	trie.AddRule(Rule{Domain: "münchen.de", Scope: RuleScopeSuffix, SourceID: "s1", Category: "ads", Action: RuleActionBlock})

	unicodeQuery := "sub.münchen.de"
	punyQuery := "sub.xn--mnchen-3ya.de"

	unicodeDetail := trie.MatchRuleDetail(unicodeQuery)
	punyDetail := trie.MatchRuleDetail(punyQuery)
	if !unicodeDetail.Matched || !punyDetail.Matched {
		t.Fatalf("unicode and punycode queries must both match: %+v %+v", unicodeDetail, punyDetail)
	}
	if unicodeDetail.Query != "sub.xn--mnchen-3ya.de" || punyDetail.Query != "sub.xn--mnchen-3ya.de" {
		t.Fatalf("Query must be the canonical punycode form, got %q and %q", unicodeDetail.Query, punyDetail.Query)
	}
	if unicodeDetail.Rule.Domain != "xn--mnchen-3ya.de" {
		t.Fatalf("stored rule must be punycode, got %+v", unicodeDetail.Rule)
	}
	// Exact apex vs descendant is decided on the canonical forms.
	if unicodeDetail.Query == unicodeDetail.Rule.Domain {
		t.Fatal("subdomain query must not equal the rule domain")
	}
	apex := trie.MatchRuleDetail("münchen.de")
	if !apex.Matched || apex.Query != apex.Rule.Domain {
		t.Fatalf("apex query must equal the rule domain, got %+v", apex)
	}
}

func TestMatchRuleDetailExactApexVsDescendant(t *testing.T) {
	trie := NewTrie()
	trie.AddRule(Rule{Domain: "apex.example.com", Scope: RuleScopeExact, SourceID: "s1", Category: "ads", Action: RuleActionBlock})
	trie.AddRule(Rule{Domain: "wild.example.com", Scope: RuleScopeSuffix, SourceID: "s1", Category: "ads", Action: RuleActionBlock})

	exact := trie.MatchRuleDetail("apex.example.com")
	if !exact.Matched || exact.Query != exact.Rule.Domain || exact.Rule.Scope != RuleScopeExact {
		t.Fatalf("exact apex must compare equal, got %+v", exact)
	}
	desc := trie.MatchRuleDetail("deep.wild.example.com")
	if !desc.Matched || desc.Query == desc.Rule.Domain {
		t.Fatalf("descendant must not equal the rule domain, got %+v", desc)
	}
	if desc.Rule.Domain != "wild.example.com" {
		t.Fatalf("deepest suffix must win, got %+v", desc.Rule)
	}
}

func TestMatchRuleDetailWildcardBoundaryAndOrigin(t *testing.T) {
	trie := NewTrie()
	trie.AddRule(Rule{Domain: "*.wild.example.com", Scope: RuleScopeExact, SourceID: "s1", Category: "ads", Action: RuleActionBlock, Origin: OriginGlobalDefault})

	rule, ok := trie.MatchRule("wild.example.com")
	if !ok || rule.Scope != RuleScopeSuffix || rule.Origin != OriginWildcard {
		t.Fatalf("wildcard must force suffix scope and origin, got %+v ok=%v", rule, ok)
	}
	detail := trie.MatchRuleDetail("sub.wild.example.com")
	if !detail.Matched || detail.Query == detail.Rule.Domain {
		t.Fatalf("wildcard descendant must hit as non-apex, got %+v", detail)
	}
	if _, ok := trie.MatchRule("evil-wild.example.com"); ok {
		t.Fatal("sibling must not match across a label boundary")
	}
	if detail := trie.MatchRuleDetail("evil-wild.example.com"); detail.Matched || detail.Query != "" {
		t.Fatal("sibling detail must be unmatched with empty query")
	}
}

func TestMatchRuleDetailInvalidIDNUnchanged(t *testing.T) {
	trie := NewTrie()
	trie.AddRule(Rule{Domain: "ads.example.com", Scope: RuleScopeSuffix, SourceID: "s1", Category: "ads", Action: RuleActionBlock})

	// Invalid IDN input must behave exactly like MatchRule: no match, no panic.
	for _, q := range []string{"http://", "a..b..c", "ex ample.com\x7f"} {
		_, wantOK := trie.MatchRule(q)
		detail := trie.MatchRuleDetail(q)
		if detail.Matched != wantOK {
			t.Fatalf("query %q: detail matched=%v, MatchRule matched=%v", q, detail.Matched, wantOK)
		}
	}
	// Empty and whitespace-only inputs never match and carry no query.
	for _, q := range []string{"", "   "} {
		detail := trie.MatchRuleDetail(q)
		if detail.Matched || detail.Query != "" {
			t.Fatalf("query %q must be unmatched with empty query, got %+v", q, detail)
		}
	}
}

func TestMatchRuleDetailASCIIAllocs(t *testing.T) {
	trie := NewTrie()
	trie.AddRule(Rule{Domain: "ads.example.com", Scope: RuleScopeSuffix, SourceID: "s1", Category: "ads", Action: RuleActionBlock})

	queries := map[string]bool{
		"ads.example.com":     true,
		"sub.ads.example.com": true,
		"miss.example.org":    false,
	}
	for q, want := range queries {
		if allocs := testing.AllocsPerRun(200, func() {
			_ = trie.MatchRuleDetail(q)
		}); allocs != 0 {
			t.Fatalf("query %q allocated %v times", q, allocs)
		}
		if got := trie.MatchRuleDetail(q).Matched; got != want {
			t.Fatalf("query %q matched=%v want %v", q, got, want)
		}
	}
}

func TestAddRuleOriginPreservedAndWildcardOverride(t *testing.T) {
	trie := NewTrie()
	if !trie.AddRule(Rule{Domain: "plain.example.com", Scope: RuleScopeSuffix, SourceID: "s", Category: "ads", Action: RuleActionBlock, Origin: OriginGlobalDefault}) {
		t.Fatal("plain rule must be stored")
	}
	if !trie.AddRule(Rule{Domain: "*.wild.example.com", Scope: RuleScopeExact, SourceID: "s", Category: "ads", Action: RuleActionBlock, Origin: OriginSourcePolicyExact}) {
		t.Fatal("wildcard rule must be stored")
	}
	plain, _ := trie.MatchRule("plain.example.com")
	if plain.Origin != OriginGlobalDefault {
		t.Fatalf("passed origin must be preserved, got %v", plain.Origin)
	}
	wild, _ := trie.MatchRule("sub.wild.example.com")
	if wild.Scope != RuleScopeSuffix || wild.Origin != OriginWildcard || wild.Domain != "wild.example.com" {
		t.Fatalf("wildcard must override scope and origin, got %+v", wild)
	}
}

func TestAddLegacyMarksLegacyAddOrigin(t *testing.T) {
	trie := NewTrie()
	trie.Add("legacy.example.com")
	rule, ok := trie.MatchRule("legacy.example.com")
	if !ok || rule.Origin != OriginLegacyAdd {
		t.Fatalf("legacy Add must mark OriginLegacyAdd, got %+v ok=%v", rule, ok)
	}
}

func TestParseCacheV2LineMarksUnknownOrigin(t *testing.T) {
	rule, ok := ParseCacheV2Line("a.example.com\tsuffix\tads\tblock\tsrc")
	if !ok || rule.Origin != OriginCacheV2Unknown {
		t.Fatalf("v2 records must carry OriginCacheV2Unknown, got %+v ok=%v", rule, ok)
	}
}
