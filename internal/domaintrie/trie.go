package domaintrie

import (
	"fmt"
	"io"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// RuleScope distinguishes exact hostname rules from suffix rules. An exact
// rule matches only the recorded domain; a suffix rule also matches every
// subdomain.
type RuleScope string

const (
	RuleScopeExact  RuleScope = "exact"
	RuleScopeSuffix RuleScope = "suffix"
)

// RuleActionBlock is the only action executed in PR2; the field exists so
// later PRs can introduce additional actions without another storage format
// change. No source currently emits anything else.
const RuleActionBlock = "block"

// Legacy rule provenance labels. "legacy" marks rules added through the
// compatibility Add helper; "legacy-cache" marks rules loaded from a
// pre-v2 (domain-only) global cache file.
const (
	LegacyRuleSourceID    = "legacy"
	CacheV2LegacySourceID = "legacy-cache"
	CacheV2Header         = "# safe-zone-adblock-cache-v2"
	DefaultRuleCategory   = "unknown"
)

// validRuleCategories is the closed set PR2 recognizes. Anything else
// normalizes to "unknown" because no provenance evidence backs it.
var validRuleCategories = map[string]struct{}{
	"ads":       {},
	"tracking":  {},
	"telemetry": {},
	"nuisance":  {},
	"unknown":   {},
}

// IsValidRuleCategory reports whether the category is part of the closed PR2
// set.
func IsValidRuleCategory(category string) bool {
	_, ok := validRuleCategories[category]
	return ok
}

// ScopeOrigin records why a rule carries its scope. It exists for
// observation only (PR3B shadow exact/suffix) and never changes matching,
// enforcement or the v2 cache format. The zero value is Unspecified, which
// observers must treat as unknown provenance.
type ScopeOrigin uint8

const (
	// OriginUnspecified means no producer recorded an origin. Observers must
	// report unavailable rather than infer anything from the scope.
	OriginUnspecified ScopeOrigin = iota
	// OriginGlobalDefault marks a plain entry that took the effective global
	// match mode. Only these rules move under a prospective global scope flip.
	OriginGlobalDefault
	// OriginSourcePolicyExact marks an entry pinned to exact by an explicit
	// per-source scope policy.
	OriginSourcePolicyExact
	// OriginSourcePolicySuffix marks an entry pinned to suffix by an explicit
	// per-source scope policy.
	OriginSourcePolicySuffix
	// OriginWildcard marks an entry whose raw selector started with "*.".
	// Wildcards always keep suffix semantics.
	OriginWildcard
	// OriginLegacyAdd marks rules added through the legacy Add helper.
	OriginLegacyAdd
	// OriginCacheV2Unknown marks rules reloaded from the global v2 cache,
	// which persists no origin. The scope alone must never be used to infer
	// one.
	OriginCacheV2Unknown
	// OriginLegacyCache marks rules reloaded from the legacy domains-only
	// global cache.
	OriginLegacyCache
)

// Rule is a typed blocklist entry. Domain is always the normalized
// (lowercase, punycode) form of the rule that was added, so a returned match
// names the real rule that fired.
type Rule struct {
	Domain   string
	Scope    RuleScope
	SourceID string
	Category string
	Action   string
	// Origin records why the rule carries its scope. Observation-only; it
	// never affects matching, enforcement or cache serialization.
	Origin ScopeOrigin
}

// childEntry is a label→node pair stored in a sorted slice.
type childEntry struct {
	Label string
	Node  *Node
}

// Node represents a single part (label) of a domain name in the Trie.
// Children are stored in a sorted slice for memory efficiency; binary search
// provides O(log n) lookup which, for the small fan-out typical of domain
// labels, is faster than map lookup due to cache locality.
//
// Exact and suffix rules are stored in separate slots so both can coexist on
// the same node (e.g. different sources). Nodes are only mutated while a
// trie is being built; a published trie is immutable and lock-free to read.
type Node struct {
	Children []childEntry
	Exact    *Rule
	Suffix   *Rule
}

// findChild performs binary search on sorted children slice.
func (n *Node) findChild(label string) (*Node, bool) {
	lo, hi := 0, len(n.Children)-1
	for lo <= hi {
		mid := int(uint(lo+hi) >> 1) // avoid overflow
		switch {
		case n.Children[mid].Label < label:
			lo = mid + 1
		case n.Children[mid].Label > label:
			hi = mid - 1
		default:
			return n.Children[mid].Node, true
		}
	}
	return nil, false
}

// addChild inserts a child in sorted order via binary search.
// If the label already exists, returns the existing child.
func (n *Node) addChild(label string) *Node {
	lo, hi := 0, len(n.Children)-1
	for lo <= hi {
		mid := int(uint(lo+hi) >> 1)
		switch {
		case n.Children[mid].Label < label:
			lo = mid + 1
		case n.Children[mid].Label > label:
			hi = mid - 1
		default:
			return n.Children[mid].Node
		}
	}
	child := &Node{}
	// Insert at position lo to maintain sorted order.
	n.Children = append(n.Children, childEntry{})
	copy(n.Children[lo+1:], n.Children[lo:])
	n.Children[lo] = childEntry{Label: label, Node: child}
	return child
}

// Trie is an optimized prefix-tree for typed blocklist rules.
// It stores domains in reverse-label order (e.g., com -> example -> ads).
// It is lock-free for readers once built.
type Trie struct {
	root        *Node
	exactCount  int
	suffixCount int
}

// NewTrie creates a new, empty Domain filter.
func NewTrie() *Trie {
	return &Trie{
		root: &Node{},
	}
}

// normalizeDomain lowercases, trims, and converts to ASCII (Punycode).
// This ensures Unicode and Punycode forms of the same domain always match.
func normalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return ""
	}
	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return domain
	}
	return ascii
}

func sanitizeDomain(domain string) string {
	for strings.HasPrefix(domain, "*.") {
		domain = strings.TrimPrefix(domain, "*.")
	}
	// Any remaining wildcard makes the host invalid for our suffix matcher.
	if strings.Contains(domain, "*") {
		return ""
	}
	return domain
}

// Add inserts a domain into the filter with legacy suffix semantics: the
// domain and every subdomain match. It is a compatibility wrapper over
// AddRule used by tests and legacy loaders; ingestion code should prefer
// AddRule so provenance is preserved.
func (t *Trie) Add(domain string) {
	t.AddRule(Rule{
		Domain:   domain,
		Scope:    RuleScopeSuffix,
		SourceID: LegacyRuleSourceID,
		Category: DefaultRuleCategory,
		Action:   RuleActionBlock,
		Origin:   OriginLegacyAdd,
	})
}

// AddRule inserts a typed rule. Rules are normalized before storage (the
// stored rule carries the normalized domain, lowercased category and a
// non-empty action). Insertion is first-wins per (node, scope) slot, so when
// callers add rules in SAFE_ZONE_ADBLOCK_SOURCES order, the earlier source
// deterministically wins. Wildcard-prefixed entries ("*.example.com") are
// forced to suffix scope with OriginWildcard regardless of the passed scope
// or origin; any other passed origin is preserved as-is. Interior wildcards
// and public suffixes are rejected. PR2 only executes block: an empty action
// normalizes to block for compatibility, but any other non-block action is
// rejected. It returns false when the rule was rejected or its slot was
// already occupied.
func (t *Trie) AddRule(rule Rule) bool {
	if t == nil || t.root == nil {
		return false
	}
	raw := strings.TrimSpace(rule.Domain)
	if raw == "" {
		return false
	}
	// A wildcard prefix always describes a suffix rule, regardless of the
	// configured scope for the source it came from.
	forcedSuffix := strings.HasPrefix(raw, "*.")
	domain := sanitizeDomain(normalizeDomain(raw))
	if domain == "" {
		return false
	}

	// Clean the domain for the publicsuffix check (it dislikes trailing/double dots).
	// The cleaned form is also what gets stored as the rule's Domain so a
	// returned match always names the real normalized rule.
	checkDomain := strings.TrimRight(domain, ".")
	for strings.Contains(checkDomain, "..") {
		checkDomain = strings.ReplaceAll(checkDomain, "..", ".")
	}
	domain = checkDomain

	// Safety guard: reject domains that ARE a public suffix (TLD or
	// multi-label registries like "co.uk", "com.vn", "edu.vn").
	// publicsuffix.EffectiveTLDPlusOne returns error when the input
	// is itself a suffix, which is exactly what we want to reject.
	if _, err := publicsuffix.EffectiveTLDPlusOne(checkDomain); err != nil {
		return false
	}

	scope := rule.Scope
	origin := rule.Origin
	if forcedSuffix {
		// A wildcard prefix always describes a suffix rule, regardless of the
		// passed scope or origin.
		scope = RuleScopeSuffix
		origin = OriginWildcard
	}
	if scope != RuleScopeExact && scope != RuleScopeSuffix {
		// Unknown scope values fall back to the legacy suffix semantics.
		scope = RuleScopeSuffix
	}
	category := strings.ToLower(strings.TrimSpace(rule.Category))
	if !IsValidRuleCategory(category) {
		category = DefaultRuleCategory
	}
	action := strings.ToLower(strings.TrimSpace(rule.Action))
	if action == "" {
		action = RuleActionBlock
	} else if action != RuleActionBlock {
		return false
	}

	curr := t.root

	// Insert from TLD down to the specific subdomain.
	// Zero-allocation: scan the string in reverse looking for '.' separators.
	end := len(domain)
	for end > 0 {
		start := strings.LastIndexByte(domain[:end], '.')
		label := domain[start+1 : end]
		end = start // will be -1 when no more dots → loop terminates
		if label == "" {
			continue // skip empty labels e.g. from trailing dots
		}
		curr = curr.addChild(label)
	}

	stored := Rule{
		Domain:   domain,
		Scope:    scope,
		SourceID: rule.SourceID,
		Category: category,
		Action:   action,
		Origin:   origin,
	}
	if scope == RuleScopeExact {
		if curr.Exact != nil {
			return false
		}
		curr.Exact = &stored
		t.exactCount++
		return true
	}
	if curr.Suffix != nil {
		return false
	}
	curr.Suffix = &stored
	t.suffixCount++
	return true
}

// MatchDetail is the result of a single trie lookup: the matched rule, the
// canonical ASCII/punycode query string that actually traversed the trie,
// and whether anything matched. Query is empty when nothing matched.
// Comparing Query == Rule.Domain tells an exact apex hit apart from a suffix
// descendant hit without a second IDNA normalization on the request path.
type MatchDetail struct {
	Rule    Rule
	Query   string
	Matched bool
}

// MatchRuleDetail returns the rule covering the queried domain, preferring:
//  1. the exact rule of the queried domain itself;
//  2. otherwise the deepest suffix rule found along the label walk
//     (a deeper suffix always beats its parent suffixes).
//
// The input is normalized exactly once; the returned Query is the canonical
// form used for traversal. The lookup is allocation-free on the ASCII path
// and lock-free on published tries.
func (t *Trie) MatchRuleDetail(domain string) MatchDetail {
	if t == nil || t.root == nil {
		return MatchDetail{}
	}
	domain = normalizeDomain(domain)
	if domain == "" {
		return MatchDetail{}
	}

	curr := t.root
	var deepest *Rule

	end := len(domain)
	for end > 0 {
		start := strings.LastIndexByte(domain[:end], '.')
		label := domain[start+1 : end]
		end = start
		if label == "" {
			continue
		}
		child, exists := curr.findChild(label)
		if !exists {
			// No deeper node can exist; the deepest suffix seen so far wins.
			if deepest != nil {
				return MatchDetail{Rule: *deepest, Query: domain, Matched: true}
			}
			return MatchDetail{}
		}
		if child.Suffix != nil {
			deepest = child.Suffix
		}
		curr = child
	}

	// All labels consumed: the queried domain's own exact rule wins.
	if curr.Exact != nil {
		return MatchDetail{Rule: *curr.Exact, Query: domain, Matched: true}
	}
	if deepest != nil {
		return MatchDetail{Rule: *deepest, Query: domain, Matched: true}
	}
	return MatchDetail{}
}

// MatchRule returns the rule that covers the queried domain. Compatibility
// wrapper over MatchRuleDetail with identical precedence and behavior.
func (t *Trie) MatchRule(domain string) (Rule, bool) {
	detail := t.MatchRuleDetail(domain)
	return detail.Rule, detail.Matched
}

// Match checks if the domain or any of its parent root domains are blocked.
// e.g., if "example.com" is blocked, Match("sub.example.com") returns true.
// Compatibility wrapper over MatchRule: it reports any exact or suffix rule.
func (t *Trie) Match(domain string) bool {
	if t == nil {
		return false
	}
	_, ok := t.MatchRule(domain)
	return ok
}

// ForEach visits every stored rule in deterministic reverse-label order.
// Exact is visited before suffix on the same node so both slots on one domain
// are observable. Returning false stops the walk. It allocates nothing on the
// read path beyond the walk itself and never mutates the trie.
func (t *Trie) ForEach(fn func(Rule) bool) {
	if t == nil || t.root == nil || fn == nil {
		return
	}
	stopped := false
	var walk func(node *Node)
	walk = func(node *Node) {
		if stopped || node == nil {
			return
		}
		if node.Exact != nil {
			if !fn(*node.Exact) {
				stopped = true
				return
			}
		}
		if node.Suffix != nil {
			if !fn(*node.Suffix) {
				stopped = true
				return
			}
		}
		for _, child := range node.Children {
			walk(child.Node)
			if stopped {
				return
			}
		}
	}
	walk(t.root)
}

// MergeFrom inserts every rule from src into t preserving first-wins per
// (domain, scope) slot: callers must merge staging tries in
// SAFE_ZONE_ADBLOCK_SOURCES order so the earlier source keeps the slot.
// Both exact and suffix slots on the same domain are merged. It returns the
// number of newly stored rules.
func (t *Trie) MergeFrom(src *Trie) int {
	if t == nil || src == nil {
		return 0
	}
	merged := 0
	src.ForEach(func(rule Rule) bool {
		if t.AddRule(rule) {
			merged++
		}
		return true
	})
	return merged
}

// Clear clears the trie. Not thread-safe for active readers.
func (t *Trie) Clear() {
	t.root = &Node{}
	t.exactCount = 0
	t.suffixCount = 0
}

// Count returns the total number of stored rules (exact + suffix).
func (t *Trie) Count() int {
	if t == nil {
		return 0
	}
	return t.exactCount + t.suffixCount
}

// ExactCount returns the number of stored exact rules.
func (t *Trie) ExactCount() int {
	if t == nil {
		return 0
	}
	return t.exactCount
}

// SuffixCount returns the number of stored suffix rules.
func (t *Trie) SuffixCount() int {
	if t == nil {
		return 0
	}
	return t.suffixCount
}

// WriteTo writes all domains in the filter to the provided writer, sorted alphabetically.
// This is the legacy v1 (domain-only) format used by tests and degraded-mode
// tooling. It is lossy: exact/suffix scope, category, action and source
// provenance are dropped, so a v1 reload can never restore typed rules — it
// must not be described as a lossless rollback. The v2 cache format is
// WriteToV2.
func (t *Trie) WriteTo(w io.Writer) (int64, error) {
	var total int64
	var err error

	var walk func(node *Node, path []string)
	walk = func(node *Node, path []string) {
		if err != nil {
			return
		}
		if node.Exact != nil || node.Suffix != nil {
			// reconstruct domain (path is from TLD down)
			domainParts := make([]string, len(path))
			for i, p := range path {
				domainParts[len(path)-1-i] = p
			}
			domain := strings.Join(domainParts, ".")
			var n int
			n, err = fmt.Fprintln(w, domain)
			total += int64(n)
			if err != nil {
				return
			}
		}

		if len(node.Children) == 0 {
			return
		}

		// Children are already sorted, iterate in order.
		for _, child := range node.Children {
			walk(child.Node, append(path, child.Label))
		}
	}

	walk(t.root, nil)
	return total, err
}

// WriteToV2 writes the v2 cache format: a version header followed by one
// tab-separated record per rule (domain, scope, category, action, source_id),
// emitted in the trie's deterministic reverse-label order. Pairs with
// ParseCacheV2Line for lossless reloads of typed rules (v1 domain-only files
// stay lossy by design).
func (t *Trie) WriteToV2(w io.Writer) (int64, error) {
	var total int64
	var err error

	writeRule := func(rule *Rule) {
		if err != nil {
			return
		}
		var n int
		n, err = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			rule.Domain, rule.Scope, rule.Category, rule.Action, rule.SourceID)
		total += int64(n)
	}

	var walk func(node *Node, path []string)
	walk = func(node *Node, path []string) {
		if err != nil {
			return
		}
		if node.Exact != nil {
			writeRule(node.Exact)
		}
		if node.Suffix != nil {
			writeRule(node.Suffix)
		}
		if err != nil || len(node.Children) == 0 {
			return
		}
		for _, child := range node.Children {
			walk(child.Node, append(path, child.Label))
		}
	}

	if _, err = fmt.Fprintln(w, CacheV2Header); err != nil {
		return total, err
	}
	total += int64(len(CacheV2Header) + 1)
	walk(t.root, nil)
	return total, err
}

// ParseCacheV2Line parses one v2 cache record. Malformed records return
// ok=false so callers can skip them instead of failing the whole load. The v2
// format persists no scope origin, so every loaded rule carries
// OriginCacheV2Unknown; callers must not infer an origin from the scope.
func ParseCacheV2Line(line string) (Rule, bool) {
	parts := strings.Split(line, "\t")
	if len(parts) != 5 {
		return Rule{}, false
	}
	rule := Rule{
		Domain:   parts[0],
		Scope:    RuleScope(parts[1]),
		Category: parts[2],
		Action:   parts[3],
		SourceID: parts[4],
		Origin:   OriginCacheV2Unknown,
	}
	if rule.Domain == "" || rule.SourceID == "" {
		return Rule{}, false
	}
	switch rule.Scope {
	case RuleScopeExact, RuleScopeSuffix:
	default:
		return Rule{}, false
	}
	if !IsValidRuleCategory(rule.Category) {
		return Rule{}, false
	}
	if rule.Action != RuleActionBlock {
		// PR2 only persists and executes block actions; anything else in the
		// cache is a format violation, not a loadable rule.
		return Rule{}, false
	}
	return rule, true
}
