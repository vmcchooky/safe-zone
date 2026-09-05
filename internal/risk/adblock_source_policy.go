package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"sync"

	"safe-zone/internal/domaintrie"
	"safe-zone/internal/logjson"
)

// adblockMatchMode controls the default scope applied to host-list entries
// that do not carry their own wildcard marker. "suffix" preserves the
// pre-PR2 behavior and is the safe default; "exact" is the PR3-facing
// rollout target.
type adblockMatchMode string

const (
	adblockMatchModeSuffix adblockMatchMode = "suffix"
	adblockMatchModeExact  adblockMatchMode = "exact"
)

const (
	envAdblockMatchMode          = "SAFE_ZONE_ADBLOCK_MATCH_MODE"
	envAdblockSourcePoliciesJSON = "SAFE_ZONE_ADBLOCK_SOURCE_POLICIES_JSON"
)

// adblockSourcePolicy is the per-source ingestion policy: which content
// category rules from this source carry and which scope plain host entries
// get. Wildcard entries always become suffix rules regardless of Scope.
type adblockSourcePolicy struct {
	Category string `json:"category"`
	Scope    string `json:"scope"`
}

// adblockSourcePolicySet is the parsed form of
// SAFE_ZONE_ADBLOCK_SOURCE_POLICIES_JSON, keyed by the exact source string
// from SAFE_ZONE_ADBLOCK_SOURCES.
type adblockSourcePolicySet map[string]adblockSourcePolicy

// canonicalSourceID derives a run-stable identifier for a source string:
// trimmed, then SHA-256 (first 16 bytes, hex). URL sources are canonicalized
// structurally (see canonicalSourceKey): only scheme and hostname are
// case-insensitive, while userinfo, port, path, query and fragment keep their
// exact case and encoding. The digest is stored as rule provenance and in the
// v2 cache; note the raw source string itself can still appear in
// adblock_meta.json keys and in fetch/scan error logs, so the digest alone
// must not be treated as a redaction boundary.
func canonicalSourceID(source string) string {
	normalized := canonicalSourceKey(strings.TrimSpace(source))
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:16])
}

// canonicalSourceKey canonicalizes a source URL with net/url: the scheme and
// hostname are lowercased, the port is kept as-is, and userinfo (including any
// password), path, raw query and fragment are preserved byte-for-byte.
// Non-URL sources (file paths, inline labels) and unparsable inputs are
// returned unchanged so identity stays deterministic and panic-free.
func canonicalSourceKey(trimmed string) string {
	if !strings.Contains(trimmed, "://") {
		return trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return trimmed
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return trimmed
	}
	host := hostname
	if port := parsed.Port(); port != "" {
		if strings.Contains(hostname, ":") {
			host = "[" + hostname + "]:" + port
		} else {
			host = hostname + ":" + port
		}
	} else if strings.HasPrefix(parsed.Host, "[") {
		host = "[" + hostname + "]"
	}
	parsed.Host = host
	return parsed.String()
}

// warnOnceFlags deduplicates adblock config warnings per key so repeated
// reads (sync ticks, per-line parsing, tests) do not spam the log. It is
// accessed from sync and config-reload goroutines, so all access is
// mutex-guarded.
var warnOnceFlags syncWarnFlags

type syncWarnFlags struct {
	mu    sync.Mutex
	flags map[string]bool
}

func (w *syncWarnFlags) once(key, message string, fields map[string]any) {
	w.mu.Lock()
	if w.flags == nil {
		w.flags = make(map[string]bool)
	}
	if w.flags[key] {
		w.mu.Unlock()
		return
	}
	w.flags[key] = true
	w.mu.Unlock()
	logjson.Warn(message, fields)
}

// parseAdblockMatchMode normalizes the global match mode. Invalid values
// fall back to suffix with a one-shot warning instead of failing DNS
// startup — this flag is a rollout control, not a correctness requirement.
func parseAdblockMatchMode(raw string) adblockMatchMode {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "", string(adblockMatchModeSuffix):
		return adblockMatchModeSuffix
	case string(adblockMatchModeExact):
		return adblockMatchModeExact
	default:
		warnOnceFlags.once("adblock_match_mode_invalid",
			"invalid SAFE_ZONE_ADBLOCK_MATCH_MODE; falling back to suffix",
			map[string]any{"service": "risk", "value": value})
		return adblockMatchModeSuffix
	}
}

// parseAdblockSourcePolicies decodes the per-source policy JSON. Keys must
// match sources in SAFE_ZONE_ADBLOCK_SOURCES exactly; unknown categories
// normalize to "unknown" and unknown scopes to the global match mode at rule
// creation time, so parsing only stores the raw strings. Invalid JSON keeps
// every source on defaults (one-shot warning), never blocks startup.
func parseAdblockSourcePolicies(raw string) adblockSourcePolicySet {
	policies := make(adblockSourcePolicySet)
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return policies
	}
	var decoded map[string]adblockSourcePolicy
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		warnOnceFlags.once("adblock_source_policies_invalid",
			"invalid adblock source policies JSON; all sources fall back to defaults",
			map[string]any{"service": "risk", "error": err.Error()})
		return policies
	}
	for source, policy := range decoded {
		policies[source] = policy
	}
	return policies
}

// resolveAdblockSourcePolicy returns the effective (category, scope, origin)
// for a source. Missing config → category unknown, scope from the global
// match mode; invalid category → unknown with a one-shot warning; invalid
// scope → global mode with a one-shot warning. The origin records which side
// decided the scope: only an explicit, valid per-source scope yields
// OriginSourcePolicyExact/Suffix — a missing, empty or invalid scope falls
// back to the global mode with OriginGlobalDefault, as does a category-only
// policy. These warnings log only the canonical source digest; fetch/scan
// error paths elsewhere may still log the raw source string.
func (s *Service) resolveAdblockSourcePolicy(source string) (string, domaintrie.RuleScope, domaintrie.ScopeOrigin) {
	category := domaintrie.DefaultRuleCategory
	scope := domaintrie.RuleScopeSuffix
	if s.adblockMatchMode.Load() == string(adblockMatchModeExact) {
		scope = domaintrie.RuleScopeExact
	}
	origin := domaintrie.OriginGlobalDefault
	if s.adblockSourcePolicies == nil {
		return category, scope, origin
	}
	policy, ok := s.adblockSourcePolicies[source]
	if !ok {
		return category, scope, origin
	}

	if cat := strings.ToLower(strings.TrimSpace(policy.Category)); cat != "" {
		if domaintrie.IsValidRuleCategory(cat) {
			category = cat
		} else {
			warnOnceFlags.once("adblock_source_category_invalid:"+canonicalSourceID(source),
				"invalid adblock source policy category; using unknown",
				map[string]any{"service": "risk", "source_id": canonicalSourceID(source)})
		}
	}
	switch sc := strings.ToLower(strings.TrimSpace(policy.Scope)); sc {
	case "":
		// no per-source override → global mode
	case string(adblockMatchModeExact):
		scope = domaintrie.RuleScopeExact
		origin = domaintrie.OriginSourcePolicyExact
	case string(adblockMatchModeSuffix):
		scope = domaintrie.RuleScopeSuffix
		origin = domaintrie.OriginSourcePolicySuffix
	default:
		warnOnceFlags.once("adblock_source_scope_invalid:"+canonicalSourceID(source),
			"invalid adblock source policy scope; using global match mode",
			map[string]any{"service": "risk", "source_id": canonicalSourceID(source)})
	}
	return category, scope, origin
}
