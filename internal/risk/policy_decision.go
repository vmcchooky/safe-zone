package risk

import (
	"strings"

	"safe-zone/internal/domaintrie"
)

// PolicySemantics controls whether adblock matches are fused with the
// security verdict (legacy) or reported as a separate content-policy decision
// (separated). "separated" is the default so an invalid value falls back to
// it rather than silently re-fusing adblock with MALICIOUS/100.
type PolicySemantics string

const (
	PolicySemanticsSeparated PolicySemantics = "separated"
	PolicySemanticsLegacy    PolicySemantics = "legacy"
)

// NormalizePolicySemantics maps any value other than "legacy" to the
// separated default. Unknown values are tolerated instead of failing startup
// because the flag exists for emergency rollback only; refusing to boot a DNS
// resolver over it would be worse than falling forward.
func NormalizePolicySemantics(value string) PolicySemantics {
	if strings.ToLower(strings.TrimSpace(value)) == string(PolicySemanticsLegacy) {
		return PolicySemanticsLegacy
	}
	return PolicySemanticsSeparated
}

// PolicyDecision describes why a policy action was chosen, separate from the
// security verdict in Result. The adblock branch is the first producer; other
// policy paths may adopt it later.
type PolicyDecision struct {
	Action         string `json:"action"`
	Kind           string `json:"kind,omitempty"`
	Category       string `json:"category,omitempty"`
	Reason         string `json:"reason,omitempty"`
	Source         string `json:"source,omitempty"`
	AssessmentMode string `json:"assessment_mode,omitempty"`
	// MatchedRule is the normalized domain of the adblock rule that fired.
	MatchedRule string `json:"matched_rule,omitempty"`
	// MatchType is the rule scope: exact or suffix.
	MatchType string `json:"match_type,omitempty"`
	// SourceID is the digest of the blocklist source that contributed the
	// rule ("legacy" for legacy Add callers, "legacy-cache" for pre-v2 cache
	// reloads).
	SourceID string `json:"source_id,omitempty"`
	// ExceptionID is the operator-configured content exception that
	// suppressed the adblock match. Set only on adblock_exception decisions;
	// the config reason behind it is never exposed.
	ExceptionID string `json:"exception_id,omitempty"`
}

// adblockDecision builds the content-policy decision for an adblock match,
// enriched with the matched rule's provenance. Category comes from the rule
// and falls back to "unknown" — merged host lists do not carry per-entry
// evidence to justify ads vs malware classification.
func adblockDecision(assessmentMode string, rule *domaintrie.Rule) PolicyDecision {
	category := domaintrie.DefaultRuleCategory
	var matchedRule, matchType, sourceID string
	if rule != nil {
		if domaintrie.IsValidRuleCategory(rule.Category) {
			category = rule.Category
		}
		matchedRule = rule.Domain
		matchType = string(rule.Scope)
		sourceID = rule.SourceID
	}
	return PolicyDecision{
		Action:         "block",
		Kind:           "content",
		Category:       category,
		Reason:         "adblock_match",
		Source:         "adblock",
		AssessmentMode: assessmentMode,
		MatchedRule:    matchedRule,
		MatchType:      matchType,
		SourceID:       sourceID,
	}
}

const adblockAssessmentLocalDefaultBrands = "lexical_local_default_brands"

// adblockAssessmentFullPipeline marks decisions whose attached security
// Result ran the full pipeline (threat assessment plus dynamic group
// enforcement) instead of the local-only lexical path.
const adblockAssessmentFullPipeline = "full_security_pipeline"

// adblockExceptionDecision builds the content-axis decision for a suppressed
// adblock match. The action is allow on the content axis only; the overall
// Policy still comes from the security Result plus dynamic enforcement, so a
// malicious security verdict keeps the overall policy at block.
func adblockExceptionDecision(rule *domaintrie.Rule, exceptionID string) PolicyDecision {
	category := domaintrie.DefaultRuleCategory
	var matchedRule, matchType, sourceID string
	if rule != nil {
		if domaintrie.IsValidRuleCategory(rule.Category) {
			category = rule.Category
		}
		matchedRule = rule.Domain
		matchType = string(rule.Scope)
		sourceID = rule.SourceID
	}
	return PolicyDecision{
		Action:         "allow",
		Kind:           "content",
		Category:       category,
		Reason:         "adblock_exception",
		Source:         "adblock",
		AssessmentMode: adblockAssessmentFullPipeline,
		MatchedRule:    matchedRule,
		MatchType:      matchType,
		SourceID:       sourceID,
		ExceptionID:    exceptionID,
	}
}

// Policy decision kinds. "content" marks content-policy blocks,
// "admin"/"allowlist" mark operator-controlled admissions. Open string:
// new policy surfaces add kinds without a storage migration.
const (
	PolicyKindContent   = "content"
	PolicyKindAdmin     = "admin"
	PolicyKindAllowlist = "allowlist"
)

// adminPolicyDecision describes an operator override on the policy axis
// without rewriting the security verdict's meaning.
func adminPolicyDecision(action string) *PolicyDecision {
	return &PolicyDecision{
		Action:   action,
		Kind:     PolicyKindAdmin,
		Category: "custom",
		Reason:   "admin_override",
		Source:   "override",
	}
}

// allowlistPolicyDecision describes a whitelist admission.
func allowlistPolicyDecision() *PolicyDecision {
	return &PolicyDecision{
		Action:   "allow",
		Kind:     PolicyKindAllowlist,
		Category: "custom",
		Reason:   "whitelisted",
		Source:   "whitelist",
	}
}

const legacyFusedAssessmentMode = "legacy_fused_policy"

// legacyPolicyDecision marks a fused legacy adblock verdict as
// policy-derived so telemetry never mistakes it for security evidence.
// The Result wire shape stays pinned for rollback compatibility.
func legacyPolicyDecision() *PolicyDecision {
	return &PolicyDecision{
		Action:         "block",
		Kind:           PolicyKindContent,
		Category:       "unknown",
		Reason:         "legacy_policy_fused",
		Source:         "adblock",
		AssessmentMode: legacyFusedAssessmentMode,
	}
}
