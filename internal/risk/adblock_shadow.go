package risk

import (
	"safe-zone/internal/domaintrie"
)

// Shadow exact/suffix observation (PR3B-lite).
//
// The shadow asks what a prospective global adblock match-mode flip from
// suffix to exact would do to each current adblock hit. It is strictly
// observational: outcomes feed aggregate counters only and never influence
// Policy, PolicyDecision, the security Result, telemetry, exception matching
// or the DNS answer.

const (
	// envAdblockShadowExactEnabled names the startup-only feature flag.
	// Empty/unset (the default) disables observation.
	envAdblockShadowExactEnabled = "SAFE_ZONE_ADBLOCK_SHADOW_EXACT_ENABLED"

	// adblockShadowTargetScope is the prospective scope being observed.
	adblockShadowTargetScope = "exact"
)

// shadowExactOutcome is one primary shadow classification. Exactly one
// primary outcome is recorded per eligible adblock hit; the names use
// "content" because the security pipeline may still block independently.
type shadowExactOutcome uint8

const (
	// shadowExactStillBlock: a global-default rule hit at its own domain. A
	// prospective exact rule would still match, so content stays blocked.
	shadowExactStillBlock shadowExactOutcome = iota
	// shadowExactWouldAllow: a global-default suffix rule hit only via a
	// subdomain. A prospective exact rule would no longer match, so the
	// content block would lift (the security pipeline could still block).
	shadowExactWouldAllow
	// shadowExactPreserved: an explicit per-source or wildcard scope. The
	// prospective flip does not touch these rules, so content stays blocked.
	shadowExactPreserved
	// shadowExactUnavailable: origin unknown or legacy. No prospective
	// conclusion is drawn rather than guessing from the scope alone.
	shadowExactUnavailable
)

// classifyShadowExactOutcome maps a fired rule plus whether the canonical
// query equals the rule domain onto one primary outcome. Only
// OriginGlobalDefault moves under the prospective flip; every other known
// origin is preserved and every unknown origin is unavailable.
func classifyShadowExactOutcome(rule *domaintrie.Rule, queryIsApex bool) shadowExactOutcome {
	switch rule.Origin {
	case domaintrie.OriginGlobalDefault:
		if queryIsApex {
			return shadowExactStillBlock
		}
		return shadowExactWouldAllow
	case domaintrie.OriginSourcePolicyExact,
		domaintrie.OriginSourcePolicySuffix,
		domaintrie.OriginWildcard:
		return shadowExactPreserved
	default:
		return shadowExactUnavailable
	}
}

// shadowExactActive reports whether the current request may record a shadow
// observation: the startup-only flag is on, semantics are separated, and the
// effective global match mode is still suffix (there is nothing to observe
// once the flip it models has happened). Legacy semantics never observe.
func (s *Service) shadowExactActive() bool {
	if s == nil || !s.adblockShadowExactEnabled {
		return false
	}
	if s.policySemantics != PolicySemanticsSeparated {
		return false
	}
	mode, _ := s.adblockMatchMode.Load().(string)
	return mode == string(adblockMatchModeSuffix)
}

// observeShadowExact records at most one primary outcome for an adblock hit,
// plus a separate exception-overlap counter when a scoped exception also
// matched. It performs no I/O and never affects enforcement.
func (s *Service) observeShadowExact(detail domaintrie.MatchDetail, exceptionMatched bool) {
	if !s.shadowExactActive() || !detail.Matched {
		return
	}
	queryIsApex := detail.Query != "" && detail.Query == detail.Rule.Domain
	switch classifyShadowExactOutcome(&detail.Rule, queryIsApex) {
	case shadowExactStillBlock:
		s.adblockShadowStillBlock.Add(1)
	case shadowExactWouldAllow:
		s.adblockShadowWouldAllow.Add(1)
	case shadowExactPreserved:
		s.adblockShadowPreserved.Add(1)
	default:
		s.adblockShadowUnavailable.Add(1)
	}
	if exceptionMatched {
		s.adblockShadowExcOverlap.Add(1)
	}
}

// AdblockShadowExactStatus aggregates shadow observation state for status
// endpoints. Observations is derived as the sum of the four loaded primary
// counters so the total invariant always holds in the JSON snapshot. No field
// carries user-data cardinality: only fixed outcome names and totals.
type AdblockShadowExactStatus struct {
	Enabled                     bool   `json:"enabled"`
	Active                      bool   `json:"active"`
	TargetScope                 string `json:"target_scope"`
	Observations                uint64 `json:"observations"`
	WouldStillBlockContent      uint64 `json:"would_still_block_content"`
	WouldAllowContent           uint64 `json:"would_allow_content"`
	ExplicitScopePreservedBlock uint64 `json:"explicit_scope_preserved_block"`
	UnavailableOriginUnknown    uint64 `json:"unavailable_origin_unknown"`
	ExceptionOverlap            uint64 `json:"exception_overlap"`
}

// AdblockShadowExactStatus returns the aggregate shadow snapshot. Each
// counter is loaded once into locals; Observations is their sum.
func (s *Service) AdblockShadowExactStatus() AdblockShadowExactStatus {
	status := AdblockShadowExactStatus{TargetScope: adblockShadowTargetScope}
	if s == nil {
		return status
	}
	status.Enabled = s.adblockShadowExactEnabled
	status.Active = s.shadowExactActive()
	status.WouldStillBlockContent = s.adblockShadowStillBlock.Load()
	status.WouldAllowContent = s.adblockShadowWouldAllow.Load()
	status.ExplicitScopePreservedBlock = s.adblockShadowPreserved.Load()
	status.UnavailableOriginUnknown = s.adblockShadowUnavailable.Load()
	status.ExceptionOverlap = s.adblockShadowExcOverlap.Load()
	status.Observations = status.WouldStillBlockContent + status.WouldAllowContent +
		status.ExplicitScopePreservedBlock + status.UnavailableOriginUnknown
	return status
}
