package risk

import (
	"context"
	"fmt"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/logjson"
	"safe-zone/internal/netguard"
	"safe-zone/internal/store"
)

// AdblockStatus holds runtime telemetry for the adblock subsystem.
// lookupEffectiveOverride reads the operator override for a domain.
//
// The previous code assigned the error to a variable that was never read: a
// SQLite lock, a busy database, or any I/O failure silently turned "this
// domain is administratively blocked" into "evaluate it normally", with no log,
// no counter, and no signal anywhere. That is a fail-open on the one control an
// operator set deliberately, on the DNS hot path.
//
// Failing closed instead is not an option: a transient store error would then
// block every domain for every client, which is a self-inflicted outage. So the
// policy is fail-open but loud — count it, log it, and publish it.
//
// An earlier version retried once after a short pause. That was removed: SQLite
// is opened with a single connection and busy_timeout=5000, so genuine lock
// contention already resolves inside the driver and the retry almost never
// helped. Meanwhile a *sustained* store failure — a full disk, a stuck WAL — is
// exactly the case where it hurt most, adding the delay to every request on
// the hot path. Measured at 16 ms per failed request, which under load means
// thousands of goroutines sleeping to fail anyway.
//
// consecutiveOverrideFailures is what lets an operator tell "broken right now"
// from "broke three times since Tuesday", and it is reset by the first
// success.
func (s *Service) lookupEffectiveOverride(ctx context.Context, groupID int64, domain string) (*store.Override, error) {
	override, err := s.readEffectiveOverride(ctx, groupID, domain)
	if err == nil {
		if s.overrideConsecutiveFailures.Load() > 0 {
			s.overrideConsecutiveFailures.Store(0)
			s.overrideLastSuccessUnix.Store(time.Now().Unix())
		}
		return override, nil
	}

	s.overrideLookupFailures.Add(1)
	s.overrideConsecutiveFailures.Add(1)
	s.overrideLastFailureUnix.Store(time.Now().Unix())
	logjson.Warn("override lookup failed; evaluating without the operator override", map[string]any{
		"service":     "risk",
		"domain":      domain,
		"group_id":    groupID,
		"error":       err.Error(),
		"fail_open":   true,
		"consecutive": s.overrideConsecutiveFailures.Load(),
	})
	return nil, err
}

func (s *Service) OverrideLookupFailures() int64 {
	if s == nil {
		return 0
	}
	return s.overrideLookupFailures.Load()
}

// overrideReader is what the override seam must satisfy. *store.DB implements
// it directly, so production reads through the store with no wrapper.
type overrideReader interface {
	GetEffectiveOverride(ctx context.Context, groupID int64, domain string) (*store.Override, error)
}

// readEffectiveOverride is the seam the override lookup goes through. It exists
// so a test can drive the failure path directly: closing the store is not a
// usable substitute, because GetEffectiveOverride returns (nil, nil) once
// Enabled() is false rather than an error, and a cancelled context only
// exercises the caller's own context. Without this seam the failure branch of
// the hot path had no coverage at all.
func (s *Service) readEffectiveOverride(ctx context.Context, groupID int64, domain string) (*store.Override, error) {
	// Both halves are checked, and the interface type does not remove the need.
	// atomic.Pointer can only hold *T, so a pointer to a nil interface value
	// is representable, and calling through it panics on the DNS hot path.
	// Store(nil) is the only way to clear the seam.
	if injected := s.overrideLookup.Load(); injected != nil && *injected != nil {
		return (*injected).GetEffectiveOverride(ctx, groupID, domain)
	}
	return s.store.GetEffectiveOverride(ctx, groupID, domain)
}

// DecisionPipelineStatus reports fail-open degradations on the hot path.
type DecisionPipelineStatus struct {
	// OverrideLookupFailures counts every admin-override read that failed
	// since start-up. Each one means a domain the operator had blocked was
	// evaluated normally, because failing closed would block all traffic
	// instead of just this. Zero is the healthy state.
	OverrideLookupFailures int64 `json:"override_lookup_failures"`
	// OverrideConsecutiveFailures is the number that actually distinguishes
	// "currently broken" from "failed a few times since last boot": it resets
	// on the first success. Alert on this being non-zero for a sustained
	// period, not on the total.
	OverrideConsecutiveFailures int64 `json:"override_consecutive_failures"`
	// LastFailureAt and LastSuccessAt are RFC3339 stamps, empty until the
	// corresponding event has happened at least once.
	LastFailureAt string `json:"last_failure_at,omitempty"`
	LastSuccessAt string `json:"last_success_at,omitempty"`
	// OutboundProxyEnabled reports whether the address guard has been
	// deliberately switched off. With a proxy configured, netguard validates
	// the proxy's address instead of the destination's, so every outbound
	// fetch runs unchecked. That is a deliberate operator choice, but it is
	// invisible in logs alone — a transport is built per fetch for the agent
	// paths, so the one-shot warning is easy to miss. Publish it as state.
	OutboundProxyEnabled bool `json:"outbound_proxy_enabled"`
}

func (s *Service) DecisionPipelineStatus() DecisionPipelineStatus {
	if s == nil {
		return DecisionPipelineStatus{}
	}
	status := DecisionPipelineStatus{
		OverrideLookupFailures:      s.overrideLookupFailures.Load(),
		OverrideConsecutiveFailures: s.overrideConsecutiveFailures.Load(),
		OutboundProxyEnabled:        netguard.OutboundProxyEnabled(),
	}
	if unix := s.overrideLastFailureUnix.Load(); unix > 0 {
		status.LastFailureAt = time.Unix(unix, 0).UTC().Format(time.RFC3339)
	}
	if unix := s.overrideLastSuccessUnix.Load(); unix > 0 {
		status.LastSuccessAt = time.Unix(unix, 0).UTC().Format(time.RFC3339)
	}
	return status
}

type AdblockStatus struct {
	Enabled         bool   `json:"enabled"`
	MatchMode       string `json:"match_mode"`
	DomainCount     int    `json:"domain_count"`
	ExactRuleCount  int    `json:"exact_rule_count"`
	SuffixRuleCount int    `json:"suffix_rule_count"`
	LastSyncAt      string `json:"last_sync_at,omitempty"`
	LastSyncOK      bool   `json:"last_sync_ok"`
	SourceCount     int    `json:"source_count"`
	SuccessCount    int    `json:"success_count"`
	// SourcePoliciesFingerprint digests the effective per-source policy set.
	// core-api and dns-resolver each hold their own copy, so comparing this
	// value across the two is how an operator confirms the nodes agree rather
	// than assuming it. An empty set digests to a stable value, not an empty
	// string, so "no policies" is still comparable.
	SourcePoliciesFingerprint string                   `json:"source_policies_fingerprint"`
	SourcePolicyCount         int                      `json:"source_policy_count"`
	Exceptions                AdblockExceptionStatus   `json:"exceptions"`
	ShadowExact               AdblockShadowExactStatus `json:"shadow_exact"`
}

// AdblockStatus returns a snapshot of the adblock subsystem state.
func (s *Service) AdblockStatus() AdblockStatus {
	matchMode := "suffix"
	if v := s.adblockMatchMode.Load(); v != nil {
		if mode, ok := v.(string); ok && mode != "" {
			matchMode = mode
		}
	}
	status := AdblockStatus{
		Enabled:      s.isAdblockEnabled(),
		MatchMode:    matchMode,
		LastSyncOK:   s.adblockLastSyncOK.Load(),
		SourceCount:  int(s.adblockSrcCount.Load()),
		SuccessCount: int(s.adblockOKCount.Load()),
		Exceptions:   s.AdblockExceptionStatus(),
		ShadowExact:  s.AdblockShadowExactStatus(),
	}
	if policies := s.currentAdblockSourcePolicies(); policies != nil {
		status.SourcePoliciesFingerprint = adblockSourcePoliciesFingerprint(policies)
		status.SourcePolicyCount = len(policies)
	}
	if t := s.adblockTrie.Load(); t != nil {
		status.DomainCount = t.Count()
		status.ExactRuleCount = t.ExactCount()
		status.SuffixRuleCount = t.SuffixCount()
	}
	if v := s.adblockLastSync.Load(); v != nil {
		if ts, ok := v.(time.Time); ok {
			status.LastSyncAt = ts.UTC().Format(time.RFC3339)
		}
	}
	return status
}

// ListOverrides returns all local overrides, optionally filtered by action.
// ListOverrides returns the configured overrides, optionally filtered by
// action. ctx bounds the query so an operator who navigated away does not leave
// it running on the single store connection.
func (s *Service) ListOverrides(ctx context.Context, action string) ([]store.Override, error) {
	if s.store == nil {
		return nil, nil
	}
	return s.store.ListOverrides(ctx, action)
}

// UpsertOverride creates or updates a local override for a domain.
// UpsertOverride creates or updates a local override for a domain. ctx bounds
// the write; see ListOverrides.
func (s *Service) UpsertOverride(ctx context.Context, domain, action, reason string) error {
	if s.store == nil {
		return store.ErrDisabled
	}
	normalized, err := analysis.NormalizeDomain(domain)
	if err != nil {
		return fmt.Errorf("invalid domain: %w", err)
	}
	return s.store.UpsertOverride(ctx, normalized, action, reason)
}

// DeleteOverride removes a local override for a domain.
// DeleteOverride removes a local override. ctx bounds the write; see
// ListOverrides.
func (s *Service) DeleteOverride(ctx context.Context, domain string) error {
	if s.store == nil {
		return store.ErrDisabled
	}
	normalized, err := analysis.NormalizeDomain(domain)
	if err != nil {
		return fmt.Errorf("invalid domain: %w", err)
	}
	return s.store.DeleteOverride(ctx, normalized)
}

func (s *Service) ListBrands(ctx context.Context) ([]analysis.Brand, error) {
	if s == nil || s.brandStore == nil {
		return nil, fmt.Errorf("brand store not configured")
	}
	return s.brandStore.ListBrands(ctx)
}

func (s *Service) GetBrand(ctx context.Context, id int64) (analysis.Brand, error) {
	if s == nil || s.brandStore == nil {
		return analysis.Brand{}, fmt.Errorf("brand store not configured")
	}
	return s.brandStore.GetBrand(ctx, id)
}

func (s *Service) CreateBrand(ctx context.Context, brand analysis.Brand) (analysis.Brand, error) {
	if s == nil || s.brandStore == nil {
		return analysis.Brand{}, fmt.Errorf("brand store not configured")
	}
	created, err := s.brandStore.CreateBrand(ctx, brand)
	if err != nil {
		return analysis.Brand{}, err
	}
	s.bumpBrandRevision(ctx)
	return created, nil
}

func (s *Service) UpdateBrand(ctx context.Context, id int64, brand analysis.Brand) (analysis.Brand, error) {
	if s == nil || s.brandStore == nil {
		return analysis.Brand{}, fmt.Errorf("brand store not configured")
	}
	updated, err := s.brandStore.UpdateBrand(ctx, id, brand)
	if err != nil {
		return analysis.Brand{}, err
	}
	s.bumpBrandRevision(ctx)
	return updated, nil
}

func (s *Service) DeleteBrand(ctx context.Context, id int64) error {
	if s == nil || s.brandStore == nil {
		return fmt.Errorf("brand store not configured")
	}
	if err := s.brandStore.DeleteBrand(ctx, id); err != nil {
		return err
	}
	s.bumpBrandRevision(ctx)
	return nil
}
