package risk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"safe-zone/internal/config"
	"safe-zone/internal/domaintrie"
	"safe-zone/internal/logjson"
	"safe-zone/internal/store"
)

// Adblock control is the operator-facing switch for the adblock layer.
//
// The layer is the single largest source of blocked requests on a
// low-traffic deployment, and it is also the layer that breaks services when
// it is too broad. Operators therefore need a fast, reversible way to turn it
// off when a payment, banking or messaging endpoint stops resolving, and to
// turn it back on once the offending rule is scoped.
//
// Two switches exist and they behave differently on purpose:
//
//   - Enabled is evaluated at decision time, so flipping it takes effect on
//     the next request without a resync or a restart.
//   - MatchMode decides the rule scope assigned while parsing a source, so
//     changing it only takes effect once the rules are rebuilt. The setter
//     requests that rebuild instead of doing it inline, because a rebuild
//     parses a multi-megabyte list and must not block an API request.
//
// Both switches persist to the store, which is the same override layer the
// periodic refresh already consults, so a change survives a restart and
// reaches every node without a config push.
const (
	// envAdblockEnabled is the process-level default. The shipped default is
	// true; a store value of adblock_enabled overrides it at runtime.
	envAdblockEnabled = "SAFE_ZONE_ADBLOCK_ENABLED"

	systemConfigAdblockEnabled        = "adblock_enabled"
	systemConfigAdblockMatchMode      = "adblock_match_mode"
	systemConfigAdblockSourcePolicies = "adblock_source_policies"
)

// SystemConfigAdblockSourcePolicies is the store key holding the persisted
// per-source policy document. Exported because the API layer reads it to render
// the current value for the operator UI; writes go through
// AdblockEngine.SetAdblockSourcePoliciesJSON so validation and ordering live
// in one place.
const SystemConfigAdblockSourcePolicies = systemConfigAdblockSourcePolicies

// ErrAdblockMatchModeInvalid is returned for an unsupported match mode. The
// caller must not silently fall back: a typo that silently reverts to the
// broader mode would look like the change did not take effect.
var ErrAdblockMatchModeInvalid = errors.New("adblock match mode must be suffix or exact")

// AdblockControl is the current operator-facing adblock configuration.
type AdblockControl struct {
	Enabled   bool   `json:"enabled"`
	MatchMode string `json:"match_mode"`
}

// AdblockControl returns the effective adblock switches.
func (e *AdblockEngine) AdblockControl() AdblockControl {
	return AdblockControl{
		Enabled:   e.isAdblockEnabled(),
		MatchMode: e.currentAdblockMatchMode(),
	}
}

// SetAdblockEnabled turns adblock on or off at runtime.
//
// The value is written to the store first so a crash between the write and
// the in-memory update cannot leave a node disagreeing with the persisted
// decision. The atomic is updated immediately afterwards, which is what makes
// the change visible to the very next request.
func (e *AdblockEngine) SetAdblockEnabled(ctx context.Context, st *store.DB, enabled bool) error {
	// Fail when the store is gone rather than applying to memory only. The
	// caller checked Enabled() before it started, so reaching this point with a
	// dead store means it failed between the check and the write. Applying
	// anyway returned success for a change that would silently revert on the
	// next restart, which is the exact failure this path exists to prevent.
	if st == nil || !st.Enabled() {
		return store.ErrDisabled
	}
	value := "false"
	if enabled {
		value = "true"
	}
	if err := st.SetSystemConfig(ctx, systemConfigAdblockEnabled, value); err != nil {
		return fmt.Errorf("persist adblock_enabled: %w", err)
	}
	e.adblockEnabled.Store(enabled)
	logjson.Info("adblock enablement changed", map[string]any{
		"service": "risk",
		"enabled": enabled,
	})
	return nil
}

// ValidateAdblockSourcePoliciesJSON checks a policy document without applying
// it, so a caller that validates a whole settings document before writing
// anything can include it.
//
// SetAdblockSourcePoliciesJSON performs the same check; this exists so the
// check is not the side effect of a write.
func ValidateAdblockSourcePoliciesJSON(raw string) error {
	return validateAdblockSourcePoliciesJSON(strings.TrimSpace(raw))
}

// SetAdblockSourcePoliciesJSON validates, persists and applies a per-source
// policy document.
//
// The document is written to the store before being published in memory, and
// both happen before any rebuild is requested, so the ordering is: a node that
// has applied a change always has that change described in the store. The
// reverse order would leave a window where this node enforces a policy the
// store does not contain, and the other process would pull it back on its next
// 30-second reconcile.
//
// An empty document clears the override and falls back to
// SAFE_ZONE_ADBLOCK_SOURCE_POLICIES_JSON, which is the same contract the
// runtime already had — the missing piece was only a way to write it.
//
// The other process (dns-resolver, or a second core-api) picks the change up
// through refreshAdblockSourcePolicies within the reconcile interval, and
// AdblockStatus().SourcePoliciesFingerprint is how an operator confirms both
// nodes agree.
func (e *AdblockEngine) SetAdblockSourcePoliciesJSON(ctx context.Context, st *store.DB, raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed != "" {
		if err := validateAdblockSourcePoliciesJSON(trimmed); err != nil {
			return err
		}
	}
	// Same reasoning as SetAdblockEnabled: a store that failed between the
	// caller's check and this write must surface as a failure, not as a
	// success that a restart will undo.
	if st == nil || !st.Enabled() {
		return store.ErrDisabled
	}
	if err := st.SetSystemConfig(ctx, systemConfigAdblockSourcePolicies, trimmed); err != nil {
		return fmt.Errorf("persist adblock_source_policies: %w", err)
	}
	if trimmed == "" {
		e.SetAdblockSourcePolicies(parseAdblockSourcePolicies(config.String(envAdblockSourcePoliciesJSON, "")))
		return nil
	}
	e.SetAdblockSourcePolicies(parseAdblockSourcePolicies(trimmed))
	return nil
}

// AdblockSourcePoliciesJSON returns the currently effective per-source policy
// document, rendered from the in-memory set so it reflects what is actually in
// force rather than what was last written.
func (e *AdblockEngine) AdblockSourcePoliciesJSON() string {
	policies := e.currentAdblockSourcePolicies()
	if len(policies) == 0 {
		return ""
	}
	rendered, err := json.Marshal(policies)
	if err != nil {
		return ""
	}
	return string(rendered)
}

// SetAdblockMatchMode changes how new rules are scoped and asks the sync loop
// to rebuild the trie so the new scope is actually applied.
//
// It does not rebuild inline. A rebuild re-reads every configured source and
// is allowed to fall back to the on-disk cache, which is too slow to run
// inside an API request. The request is instead handed to the sync goroutine
// through a coalescing channel: repeated calls collapse into one rebuild.
func (e *AdblockEngine) SetAdblockMatchMode(ctx context.Context, st *store.DB, mode string) error {
	normalized := strings.ToLower(strings.TrimSpace(mode))
	if normalized != string(adblockMatchModeSuffix) && normalized != string(adblockMatchModeExact) {
		return fmt.Errorf("%w: got %q", ErrAdblockMatchModeInvalid, mode)
	}
	if st != nil && st.Enabled() {
		if err := st.SetSystemConfig(ctx, systemConfigAdblockMatchMode, normalized); err != nil {
			return fmt.Errorf("persist adblock_match_mode: %w", err)
		}
	}
	e.adblockMatchMode.Store(normalized)
	e.RequestAdblockResync()
	logjson.Info("adblock match mode changed", map[string]any{
		"service":    "risk",
		"match_mode": normalized,
	})
	return nil
}

// currentAdblockMatchMode reports the mode in force, defaulting to suffix when
// nothing has been stored yet.
func (e *AdblockEngine) currentAdblockMatchMode() string {
	if v := e.adblockMatchMode.Load(); v != nil {
		if mode, ok := v.(string); ok && mode != "" {
			return mode
		}
	}
	return string(adblockMatchModeSuffix)
}

// RequestAdblockResync asks the sync goroutine to rebuild the rule trie.
//
// The send is non-blocking on a one-slot buffered channel: if a rebuild is
// already pending the request is absorbed, and if no sync goroutine is running
// the call is a harmless no-op instead of leaking a blocked sender.
func (e *AdblockEngine) RequestAdblockResync() {
	if e.adblockResync == nil {
		return
	}
	select {
	case e.adblockResync <- struct{}{}:
	default:
	}
}

// adblockSourcePoliciesFingerprint renders a stable digest of an effective
// per-source policy set.
//
// The point is divergence detection, not secrecy. core-api and dns-resolver each
// hold their own copy, and on 2026-09-27 a policy change applied to only one of
// them left the deployment in a state that looked correct for whichever domain
// happened to be checked first. Exposing this digest lets an operator confirm
// the nodes agree instead of assuming it.
//
// Go map iteration order is randomised, so entries are sorted before hashing;
// without that the digest would differ between processes holding an identical
// configuration.
func adblockSourcePoliciesFingerprint(set adblockSourcePolicySet) string {
	sources := make([]string, 0, len(set))
	for source := range set {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	digest := sha256.New()
	for _, source := range sources {
		policy := set[source]
		_, _ = io.WriteString(digest, canonicalSourceKey(source))
		_, _ = io.WriteString(digest, "\x00")
		_, _ = io.WriteString(digest, strings.ToLower(strings.TrimSpace(policy.Category)))
		_, _ = io.WriteString(digest, "\x00")
		_, _ = io.WriteString(digest, strings.ToLower(strings.TrimSpace(policy.Scope)))
		_, _ = io.WriteString(digest, "\n")
	}
	return hex.EncodeToString(digest.Sum(nil)[:8])
}

// currentAdblockSourcePolicies returns the published policy set, or nil when
// none has been set. The returned set must not be mutated: it is the same map
// the sync goroutine reads while resolving a policy per line, so a caller
// writing to it would race.
func (e *AdblockEngine) currentAdblockSourcePolicies() adblockSourcePolicySet {
	if set := e.adblockSourcePolicies.Load(); set != nil {
		return *set
	}
	return nil
}

// SetAdblockSourcePolicies replaces the per-source policy set at runtime and
// asks the sync loop to rebuild the trie.
//
// The rebuild is required, not optional: category and scope are stamped onto
// each rule while its source is parsed, so a policy change cannot take effect
// until the rules are read again. This mirrors SetAdblockMatchMode, which has
// the same constraint, and it is the difference between a policy that is stored
// and one that is actually in force.
func (e *AdblockEngine) SetAdblockSourcePolicies(policies adblockSourcePolicySet) {
	fingerprint := adblockSourcePoliciesFingerprint(policies)
	if adblockSourcePoliciesFingerprint(e.currentAdblockSourcePolicies()) == fingerprint {
		return
	}
	published := policies
	e.adblockSourcePolicies.Store(&published)
	e.RequestAdblockResync()
	logjson.Info("adblock source policies changed; rule rebuild requested", map[string]any{
		"service":      "risk",
		"source_count": len(policies),
		"fingerprint":  fingerprint,
	})
}

// refreshAdblockSourcePolicies reconciles the persisted per-source policies
// with the process default.
//
// The store wins over the environment for the same reason: an operator who
// changes a policy at runtime must not have it silently reverted by the next
// refresh. Running this in every process is what makes a change reach
// dns-resolver without a restart. Before it existed, applying a policy meant
// restarting both services by hand, and restarting only one produced a split
// configuration that was easy to miss.
//
// A read error keeps the policy in force rather than falling back to the
// environment: the fallback would revert the operator's change, and it would
// also request a rebuild on every tick while the store stayed unhealthy.
func (e *AdblockEngine) refreshAdblockSourcePolicies(st *store.DB) {
	envPolicies := parseAdblockSourcePolicies(config.String(envAdblockSourcePoliciesJSON, ""))
	if st == nil || !st.Enabled() {
		e.SetAdblockSourcePolicies(envPolicies)
		return
	}

	raw, err := st.GetSystemConfig(context.Background(), systemConfigAdblockSourcePolicies)
	if err != nil {
		// Keep whatever is in force. Falling back to the environment here
		// silently reverted an operator's runtime change, and because
		// SetAdblockSourcePolicies also requests a rebuild, it paid for a
		// full multi-megabyte re-download and re-parse every 30 seconds
		// while the store was unhealthy.
		logjson.Warn("adblock source policy refresh failed; keeping the policy in force", map[string]any{
			"service": "risk",
			"error":   err.Error(),
		})
		return
	}
	if strings.TrimSpace(raw) == "" {
		e.SetAdblockSourcePolicies(envPolicies)
		return
	}
	e.SetAdblockSourcePolicies(parseAdblockSourcePolicies(raw))
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
func (e *AdblockEngine) AdblockStatus() AdblockStatus {
	matchMode := "suffix"
	if v := e.adblockMatchMode.Load(); v != nil {
		if mode, ok := v.(string); ok && mode != "" {
			matchMode = mode
		}
	}
	status := AdblockStatus{
		Enabled:      e.isAdblockEnabled(),
		MatchMode:    matchMode,
		LastSyncOK:   e.adblockLastSyncOK.Load(),
		SourceCount:  int(e.adblockSrcCount.Load()),
		SuccessCount: int(e.adblockOKCount.Load()),
		Exceptions:   e.AdblockExceptionStatus(),
		ShadowExact:  e.AdblockShadowExactStatus(),
	}
	if policies := e.currentAdblockSourcePolicies(); policies != nil {
		status.SourcePoliciesFingerprint = adblockSourcePoliciesFingerprint(policies)
		status.SourcePolicyCount = len(policies)
	}
	if t := e.adblockTrie.Load(); t != nil {
		status.DomainCount = t.Count()
		status.ExactRuleCount = t.ExactCount()
		status.SuffixRuleCount = t.SuffixCount()
	}
	if v := e.adblockLastSync.Load(); v != nil {
		if ts, ok := v.(time.Time); ok {
			status.LastSyncAt = ts.UTC().Format(time.RFC3339)
		}
	}
	return status
}

// AdblockTrieOverride replaces the in-memory adblock trie. Production flows
// must go through syncAdblockLists; this seam exists so transport-level
// tests (e.g. the dns-resolver /v1/policy endpoint) can pin trie contents
// without a network sync. A nil trie is normalized to an empty trie so
// Policy never observes a nil pointer.
func (e *AdblockEngine) AdblockTrieOverride(trie *domaintrie.Trie) {
	if trie == nil {
		trie = domaintrie.NewTrie()
	}
	e.adblockTrie.Store(trie)
}
