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

	"safe-zone/internal/config"
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
// Service.SetAdblockSourcePoliciesJSON so validation and ordering live in one
// place.
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
func (s *Service) AdblockControl() AdblockControl {
	return AdblockControl{
		Enabled:   s.isAdblockEnabled(),
		MatchMode: s.currentAdblockMatchMode(),
	}
}

// SetAdblockEnabled turns adblock on or off at runtime.
//
// The value is written to the store first so a crash between the write and
// the in-memory update cannot leave a node disagreeing with the persisted
// decision. The atomic is updated immediately afterwards, which is what makes
// the change visible to the very next request.
func (s *Service) SetAdblockEnabled(ctx context.Context, enabled bool) error {
	// Fail when the store is gone rather than applying to memory only. The
	// caller checked Enabled() before it started, so reaching this point with a
	// dead store means it failed between the check and the write. Applying
	// anyway returned success for a change that would silently revert on the
	// next restart, which is the exact failure this path exists to prevent.
	if s.store == nil || !s.store.Enabled() {
		return store.ErrDisabled
	}
	value := "false"
	if enabled {
		value = "true"
	}
	if err := s.store.SetSystemConfig(ctx, systemConfigAdblockEnabled, value); err != nil {
		return fmt.Errorf("persist adblock_enabled: %w", err)
	}
	s.adblockEnabled.Store(enabled)
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
func (s *Service) SetAdblockSourcePoliciesJSON(ctx context.Context, raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed != "" {
		if err := validateAdblockSourcePoliciesJSON(trimmed); err != nil {
			return err
		}
	}
	// Same reasoning as SetAdblockEnabled: a store that failed between the
	// caller's check and this write must surface as a failure, not as a
	// success that a restart will undo.
	if s.store == nil || !s.store.Enabled() {
		return store.ErrDisabled
	}
	if err := s.store.SetSystemConfig(ctx, systemConfigAdblockSourcePolicies, trimmed); err != nil {
		return fmt.Errorf("persist adblock_source_policies: %w", err)
	}
	if trimmed == "" {
		s.SetAdblockSourcePolicies(parseAdblockSourcePolicies(config.String(envAdblockSourcePoliciesJSON, "")))
		return nil
	}
	s.SetAdblockSourcePolicies(parseAdblockSourcePolicies(trimmed))
	return nil
}

// AdblockSourcePoliciesJSON returns the currently effective per-source policy
// document, rendered from the in-memory set so it reflects what is actually in
// force rather than what was last written.
func (s *Service) AdblockSourcePoliciesJSON() string {
	policies := s.currentAdblockSourcePolicies()
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
func (s *Service) SetAdblockMatchMode(ctx context.Context, mode string) error {
	normalized := strings.ToLower(strings.TrimSpace(mode))
	if normalized != string(adblockMatchModeSuffix) && normalized != string(adblockMatchModeExact) {
		return fmt.Errorf("%w: got %q", ErrAdblockMatchModeInvalid, mode)
	}
	if s.store != nil && s.store.Enabled() {
		if err := s.store.SetSystemConfig(ctx, systemConfigAdblockMatchMode, normalized); err != nil {
			return fmt.Errorf("persist adblock_match_mode: %w", err)
		}
	}
	s.adblockMatchMode.Store(normalized)
	s.RequestAdblockResync()
	logjson.Info("adblock match mode changed", map[string]any{
		"service":    "risk",
		"match_mode": normalized,
	})
	return nil
}

// currentAdblockMatchMode reports the mode in force, defaulting to suffix when
// nothing has been stored yet.
func (s *Service) currentAdblockMatchMode() string {
	if v := s.adblockMatchMode.Load(); v != nil {
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
func (s *Service) RequestAdblockResync() {
	if s.adblockResync == nil {
		return
	}
	select {
	case s.adblockResync <- struct{}{}:
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
func (s *Service) currentAdblockSourcePolicies() adblockSourcePolicySet {
	if set := s.adblockSourcePolicies.Load(); set != nil {
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
func (s *Service) SetAdblockSourcePolicies(policies adblockSourcePolicySet) {
	fingerprint := adblockSourcePoliciesFingerprint(policies)
	if adblockSourcePoliciesFingerprint(s.currentAdblockSourcePolicies()) == fingerprint {
		return
	}
	published := policies
	s.adblockSourcePolicies.Store(&published)
	s.RequestAdblockResync()
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
func (s *Service) refreshAdblockSourcePolicies() {
	envPolicies := parseAdblockSourcePolicies(config.String(envAdblockSourcePoliciesJSON, ""))
	if s.store == nil || !s.store.Enabled() {
		s.SetAdblockSourcePolicies(envPolicies)
		return
	}

	raw, err := s.store.GetSystemConfig(context.Background(), systemConfigAdblockSourcePolicies)
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
		s.SetAdblockSourcePolicies(envPolicies)
		return
	}
	s.SetAdblockSourcePolicies(parseAdblockSourcePolicies(raw))
}
