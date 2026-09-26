package risk

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"safe-zone/internal/logjson"
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

	systemConfigAdblockEnabled   = "adblock_enabled"
	systemConfigAdblockMatchMode = "adblock_match_mode"
)

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
	value := "false"
	if enabled {
		value = "true"
	}
	if s.store != nil && s.store.Enabled() {
		if err := s.store.SetSystemConfig(ctx, systemConfigAdblockEnabled, value); err != nil {
			return fmt.Errorf("persist adblock_enabled: %w", err)
		}
	}
	s.adblockEnabled.Store(enabled)
	logjson.Info("adblock enablement changed", map[string]any{
		"service": "risk",
		"enabled": enabled,
	})
	return nil
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
