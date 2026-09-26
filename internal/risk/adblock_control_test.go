package risk

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"safe-zone/internal/config"
	"safe-zone/internal/domaintrie"
	"safe-zone/internal/store"
)

// newAdblockControlService builds a service wired for control tests. Adblock
// sync is disabled so no network call happens; the tests drive the switches
// and the trie directly.
//
// The package TestMain pins SAFE_ZONE_ADBLOCK_ENABLED=false to keep every
// other test hermetic, so tests that assert the shipped default opt in
// explicitly. That is the point: the default is a product decision and it is
// asserted here rather than assumed.
func newAdblockControlService(t *testing.T) (*Service, *store.DB) {
	t.Helper()

	storeDB, err := store.New(filepath.Join(t.TempDir(), "control.db"), 30)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = storeDB.Close() })

	svc := NewService(Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		Store:              storeDB,
		AdblockFileRoot:    t.TempDir(),
		PolicySemantics:    PolicySemanticsSeparated,
		DisableAdblockSync: true,
	})
	t.Cleanup(func() { _ = svc.Close() })
	return svc, storeDB
}

func TestAdblockDefaultsToEnabled(t *testing.T) {
	// TestMain turns the flag off globally, so clear it to observe the
	// shipped default that a fresh deployment gets.
	t.Setenv(envAdblockEnabled, "")
	svc, _ := newAdblockControlService(t)

	if !svc.isAdblockEnabled() {
		t.Fatal("adblock must ship enabled by default")
	}
}

func TestSetAdblockEnabledTakesEffectWithoutResync(t *testing.T) {
	t.Setenv(envAdblockEnabled, "true")
	svc, storeDB := newAdblockControlService(t)
	ctx := context.Background()

	// A rule set is already loaded, as it would be in production.
	trie := domaintrie.NewTrie()
	if !trie.AddRule(domaintrie.Rule{
		Domain:   "ads.example",
		SourceID: domaintrie.CacheV2LegacySourceID,
		Category: domaintrie.DefaultRuleCategory,
		Scope:    domaintrie.RuleScopeSuffix,
	}) {
		t.Fatal("failed to seed the adblock trie")
	}
	svc.adblockTrie.Store(trie)

	if pol := svc.Policy(ctx, "ads.example", ClientInfo{}); pol.Decision == nil || pol.Decision.Action != "block" {
		t.Fatalf("expected the loaded rule to block, got %+v", pol.Decision)
	}

	if err := svc.SetAdblockEnabled(ctx, false); err != nil {
		t.Fatalf("disable: %v", err)
	}

	// The whole point of the switch: no resync, no restart, next request only.
	if svc.isAdblockEnabled() {
		t.Fatal("expected adblock to be disabled immediately")
	}
	if pol := svc.Policy(ctx, "ads.example", ClientInfo{}); pol.Decision != nil && pol.Decision.Action == "block" {
		t.Fatalf("disabled adblock must not block, got %+v", pol.Decision)
	}

	// Turning it back on must restore the previous behaviour.
	if err := svc.SetAdblockEnabled(ctx, true); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	if pol := svc.Policy(ctx, "ads.example", ClientInfo{}); pol.Decision == nil || pol.Decision.Action != "block" {
		t.Fatalf("re-enabled adblock must block again, got %+v", pol.Decision)
	}

	// The decision must be persisted, not just held in memory.
	saved, err := storeDB.GetSystemConfig(ctx, systemConfigAdblockEnabled)
	if err != nil {
		t.Fatalf("read persisted flag: %v", err)
	}
	if saved != "true" {
		t.Fatalf("persisted adblock_enabled = %q; want true", saved)
	}
}

func TestSetAdblockMatchModeRejectsUnknownValue(t *testing.T) {
	svc, _ := newAdblockControlService(t)
	ctx := context.Background()

	before := svc.currentAdblockMatchMode()
	err := svc.SetAdblockMatchMode(ctx, "regex")
	if !errors.Is(err, ErrAdblockMatchModeInvalid) {
		t.Fatalf("expected ErrAdblockMatchModeInvalid, got %v", err)
	}
	// A rejected value must not silently fall back to the broader mode: that
	// would look like the change never applied.
	if got := svc.currentAdblockMatchMode(); got != before {
		t.Fatalf("invalid mode changed state: %q -> %q", before, got)
	}
}

func TestSetAdblockMatchModePersistsAndSurvivesRefresh(t *testing.T) {
	t.Setenv(envAdblockMatchMode, "suffix")
	svc, storeDB := newAdblockControlService(t)
	ctx := context.Background()

	if err := svc.SetAdblockMatchMode(ctx, "exact"); err != nil {
		t.Fatalf("set exact: %v", err)
	}
	if got := svc.currentAdblockMatchMode(); got != "exact" {
		t.Fatalf("match mode = %q; want exact", got)
	}

	saved, err := storeDB.GetSystemConfig(ctx, systemConfigAdblockMatchMode)
	if err != nil {
		t.Fatalf("read persisted mode: %v", err)
	}
	if saved != "exact" {
		t.Fatalf("persisted match mode = %q; want exact", saved)
	}

	// Regression guard: the periodic refresh must not revert the operator's
	// choice back to the environment default.
	svc.refreshAdblockMatchMode()
	if got := svc.currentAdblockMatchMode(); got != "exact" {
		t.Fatalf("refresh reverted operator choice: got %q, want exact", got)
	}
}

func TestRefreshAdblockMatchModeFallsBackToEnvironment(t *testing.T) {
	t.Setenv(envAdblockMatchMode, "exact")
	svc, _ := newAdblockControlService(t)

	// No persisted override: the environment seeds the mode.
	svc.refreshAdblockMatchMode()
	if got := svc.currentAdblockMatchMode(); got != "exact" {
		t.Fatalf("match mode = %q; want exact from environment", got)
	}
}

func TestRequestAdblockResyncCoalescesAndNeverBlocks(t *testing.T) {
	svc, _ := newAdblockControlService(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Far more requests than the channel can hold must not deadlock.
		for i := 0; i < 100; i++ {
			svc.RequestAdblockResync()
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RequestAdblockResync blocked the caller")
	}
}

func TestRequestAdblockResyncIsNoopWithoutChannel(t *testing.T) {
	// A service built without NewService has no channel; the call must stay
	// safe rather than panic or block.
	svc := &Service{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.RequestAdblockResync()
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RequestAdblockResync blocked on a nil channel")
	}
}
