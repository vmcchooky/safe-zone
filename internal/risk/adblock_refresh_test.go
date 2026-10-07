package risk

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"safe-zone/internal/config"
	"safe-zone/internal/store"
)

func newRefreshTestService(t *testing.T) (*Service, *store.DB) {
	t.Helper()
	t.Setenv(envAdblockEnabled, "true")
	t.Setenv(envAdblockMatchMode, string(adblockMatchModeSuffix))
	t.Setenv(envAdblockSourcePoliciesJSON, `{"https://env.test/hosts":{"category":"unknown"}}`)

	db, err := store.New(filepath.Join(t.TempDir(), "refresh.db"), 30)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	svc := NewService(Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		RedisTimeout:       10 * time.Millisecond,
		Store:              db,
		AdblockFileRoot:    t.TempDir(),
		DisableAdblockSync: true,
	})
	t.Cleanup(func() { _ = svc.Close() })
	return svc, db
}

// The store wins over the environment: an operator's runtime change must not be
// reverted by the next 30-second refresh.
func TestRefreshAppliesStoredValues(t *testing.T) {
	svc, db := newRefreshTestService(t)
	ctx := t.Context()

	if err := db.SetSystemConfig(ctx, "adblock_enabled", "false"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSystemConfig(ctx, systemConfigAdblockMatchMode, "exact"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSystemConfig(ctx, systemConfigAdblockSourcePolicies,
		`{"https://store.test/hosts":{"category":"tracking"}}`); err != nil {
		t.Fatal(err)
	}

	svc.adblock.refreshAdblockEnabled(svc.store)
	if svc.adblock.isAdblockEnabled() {
		t.Fatal("the stored adblock_enabled=false must win over the environment")
	}
	svc.adblock.refreshAdblockMatchMode(svc.store)
	if got := svc.adblock.currentAdblockMatchMode(); got != "exact" {
		t.Fatalf("stored match mode = %q, want exact", got)
	}
	svc.adblock.refreshAdblockSourcePolicies(svc.store)
	policies := svc.adblock.currentAdblockSourcePolicies()
	if _, ok := policies["https://store.test/hosts"]; !ok {
		t.Fatalf("stored source policy must win over the environment, got %v", policies)
	}
	if _, ok := policies["https://env.test/hosts"]; ok {
		t.Fatal("the environment policy must not be merged in when the store has a value")
	}
}

// With no store the environment is still the right default. The read-error fix
// must not make a value permanent when there is nothing to read.
func TestRefreshFallsBackToEnvironmentWithoutAStore(t *testing.T) {
	t.Setenv(envAdblockEnabled, "false")
	t.Setenv(envAdblockMatchMode, "exact")
	t.Setenv(envAdblockSourcePoliciesJSON, `{"https://env.test/hosts":{"category":"unknown"}}`)

	svc := NewService(Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		RedisTimeout:       10 * time.Millisecond,
		AdblockFileRoot:    t.TempDir(),
		DisableAdblockSync: true,
	})
	t.Cleanup(func() { _ = svc.Close() })

	svc.adblock.refreshAdblockEnabled(svc.store)
	if svc.adblock.isAdblockEnabled() {
		t.Fatal("without a store the environment value must be used")
	}
	svc.adblock.refreshAdblockMatchMode(svc.store)
	if got := svc.adblock.currentAdblockMatchMode(); got != "exact" {
		t.Fatalf("without a store the environment match mode must be used, got %q", got)
	}
	svc.adblock.refreshAdblockSourcePolicies(svc.store)
	if len(svc.adblock.currentAdblockSourcePolicies()) == 0 {
		t.Fatal("without a store the environment source policies must be used")
	}
}

// A disabled store is different from an unreadable one: there is genuinely no
// stored state, so the environment default is correct. Asserted explicitly so
// the two cases are not conflated by a future refactor — closing the store
// makes Enabled() false, so this is NOT the read-error path.
func TestRefreshFallsBackToEnvironmentWhenStoreIsDisabled(t *testing.T) {
	svc, db := newRefreshTestService(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	svc.adblock.refreshAdblockEnabled(svc.store)
	if !svc.adblock.isAdblockEnabled() {
		t.Fatal("a disabled store means no stored state, so the environment default applies")
	}
	svc.adblock.refreshAdblockSourcePolicies(svc.store)
	if len(svc.adblock.currentAdblockSourcePolicies()) == 0 {
		t.Fatal("a disabled store must fall back to the environment policies")
	}
}

// An unchanged policy must not request a rebuild. The request drives a full
// re-download and re-parse of every adblock source, and the old code issued one
// on every tick regardless of whether anything had changed.
func TestUnchangedSourcePoliciesDoNotRequestARebuild(t *testing.T) {
	svc, db := newRefreshTestService(t)
	if err := db.SetSystemConfig(context.Background(), systemConfigAdblockSourcePolicies,
		`{"https://store.test/hosts":{"category":"tracking"}}`); err != nil {
		t.Fatal(err)
	}

	svc.adblock.refreshAdblockSourcePolicies(svc.store)
	if !svc.drainAdblockResync() {
		t.Fatal("the first refresh applies a new policy and must request a rebuild")
	}

	for range 3 {
		svc.adblock.refreshAdblockSourcePolicies(svc.store)
	}
	if svc.drainAdblockResync() {
		t.Fatal("an unchanged policy must not request a rebuild")
	}

	// Changing the policy must request one again, otherwise the rule rebuild
	// the doc calls "required, not optional" would never happen.
	if err := db.SetSystemConfig(context.Background(), systemConfigAdblockSourcePolicies,
		`{"https://store.test/hosts":{"category":"malware"}}`); err != nil {
		t.Fatal(err)
	}
	svc.adblock.refreshAdblockSourcePolicies(svc.store)
	if !svc.drainAdblockResync() {
		t.Fatal("a changed policy must request a rebuild")
	}
}

// drainAdblockResync reports whether a rebuild request was pending, consuming
// it if so.
func (s *Service) drainAdblockResync() bool {
	if s.adblock.adblockResync == nil {
		return false
	}
	select {
	case <-s.adblock.adblockResync:
		return true
	default:
		return false
	}
}
