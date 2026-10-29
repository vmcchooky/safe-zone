package risk

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"safe-zone/internal/config"
	"safe-zone/internal/store"
)

// newReloadTestService builds a service over its own SQLite handle in a
// throwaway directory, with reload machinery enabled but the 30s reconciler
// parked on an hour-long ticker: the tests below drive the reconcile paths
// directly, the way one tick would. Redis is never configured, so everything
// here exercises the poll-fallback path that works without it.
func newReloadTestService(t *testing.T) (*Service, *store.DB, string) {
	t.Helper()

	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")
	// The tests import hand-written one- and two-domain allow lists; the
	// production safety floor (refuse an import that leaves fewer than 100
	// entries once a set exists) must not apply to fixtures this small.
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")
	tempDir := t.TempDir()
	serviceDB, err := store.New(filepath.Join(tempDir, "reload.db"), 30)
	if err != nil {
		t.Fatalf("open service store: %v", err)
	}

	service := NewService(Options{
		AnalysisConfig:      config.DefaultAnalysisConfig(),
		RedisTimeout:        10 * time.Millisecond,
		TTLAllowed:          time.Hour,
		TTLSuspicious:       time.Hour,
		TTLBlocked:          time.Hour,
		RecentLimit:         10,
		Store:               serviceDB,
		AdblockFileRoot:     tempDir,
		PolicySemantics:     PolicySemanticsSeparated,
		DisableAdblockSync:  true,
		ConfigReloadEnabled: true,
		// Park the reconciler goroutine; the tests call the tick bodies
		// directly so a background tick cannot race an assertion.
		ConfigReloadPollInterval: time.Hour,
	})
	t.Cleanup(func() {
		_ = service.Close()
	})
	return service, serviceDB, tempDir
}

// newWriterStore opens a second handle on the same SQLite file, standing in
// for the other process (core-api writing, dns-resolver reading, or the
// reverse). Each handle keeps its own in-memory CIDR cache, which is exactly
// the cross-process staleness the reconciler exists to repair.
func newWriterStore(t *testing.T, tempDir string) *store.DB {
	t.Helper()
	writer, err := store.New(filepath.Join(tempDir, "reload.db"), 30)
	if err != nil {
		t.Fatalf("open writer store: %v", err)
	}
	t.Cleanup(func() {
		_ = writer.Close()
	})
	return writer
}

// TestReconcilerConvergesWithoutRedis proves the documented worst-case bound:
// a stale process converges within one poll interval through the store alone.
// Every mutation below is performed through a second handle, the way the
// other process would write it.
func TestReconcilerConvergesWithoutRedis(t *testing.T) {
	service, serviceDB, tempDir := newReloadTestService(t)
	writer := newWriterStore(t, tempDir)
	ctx := context.Background()

	// Whitelist: the other process replaced the allow list.
	wantDomain := "operator-allowed.example"
	if err := writer.UpdateWhitelist(ctx, []string{wantDomain}); err != nil {
		t.Fatalf("writer replace whitelist: %v", err)
	}
	writerRevision, err := writer.GetWhitelistRevision(ctx)
	if err != nil {
		t.Fatalf("writer whitelist revision: %v", err)
	}
	if service.whitelist.Revision() == writerRevision {
		t.Fatalf("precondition: stale process already holds revision %d", writerRevision)
	}
	if service.whitelist.IsAllowed(ctx, wantDomain) {
		t.Fatal("precondition: stale process already allows the new domain")
	}

	service.reconcileWhitelist()

	if got := service.whitelist.Revision(); got != writerRevision {
		t.Fatalf("whitelist revision after reconcile = %d, want %d", got, writerRevision)
	}
	if !service.whitelist.IsAllowed(ctx, wantDomain) {
		t.Fatalf("whitelist did not converge: %q still not allowed", wantDomain)
	}

	// Analysis config: the other process persisted a changed configuration.
	storedConfig := config.DefaultAnalysisConfig()
	storedConfig.PunycodeScore++
	if err := writer.SetAnalysisConfig(ctx, storedConfig); err != nil {
		t.Fatalf("writer set analysis config: %v", err)
	}
	wantRevision := analysisConfigRevision(storedConfig.Clone())
	if service.currentConfigRevision() == wantRevision {
		t.Fatal("precondition: stale process already holds the new config revision")
	}

	service.reconcileAnalysisConfig()

	if got := service.currentConfigRevision(); got != wantRevision {
		t.Fatalf("config revision after reconcile = %q, want %q", got, wantRevision)
	}

	// Client mappings: the other process mapped a client IP to a new group.
	groupID, err := writer.CreateGroup(ctx, "reload-test-group", "", nil, false, false)
	if err != nil {
		t.Fatalf("writer create group: %v", err)
	}
	if _, err := writer.AddMappingInt(ctx, "ip", "192.0.2.77", groupID); err != nil {
		t.Fatalf("writer add mapping: %v", err)
	}
	// The durable revision lives in system_config; CIDRMappingRevision() is
	// each handle's own cache revision, which the writer handle has not
	// refreshed (it has no reconciler running — exactly the stale-process
	// situation under test).
	writerMappingRevision, err := writer.GetClientMappingsRevision(ctx)
	if err != nil {
		t.Fatalf("writer mapping revision: %v", err)
	}
	if serviceDB.CIDRMappingRevision() == writerMappingRevision {
		t.Fatal("precondition: stale process already holds the new mapping revision")
	}

	service.reconcileClientMappings()

	if got := serviceDB.CIDRMappingRevision(); got != writerMappingRevision {
		t.Fatalf("client mappings revision after reconcile = %d, want %d", got, writerMappingRevision)
	}
}

// TestPubSubReloadEventsApplyAndDeduplicate drives the subscriber's message
// handler directly, the way one delivered Redis message would be processed:
// a matching revision applies the change immediately, a stale or duplicate
// event is ignored, and malformed input is dropped without effect.
func TestPubSubReloadEventsApplyAndDeduplicate(t *testing.T) {
	service, serviceDB, tempDir := newReloadTestService(t)
	writer := newWriterStore(t, tempDir)
	ctx := context.Background()

	// Whitelist: a fresh event applies; a stale event is ignored.
	if err := writer.UpdateWhitelist(ctx, []string{"via-pubsub.example"}); err != nil {
		t.Fatalf("writer replace whitelist: %v", err)
	}
	currentRevision, err := writer.GetWhitelistRevision(ctx)
	if err != nil {
		t.Fatalf("writer whitelist revision: %v", err)
	}
	service.handleConfigReloadMessage(fmt.Sprintf(
		`{"type":"whitelist_updated","revision":"%d","source":"test","updated_at":"2026-10-29T00:00:00Z"}`,
		currentRevision))
	if !service.whitelist.IsAllowed(ctx, "via-pubsub.example") {
		t.Fatal("whitelist pub/sub event was not applied")
	}

	// The other process moves on again; the stale event for the older
	// revision must NOT pull the newer change in (it is filtered as a
	// duplicate, and the 30s reconciler remains the fallback).
	if err := writer.UpdateWhitelist(ctx, []string{"via-pubsub.example", "newer.example"}); err != nil {
		t.Fatalf("writer replace whitelist again: %v", err)
	}
	service.handleConfigReloadMessage(fmt.Sprintf(
		`{"type":"whitelist_updated","revision":"%d","source":"test","updated_at":"2026-10-29T00:00:00Z"}`,
		currentRevision))
	if service.whitelist.IsAllowed(ctx, "newer.example") {
		t.Fatal("stale pub/sub event applied a newer revision")
	}
	service.reconcileWhitelist()
	if !service.whitelist.IsAllowed(ctx, "newer.example") {
		t.Fatal("poll fallback did not converge after stale event")
	}

	// Analysis config: an event applies the stored change.
	storedConfig := config.DefaultAnalysisConfig()
	storedConfig.PunycodeScore += 2
	if err := writer.SetAnalysisConfig(ctx, storedConfig); err != nil {
		t.Fatalf("writer set analysis config: %v", err)
	}
	wantRevision := analysisConfigRevision(storedConfig.Clone())
	service.handleConfigReloadMessage(
		`{"type":"analysis_config_updated","revision":"not-checked-against-store","source":"test"}`)
	if got := service.currentConfigRevision(); got != wantRevision {
		t.Fatalf("config revision after pub/sub event = %q, want %q", got, wantRevision)
	}

	// Client mappings: an event applies, and a malformed one is a no-op.
	groupID, err := writer.CreateGroup(ctx, "pubsub-test-group", "", nil, false, false)
	if err != nil {
		t.Fatalf("writer create group: %v", err)
	}
	if _, err := writer.AddMappingInt(ctx, "client_id", "device-pubsub", groupID); err != nil {
		t.Fatalf("writer add mapping: %v", err)
	}
	mappingRevision, err := writer.GetClientMappingsRevision(ctx)
	if err != nil {
		t.Fatalf("writer mapping revision: %v", err)
	}
	service.handleConfigReloadMessage(fmt.Sprintf(
		`{"type":"client_mappings_updated","revision":"%d","source":"test"}`, mappingRevision))
	if got := serviceDB.CIDRMappingRevision(); got != mappingRevision {
		t.Fatalf("client mappings revision after pub/sub event = %d, want %d", got, mappingRevision)
	}

	revisionBefore := serviceDB.CIDRMappingRevision()
	service.handleConfigReloadMessage(`{not json`)
	service.handleConfigReloadMessage(`{"type":"whitelist_updated","revision":"not-a-number","source":"test"}`)
	service.handleConfigReloadMessage(`{"type":"unknown_event","revision":"1","source":"test"}`)
	if got := serviceDB.CIDRMappingRevision(); got != revisionBefore {
		t.Fatalf("malformed events changed state: %d -> %d", revisionBefore, got)
	}
}

// TestMatchModePollTriggersResync pins the invalidation contract found by the
// 2026-10-29 cache-invalidation audit: a match-mode value written by another
// process must reach this process within one 30s config tick AND rescope the
// running rule set, because rule scope is decided at rebuild time. Without
// the resync request, the non-writer process kept the old scope until the 12h
// source-rebuild ticker.
func TestMatchModePollTriggersResync(t *testing.T) {
	service, serviceDB, _ := newReloadTestService(t)
	ctx := context.Background()

	// Drain anything the constructor posted so the assertions below only see
	// the effects of the ticks under test. DisableAdblockSync leaves the
	// channel unconsumed, which is what makes the request observable.
	select {
	case <-service.adblock.adblockResync:
	default:
	}

	// Another process persists the mode change; this process only sees it
	// through the store.
	if err := serviceDB.SetSystemConfig(ctx, systemConfigAdblockMatchMode, "exact"); err != nil {
		t.Fatalf("persist match mode: %v", err)
	}

	service.adblock.refreshAdblockMatchMode(serviceDB)

	if got := service.adblock.currentAdblockMatchMode(); got != string(adblockMatchModeExact) {
		t.Fatalf("match mode after poll = %q, want %q", got, adblockMatchModeExact)
	}
	select {
	case <-service.adblock.adblockResync:
	default:
		t.Fatal("match mode change did not request a rule-set rebuild")
	}

	// A tick with no change behind it must not rebuild.
	service.adblock.refreshAdblockMatchMode(serviceDB)
	select {
	case <-service.adblock.adblockResync:
		t.Fatal("unchanged tick requested a rebuild")
	default:
	}
}
