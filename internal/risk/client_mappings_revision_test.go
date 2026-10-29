package risk

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"safe-zone/internal/cache"
	"safe-zone/internal/config"
	"safe-zone/internal/store"
)

// openSharedStores returns two handles on the same SQLite file, standing in
// for core-api (writer) and dns-resolver (reader) sharing the app-data volume.
func openSharedStores(t *testing.T) (writer, reader *store.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shared.db")
	writer, err := store.New(path, 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })

	reader, err = store.New(path, 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	return writer, reader
}

// dns-resolver must pick up a CIDR mapping written by core-api without a
// restart. With Redis disabled the 30s reconciler is the only signal; this
// test calls it directly.
func TestClientMappingsReconcilerReloadsWithoutRedis(t *testing.T) {
	writer, reader := openSharedStores(t)
	ctx := context.Background()

	service := NewService(Options{
		AnalysisConfig:      config.DefaultAnalysisConfig(),
		Store:               reader,
		ConfigReloadEnabled: true,
	})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
	})

	groupID, err := writer.CreateGroup(ctx, "cross-process", "", nil, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.AddMappingInt(ctx, "cidr", "10.20.0.0/16", groupID); err != nil {
		t.Fatal(err)
	}

	group, err := reader.GetGroupForClient(ctx, "10.20.5.5", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if group.ID == groupID {
		t.Fatal("reader resolved a CIDR mapping before reconciling")
	}

	service.reconcileClientMappings()

	group, err = reader.GetGroupForClient(ctx, "10.20.5.5", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if group.ID != groupID {
		t.Fatalf("after reconcile group = %d, want %d", group.ID, groupID)
	}
}

// The immediate path: core-api publishes the new revision and the resolver's
// subscriber rebuilds its own index, on the same config-reload channel used by
// the analysis config and whitelist events.
func TestClientMappingsReloadSubscriberAppliesPublishedRevision(t *testing.T) {
	redisServer, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer redisServer.Close()

	writer, reader := openSharedStores(t)
	ctx := context.Background()

	service := NewService(Options{
		AnalysisConfig:      config.DefaultAnalysisConfig(),
		Redis:               cache.NewRedis(redisServer.Addr(), "", 0),
		RedisTimeout:        time.Second,
		Store:               reader,
		ConfigReloadEnabled: true,
	})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
	})

	waitForPubSubSubscribers(t, redisServer, service.configReloadChan, 1)

	groupID, err := writer.CreateGroup(ctx, "pubsub", "", nil, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.AddMappingInt(ctx, "cidr", "10.30.0.0/16", groupID); err != nil {
		t.Fatal(err)
	}
	revision, err := writer.GetClientMappingsRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}

	published, err := service.PublishClientMappingsReload(ctx, revision)
	if err != nil {
		t.Fatal(err)
	}
	if !published {
		t.Fatal("expected the reload event to be published with Redis enabled")
	}

	waitForCondition(t, asyncPollBudget, func() bool {
		group, err := reader.GetGroupForClient(ctx, "10.30.5.5", "", false)
		return err == nil && group.ID == groupID
	}, "expected the subscriber to apply the published client mappings revision")
}

// A mapping write must still succeed when Redis is off; the caller falls back
// to the poll reconciler instead of failing the request.
func TestPublishClientMappingsReloadWithoutRedisIsNotAnError(t *testing.T) {
	_, reader := openSharedStores(t)
	service := NewService(Options{
		AnalysisConfig:      config.DefaultAnalysisConfig(),
		Store:               reader,
		ConfigReloadEnabled: true,
	})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
	})

	published, err := service.PublishClientMappingsReload(context.Background(), 1)
	if err != nil {
		t.Fatalf("publishing without Redis must not be an error: %v", err)
	}
	if published {
		t.Fatal("published = true without Redis, want false")
	}
}
