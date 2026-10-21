package risk

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"safe-zone/internal/cache"
	"safe-zone/internal/config"
)

// dns-resolver holds its own in-memory allow list. A rollback in core-api
// bumps the durable revision, and the poll reconciler is what applies it when
// Redis is disabled. This test runs the reconciler with no Redis at all: the
// fallback must not depend on the optional cache.
func TestWhitelistReconcilerReloadsWithoutRedis(t *testing.T) {
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")
	db := newTestDB(t)
	ctx := context.Background()

	if err := db.UpdateWhitelist(ctx, []string{"before.example"}); err != nil {
		t.Fatal(err)
	}

	service := NewService(Options{
		AnalysisConfig:      config.DefaultAnalysisConfig(),
		Store:               db,
		ConfigReloadEnabled: true,
	})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
	})

	if got := service.Whitelist().Revision(); got != 1 {
		t.Fatalf("startup revision = %d, want 1", got)
	}
	if !service.Whitelist().ContainsExactIndex("before.example") {
		t.Fatal("startup index does not contain the stored domain")
	}

	if err := db.UpdateWhitelist(ctx, []string{"after.example"}); err != nil {
		t.Fatal(err)
	}

	service.reconcileWhitelist()

	if got := service.Whitelist().Revision(); got != 2 {
		t.Fatalf("reconciled revision = %d, want 2", got)
	}
	if !service.Whitelist().ContainsExactIndex("after.example") {
		t.Fatal("the reconciler did not load the new allow list")
	}
	if service.Whitelist().ContainsExactIndex("before.example") {
		t.Fatal("the reconciler kept a domain that is no longer in the store")
	}
}

// The rollback path publishes the new revision so a separate process reloads
// immediately instead of waiting for the next poll. The subscriber must apply
// a whitelist event on the shared config-reload channel.
func TestWhitelistReloadSubscriberAppliesPublishedRevision(t *testing.T) {
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")
	redisServer, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer redisServer.Close()

	db := newTestDB(t)
	ctx := context.Background()
	if err := db.UpdateWhitelist(ctx, []string{"before.example"}); err != nil {
		t.Fatal(err)
	}

	service := NewService(Options{
		AnalysisConfig:      config.DefaultAnalysisConfig(),
		Redis:               cache.NewRedis(redisServer.Addr(), "", 0),
		RedisTimeout:        time.Second,
		Store:               db,
		ConfigReloadEnabled: true,
	})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
	})

	waitForPubSubSubscribers(t, redisServer, service.configReloadChan, 1)

	if err := db.UpdateWhitelist(ctx, []string{"after.example"}); err != nil {
		t.Fatal(err)
	}
	published, err := service.PublishWhitelistReload(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !published {
		t.Fatal("expected the reload event to be published with Redis enabled")
	}

	waitForCondition(t, asyncPollBudget, func() bool {
		return service.Whitelist().Revision() == 2 && service.Whitelist().ContainsExactIndex("after.example")
	}, "expected the subscriber to apply the published whitelist revision")

	if service.Whitelist().ContainsExactIndex("before.example") {
		t.Fatal("the subscriber kept a domain that is no longer in the store")
	}
}

// A rollback must still report success when Redis is off; the response carries
// published=false so the caller knows the poll reconciler is the path.
func TestPublishWhitelistReloadWithoutRedisIsNotAnError(t *testing.T) {
	db := newTestDB(t)
	service := NewService(Options{
		AnalysisConfig:      config.DefaultAnalysisConfig(),
		Store:               db,
		ConfigReloadEnabled: true,
	})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
	})

	published, err := service.PublishWhitelistReload(context.Background(), 1)
	if err != nil {
		t.Fatalf("publishing without Redis must not be an error: %v", err)
	}
	if published {
		t.Fatal("published = true without Redis, want false")
	}
}
