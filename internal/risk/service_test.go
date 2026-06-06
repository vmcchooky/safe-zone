package risk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/config"
	"safe-zone/internal/feed"
	"safe-zone/internal/osint"
	"safe-zone/internal/store"
	"safe-zone/internal/tlsinspect"
	"safe-zone/internal/whois"
)

func TestAnalyzeWithoutRedis(t *testing.T) {
	service := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		RedisTimeout:   10 * time.Millisecond,
		TTLAllowed:     time.Hour,
		TTLSuspicious:  time.Hour,
		TTLBlocked:     time.Hour,
		RecentLimit:    10,
	})

	result := service.Analyze(context.Background(), "secure-login-wallet-example.com", ClientInfo{})
	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected malicious verdict, got %s", result.Verdict)
	}
	if result.CacheHit {
		t.Fatal("expected no cache hit when redis is disabled")
	}
	if result.AnalyzedAt == "" {
		t.Fatal("expected analyzed timestamp")
	}
}

func TestUpdateAnalysisConfigInvalidatesCachedAnalysis(t *testing.T) {
	redisServer, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer redisServer.Close()
	db, err := store.New(":memory:", 30)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultAnalysisConfig()
	cfg.LongDomainLength = 253
	cfg.EntropyThreshold = 8
	service := NewService(Options{
		Redis:          cache.NewRedis(redisServer.Addr(), "", 0),
		RedisTimeout:   time.Second,
		AnalysisConfig: cfg,
		Store:          db,
	})
	defer func() { _ = service.Close() }()

	first := service.Analyze(context.Background(), "averylongdomainname-example.com", ClientInfo{})
	if first.CacheHit {
		t.Fatal("first analysis should not hit cache")
	}

	cfg.LongDomainLength = 10
	cfg.LongDomainScore = 30
	if err := service.UpdateAnalysisConfig(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	second := service.Analyze(context.Background(), "averylongdomainname-example.com", ClientInfo{})
	if second.CacheHit {
		t.Fatal("config revision should invalidate cached analysis")
	}
	if second.Score <= first.Score {
		t.Fatalf("expected updated config to increase score: first=%d second=%d", first.Score, second.Score)
	}
}

func TestNewServiceLoadsStoredAnalysisConfig(t *testing.T) {
	db, err := store.New(":memory:", 30)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultAnalysisConfig()
	cfg.LongDomainLength = 77
	if err := db.SetAnalysisConfig(cfg); err != nil {
		t.Fatal(err)
	}

	service := NewService(Options{AnalysisConfig: config.DefaultAnalysisConfig(), Store: db})
	defer func() { _ = service.Close() }()
	if got := service.GetAnalysisConfig().LongDomainLength; got != 77 {
		t.Fatalf("expected stored config to win, got %d", got)
	}
}

func TestGetAnalysisConfigReturnsDeepClone(t *testing.T) {
	service := NewService(Options{AnalysisConfig: config.DefaultAnalysisConfig()})
	defer func() { _ = service.Close() }()

	cfg := service.GetAnalysisConfig()
	cfg.LongDomainLength = 99
	cfg.Keywords[0] = "tampered"

	got := service.GetAnalysisConfig()
	if got.LongDomainLength == 99 {
		t.Fatal("expected scalar mutation on returned config to not affect service state")
	}
	if got.Keywords[0] == "tampered" {
		t.Fatal("expected slice mutation on returned config to not affect service state")
	}
}

func TestAnalysisConfigReloadMetadataTracksSource(t *testing.T) {
	db, err := store.New(":memory:", 30)
	if err != nil {
		t.Fatal(err)
	}

	service := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		Store:          db,
	})
	defer func() { _ = service.Close() }()

	startupRevision, startupSource, startupTime := service.currentConfigReloadState()
	if startupRevision == "" {
		t.Fatal("expected startup config revision to be tracked")
	}
	if startupSource != configReloadSourceStartup {
		t.Fatalf("expected startup source %q, got %q", configReloadSourceStartup, startupSource)
	}
	if startupTime.IsZero() {
		t.Fatal("expected startup reload time to be tracked")
	}

	cfg := service.GetAnalysisConfig()
	cfg.LongDomainLength = 77
	if err := service.UpdateAnalysisConfig(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}

	revision, source, reloadedAt := service.currentConfigReloadState()
	if revision == "" {
		t.Fatal("expected updated config revision to be tracked")
	}
	if revision == startupRevision {
		t.Fatal("expected config revision to change after update")
	}
	if source != configReloadSourceLocalWrite {
		t.Fatalf("expected reload source %q, got %q", configReloadSourceLocalWrite, source)
	}
	if reloadedAt.IsZero() {
		t.Fatal("expected reload time to be tracked after update")
	}
	if reloadedAt.Before(startupTime) {
		t.Fatal("expected reload time to move forward or stay monotonic")
	}
}

func TestAnalysisConfigReloadStatusExposesCurrentState(t *testing.T) {
	service := NewService(Options{
		AnalysisConfig:           config.DefaultAnalysisConfig(),
		ConfigReloadChannel:      "safe-zone:test:analysis-config",
		ConfigReloadPollInterval: 45 * time.Second,
		ConfigReloadEnabled:      true,
		NodeRole:                 "core-api",
	})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
	})

	status := service.AnalysisConfigReloadStatus()
	if !status.Enabled {
		t.Fatal("expected config reload status to be enabled")
	}
	if status.Channel != "safe-zone:test:analysis-config" {
		t.Fatalf("expected custom channel, got %q", status.Channel)
	}
	if status.PollInterval != "45s" {
		t.Fatalf("expected poll interval 45s, got %q", status.PollInterval)
	}
	if status.NodeRole != "core-api" {
		t.Fatalf("expected node role core-api, got %q", status.NodeRole)
	}
	if status.Revision == "" {
		t.Fatal("expected config revision in status")
	}
	if status.LastReloadSource != configReloadSourceStartup {
		t.Fatalf("expected startup reload source, got %q", status.LastReloadSource)
	}
	if status.LastReloadAt == "" {
		t.Fatal("expected last reload time in status")
	}
	if status.RedisConfigured {
		t.Fatal("expected redis to be disabled in status")
	}
	if status.StoreConfigured {
		t.Fatal("expected store to be disabled in status")
	}
	if status.SubscriberActive {
		t.Fatal("expected subscriber to be inactive without redis and store")
	}
	if status.ReconcilerActive {
		t.Fatal("expected reconciler to be inactive without store")
	}
}

func TestUpdateAnalysisConfigPublishFailureDoesNotFail(t *testing.T) {
	redisServer, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	serverClosed := false
	defer func() {
		if !serverClosed {
			redisServer.Close()
		}
	}()

	db, err := store.New(":memory:", 30)
	if err != nil {
		t.Fatal(err)
	}

	service := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		Redis:          cache.NewRedis(redisServer.Addr(), "", 0),
		RedisTimeout:   50 * time.Millisecond,
		Store:          db,
	})
	defer func() {
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	redisServer.Close()
	serverClosed = true

	cfg := service.GetAnalysisConfig()
	cfg.LongDomainLength = 12
	cfg.LongDomainScore = 31
	if err := service.UpdateAnalysisConfig(context.Background(), cfg); err != nil {
		t.Fatalf("expected update to succeed when publish fails, got %v", err)
	}

	got := service.GetAnalysisConfig()
	if got.LongDomainLength != cfg.LongDomainLength || got.LongDomainScore != cfg.LongDomainScore {
		t.Fatalf("expected local config apply after publish failure, got %#v", got)
	}

	stored, err := db.GetAnalysisConfig()
	if err != nil {
		t.Fatal(err)
	}
	if stored == nil {
		t.Fatal("expected config to be persisted even when publish fails")
	}
	if stored.LongDomainLength != cfg.LongDomainLength || stored.LongDomainScore != cfg.LongDomainScore {
		t.Fatalf("expected stored config to match update, got %#v", stored)
	}

	revision, source, reloadedAt := service.currentConfigReloadState()
	if revision != analysisConfigRevision(cfg) {
		t.Fatalf("expected local revision %q, got %q", analysisConfigRevision(cfg), revision)
	}
	if source != configReloadSourceLocalWrite {
		t.Fatalf("expected local write source after publish failure, got %q", source)
	}
	if reloadedAt.IsZero() {
		t.Fatal("expected reload timestamp after publish failure")
	}
}

func TestResetAnalysisConfigPublishesReloadEvent(t *testing.T) {
	redisServer, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer redisServer.Close()

	db, err := store.New(":memory:", 30)
	if err != nil {
		t.Fatal(err)
	}

	nonDefault := config.DefaultAnalysisConfig()
	nonDefault.LongDomainLength = 77
	if err := db.SetAnalysisConfig(nonDefault); err != nil {
		t.Fatal(err)
	}

	service := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		Redis:          cache.NewRedis(redisServer.Addr(), "", 0),
		RedisTimeout:   time.Second,
		Store:          db,
	})
	defer func() {
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	ch, closeSub, err := service.redis.Subscribe(context.Background(), defaultAnalysisConfigReloadChannel)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := closeSub(); err != nil {
			t.Fatal(err)
		}
	}()

	defaults := config.DefaultAnalysisConfig()
	resetCfg, err := service.ResetAnalysisConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if analysisConfigRevision(resetCfg) != analysisConfigRevision(defaults) {
		t.Fatalf("expected reset config to return defaults, got %#v", resetCfg)
	}

	select {
	case raw, ok := <-ch:
		if !ok {
			t.Fatal("expected reset publish event before subscription closed")
		}

		var event analysisConfigReloadEvent
		if err := json.Unmarshal([]byte(raw), &event); err != nil {
			t.Fatalf("expected valid reload event JSON, got %q: %v", raw, err)
		}
		if event.Type != analysisConfigReloadEventType {
			t.Fatalf("expected event type %q, got %q", analysisConfigReloadEventType, event.Type)
		}
		if event.Revision != analysisConfigRevision(defaults) {
			t.Fatalf("expected event revision %q, got %q", analysisConfigRevision(defaults), event.Revision)
		}
		if event.UpdatedAt == "" {
			t.Fatal("expected event updated_at to be populated")
		}
		if event.Source != configReloadSourceLocalWrite {
			t.Fatalf("expected event source %q, got %q", configReloadSourceLocalWrite, event.Source)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for reset reload event")
	}

	stored, err := db.GetAnalysisConfig()
	if err != nil {
		t.Fatal(err)
	}
	if stored == nil {
		t.Fatal("expected reset config to be persisted")
	}
	if analysisConfigRevision(*stored) != analysisConfigRevision(defaults) {
		t.Fatalf("expected stored config to reset to defaults, got %#v", stored)
	}
}

func TestAnalysisConfigReloadSubscriberIgnoresCurrentRevisionEvent(t *testing.T) {
	redisServer, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer redisServer.Close()

	db, err := store.New(":memory:", 30)
	if err != nil {
		t.Fatal(err)
	}

	initialCfg := config.DefaultAnalysisConfig()
	initialCfg.LongDomainLength = 77
	if err := db.SetAnalysisConfig(initialCfg); err != nil {
		t.Fatal(err)
	}

	service := NewService(Options{
		AnalysisConfig:      config.DefaultAnalysisConfig(),
		Redis:               cache.NewRedis(redisServer.Addr(), "", 0),
		RedisTimeout:        time.Second,
		Store:               db,
		ConfigReloadEnabled: true,
	})
	defer func() {
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	waitForPubSubSubscribers(t, redisServer, service.configReloadChan, 1)

	revision, source, reloadedAt := service.currentConfigReloadState()
	if revision == "" {
		t.Fatal("expected initial revision to be tracked")
	}

	updatedCfg := service.GetAnalysisConfig()
	updatedCfg.LongDomainLength = 11
	updatedCfg.LongDomainScore = 33
	if err := db.SetAnalysisConfig(updatedCfg); err != nil {
		t.Fatal(err)
	}

	if err := service.redis.PublishJSON(context.Background(), service.configReloadChan, analysisConfigReloadEvent{
		Type:      analysisConfigReloadEventType,
		Revision:  revision,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Source:    "other-node",
	}); err != nil {
		t.Fatal(err)
	}

	time.Sleep(150 * time.Millisecond)

	gotRevision, gotSource, gotReloadedAt := service.currentConfigReloadState()
	if gotRevision != revision {
		t.Fatalf("expected same revision after self-loop event, got %q want %q", gotRevision, revision)
	}
	if gotSource != source {
		t.Fatalf("expected same reload source after self-loop event, got %q want %q", gotSource, source)
	}
	if !gotReloadedAt.Equal(reloadedAt) {
		t.Fatalf("expected self-loop event to avoid apply; reload time changed from %s to %s", reloadedAt, gotReloadedAt)
	}
	if got := service.GetAnalysisConfig(); got.LongDomainLength != initialCfg.LongDomainLength {
		t.Fatalf("expected self-loop event to avoid SQLite reload, got length %d want %d", got.LongDomainLength, initialCfg.LongDomainLength)
	}
}

func TestAnalysisConfigReloadSubscriberAppliesRemoteRevision(t *testing.T) {
	redisServer, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer redisServer.Close()

	db, err := store.New(":memory:", 30)
	if err != nil {
		t.Fatal(err)
	}

	initialCfg := config.DefaultAnalysisConfig()
	initialCfg.LongDomainLength = 77
	if err := db.SetAnalysisConfig(initialCfg); err != nil {
		t.Fatal(err)
	}

	service := NewService(Options{
		AnalysisConfig:      config.DefaultAnalysisConfig(),
		Redis:               cache.NewRedis(redisServer.Addr(), "", 0),
		RedisTimeout:        time.Second,
		Store:               db,
		ConfigReloadEnabled: true,
	})
	defer func() {
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	waitForPubSubSubscribers(t, redisServer, service.configReloadChan, 1)

	updatedCfg := service.GetAnalysisConfig()
	updatedCfg.LongDomainLength = 12
	updatedCfg.LongDomainScore = 41
	if err := db.SetAnalysisConfig(updatedCfg); err != nil {
		t.Fatal(err)
	}

	nextRevision := analysisConfigRevision(updatedCfg)
	if err := service.redis.PublishJSON(context.Background(), service.configReloadChan, analysisConfigReloadEvent{
		Type:      analysisConfigReloadEventType,
		Revision:  nextRevision,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Source:    "core-api",
	}); err != nil {
		t.Fatal(err)
	}

	waitForCondition(t, time.Second, func() bool {
		revision, source, _ := service.currentConfigReloadState()
		return revision == nextRevision && source == configReloadSourcePubSub
	}, "expected pubsub event to reload config from store")

	got := service.GetAnalysisConfig()
	if got.LongDomainLength != updatedCfg.LongDomainLength || got.LongDomainScore != updatedCfg.LongDomainScore {
		t.Fatalf("expected remote config to be applied, got %#v want %#v", got, updatedCfg)
	}
}

func TestAnalysisConfigReloadSubscriberRetriesAfterDisconnect(t *testing.T) {
	db, err := store.New(":memory:", 30)
	if err != nil {
		t.Fatal(err)
	}

	initialCfg := config.DefaultAnalysisConfig()
	initialCfg.LongDomainLength = 77
	if err := db.SetAnalysisConfig(initialCfg); err != nil {
		t.Fatal(err)
	}

	service := NewService(Options{
		AnalysisConfig: initialCfg,
		Store:          db,
	})
	service.configReloadChan = "test-analysis-config-reload"
	service.configReloadOn = true
	service.reloadBackoffMin = 10 * time.Millisecond
	service.reloadBackoffMax = 20 * time.Millisecond

	firstMessages := make(chan string)
	secondMessages := make(chan string, 1)
	var subscribeAttempts atomic.Int32
	service.subscribeReload = func(ctx context.Context, channel string) (<-chan string, func() error, error) {
		switch subscribeAttempts.Add(1) {
		case 1:
			return firstMessages, func() error { return nil }, nil
		case 2:
			return secondMessages, func() error { return nil }, nil
		default:
			<-ctx.Done()
			return nil, func() error { return nil }, ctx.Err()
		}
	}

	service.configReloadWG.Add(1)
	go service.runConfigReloadSubscriber()
	defer func() {
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	waitForCondition(t, time.Second, func() bool {
		return subscribeAttempts.Load() >= 1
	}, "expected initial subscribe attempt")

	close(firstMessages)

	updatedCfg := service.GetAnalysisConfig()
	updatedCfg.LongDomainLength = 15
	updatedCfg.LongDomainScore = 29
	if err := db.SetAnalysisConfig(updatedCfg); err != nil {
		t.Fatal(err)
	}

	waitForCondition(t, time.Second, func() bool {
		return subscribeAttempts.Load() >= 2
	}, "expected subscriber to retry after disconnect")

	eventPayload, err := json.Marshal(analysisConfigReloadEvent{
		Type:      analysisConfigReloadEventType,
		Revision:  analysisConfigRevision(updatedCfg),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Source:    "core-api",
	})
	if err != nil {
		t.Fatal(err)
	}
	secondMessages <- string(eventPayload)

	waitForCondition(t, time.Second, func() bool {
		revision, source, _ := service.currentConfigReloadState()
		return revision == analysisConfigRevision(updatedCfg) && source == configReloadSourcePubSub
	}, "expected retried subscriber to apply remote reload")
}

func TestAnalysisConfigReloadSubscriberShutdownInterruptsBackoff(t *testing.T) {
	service := NewService(Options{AnalysisConfig: config.DefaultAnalysisConfig()})
	service.configReloadChan = "test-analysis-config-reload"
	service.configReloadOn = true
	service.reloadBackoffMin = time.Second
	service.reloadBackoffMax = time.Second

	var subscribeAttempts atomic.Int32
	service.subscribeReload = func(ctx context.Context, channel string) (<-chan string, func() error, error) {
		subscribeAttempts.Add(1)
		return nil, nil, errors.New("boom")
	}

	done := make(chan struct{})
	service.configReloadWG.Add(1)
	go func() {
		service.runConfigReloadSubscriber()
		close(done)
	}()

	waitForCondition(t, time.Second, func() bool {
		return subscribeAttempts.Load() >= 1
	}, "expected subscriber to enter backoff after failure")

	startedClose := time.Now()
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case <-done:
		if time.Since(startedClose) > 250*time.Millisecond {
			t.Fatalf("expected shutdown to interrupt backoff promptly, took %s", time.Since(startedClose))
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("expected subscriber to exit promptly during shutdown")
	}
}

func TestAnalysisConfigReconcilerAppliesMissedRevision(t *testing.T) {
	db, err := store.New(":memory:", 30)
	if err != nil {
		t.Fatal(err)
	}

	initialCfg := config.DefaultAnalysisConfig()
	initialCfg.LongDomainLength = 77
	if err := db.SetAnalysisConfig(initialCfg); err != nil {
		t.Fatal(err)
	}

	service := NewService(Options{
		AnalysisConfig:           config.DefaultAnalysisConfig(),
		Store:                    db,
		ConfigReloadEnabled:      true,
		ConfigReloadPollInterval: 10 * time.Millisecond,
	})
	defer func() {
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	updatedCfg := service.GetAnalysisConfig()
	updatedCfg.LongDomainLength = 12
	updatedCfg.LongDomainScore = 41
	if err := db.SetAnalysisConfig(updatedCfg); err != nil {
		t.Fatal(err)
	}

	waitForCondition(t, time.Second, func() bool {
		revision, source, _ := service.currentConfigReloadState()
		return revision == analysisConfigRevision(updatedCfg) && source == configReloadSourceReconcile
	}, "expected reconciliation loop to self-heal missed config revision")

	got := service.GetAnalysisConfig()
	if got.LongDomainLength != updatedCfg.LongDomainLength || got.LongDomainScore != updatedCfg.LongDomainScore {
		t.Fatalf("expected reconciled config to match store, got %#v want %#v", got, updatedCfg)
	}
}

func TestAnalysisConfigReconcilerDoesNotReapplySameRevision(t *testing.T) {
	db, err := store.New(":memory:", 30)
	if err != nil {
		t.Fatal(err)
	}

	initialCfg := config.DefaultAnalysisConfig()
	initialCfg.LongDomainLength = 77
	if err := db.SetAnalysisConfig(initialCfg); err != nil {
		t.Fatal(err)
	}

	service := NewService(Options{
		AnalysisConfig:           config.DefaultAnalysisConfig(),
		Store:                    db,
		ConfigReloadEnabled:      true,
		ConfigReloadPollInterval: 10 * time.Millisecond,
	})
	defer func() {
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	updatedCfg := service.GetAnalysisConfig()
	updatedCfg.LongDomainLength = 15
	updatedCfg.LongDomainScore = 29
	if err := db.SetAnalysisConfig(updatedCfg); err != nil {
		t.Fatal(err)
	}

	waitForCondition(t, time.Second, func() bool {
		revision, source, _ := service.currentConfigReloadState()
		return revision == analysisConfigRevision(updatedCfg) && source == configReloadSourceReconcile
	}, "expected reconciliation loop to apply updated revision once")

	revision, source, reloadedAt := service.currentConfigReloadState()
	time.Sleep(75 * time.Millisecond)

	gotRevision, gotSource, gotReloadedAt := service.currentConfigReloadState()
	if gotRevision != revision {
		t.Fatalf("expected revision to stay stable after reconcile, got %q want %q", gotRevision, revision)
	}
	if gotSource != source {
		t.Fatalf("expected reload source to stay %q after redundant polls, got %q", source, gotSource)
	}
	if !gotReloadedAt.Equal(reloadedAt) {
		t.Fatalf("expected unchanged revision to avoid reapply; reload time changed from %s to %s", reloadedAt, gotReloadedAt)
	}
}

func TestPolicyBlocksOnlyMalicious(t *testing.T) {
	service := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		RedisTimeout:   10 * time.Millisecond,
		TTLAllowed:     time.Hour,
		TTLSuspicious:  time.Hour,
		TTLBlocked:     time.Hour,
		RecentLimit:    10,
	})

	blocked := service.Policy(context.Background(), "secure-login-wallet-example.com", ClientInfo{})
	if blocked.Policy != "block" {
		t.Fatalf("expected malicious policy to block, got %s", blocked.Policy)
	}

	allowed := service.Policy(context.Background(), "example.com", ClientInfo{})
	if allowed.Policy != "allow" {
		t.Fatalf("expected safe policy to allow, got %s", allowed.Policy)
	}
}

func TestCacheStatusDisabled(t *testing.T) {
	service := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond})

	status := service.CacheStatus(context.Background())
	if status.Configured {
		t.Fatal("expected cache to be unconfigured")
	}
	if status.Status != "disabled" {
		t.Fatalf("expected disabled cache status, got %s", status.Status)
	}
}

func TestThreatFeedExactMatch(t *testing.T) {
	service, closeService := newTestServiceWithRedis(t)
	defer closeService()

	if _, err := service.redis.SetAdd(context.Background(), defaultThreatFeedKey, "bad.test"); err != nil {
		t.Fatal(err)
	}

	result := service.Analyze(context.Background(), "bad.test", ClientInfo{})
	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected malicious feed verdict, got %s", result.Verdict)
	}
	if result.Score != 100 {
		t.Fatalf("expected feed score 100, got %d", result.Score)
	}
	if len(result.Reasons) != 1 || result.Reasons[0] != threatFeedReason {
		t.Fatalf("expected feed reason, got %#v", result.Reasons)
	}
}

func TestThreatFeedSuffixMatch(t *testing.T) {
	service, closeService := newTestServiceWithRedis(t)
	defer closeService()

	if _, err := service.redis.SetAdd(context.Background(), defaultThreatFeedKey, "bad.test"); err != nil {
		t.Fatal(err)
	}

	result := service.Analyze(context.Background(), "login.bad.test", ClientInfo{})
	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected malicious feed verdict, got %s", result.Verdict)
	}
	if result.Score != 100 {
		t.Fatalf("expected feed score 100, got %d", result.Score)
	}
	if len(result.Reasons) != 1 || result.Reasons[0] != threatFeedReason {
		t.Fatalf("expected feed reason, got %#v", result.Reasons)
	}
}

func TestThreatFeedTrustedBrandSuffixBypass(t *testing.T) {
	service, closeService := newTestServiceWithRedis(t)
	defer closeService()

	if _, err := service.redis.SetAdd(context.Background(), defaultThreatFeedKey, "googlevideo.com"); err != nil {
		t.Fatal(err)
	}

	result := service.Analyze(context.Background(), "r7---sn-8pxuuxa-nbo6l.googlevideo.com", ClientInfo{})
	if result.Verdict != analysis.VerdictSafe {
		t.Fatalf("expected trusted brand suffix to bypass noisy feed match, got %s with reasons %v", result.Verdict, result.Reasons)
	}
	if hasReasonContaining(result.Reasons, threatFeedReason) {
		t.Fatalf("expected no threat feed reason for trusted brand suffix, got %v", result.Reasons)
	}
}

func TestRuntimeBrandStoreUpdatesAnalyzer(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	storeDB, err := store.New(filepath.Join(t.TempDir(), "brands.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		Redis:          cache.NewRedis(server.Addr(), "", 0),
		RedisTimeout:   100 * time.Millisecond,
		TTLAllowed:     time.Hour,
		TTLSuspicious:  time.Hour,
		TTLBlocked:     time.Hour,
		BrandCacheTTL:  time.Hour,
		Store:          storeDB,
	})
	defer func() {
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	before := service.Analyze(context.Background(), "quor1x.com", ClientInfo{})
	if hasReasonContaining(before.Reasons, "quorix") {
		t.Fatalf("expected quorix not to be detected before runtime brand create, got %v", before.Reasons)
	}

	if _, err := service.CreateBrand(context.Background(), analysis.Brand{
		Name:           "quorix",
		OfficialDomain: "quorix.io.vn",
		AltDomains:     []string{"safe.quorix.io.vn"},
	}); err != nil {
		t.Fatal(err)
	}

	after := service.Analyze(context.Background(), "quor1x.com", ClientInfo{})
	if !hasReasonContaining(after.Reasons, "typosquatting of quorix") {
		t.Fatalf("expected runtime brand spoofing reason, got %v", after.Reasons)
	}
	if after.Score < config.DefaultAnalysisConfig().BrandSpoofingScore {
		t.Fatalf("expected brand spoofing score contribution, got %d", after.Score)
	}
}

func TestSuspiciousDomainEnrichmentRunsInBackgroundAndUpdatesCache(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	service := NewService(Options{
		AnalysisConfig:  config.DefaultAnalysisConfig(),
		Redis:           cache.NewRedis(server.Addr(), "", 0),
		RedisTimeout:    100 * time.Millisecond,
		TTLAllowed:      time.Hour,
		TTLSuspicious:   time.Hour,
		TTLBlocked:      time.Hour,
		EnrichEnabled:   true,
		EnrichTimeout:   time.Second,
		EnrichQueueSize: 4,
	})
	defer func() {
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	started := make(chan struct{})
	release := make(chan struct{})
	service.enrichmentLookup = func(ctx context.Context, domain string) enrichmentSignals {
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
			return enrichmentSignals{}
		}
		return enrichmentSignals{
			TLS:   tlsinspect.Result{Score: 20, Reasons: []string{"tls: test background signal"}},
			WHOIS: whois.Result{Score: 15, Reasons: []string{"whois: test background signal"}},
		}
	}

	first := service.Analyze(context.Background(), "secure-login-example.com", ClientInfo{})
	if first.CacheHit {
		t.Fatal("expected first request to be a cache miss")
	}
	if hasReasonContaining(first.Reasons, "tls:") || hasReasonContaining(first.Reasons, "whois:") {
		t.Fatalf("expected preliminary result without enrichment, got %v", first.Reasons)
	}
	if first.Score >= 70 {
		t.Fatalf("expected preliminary suspicious score before enrichment, got %d", first.Score)
	}

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("expected background enrichment worker to start")
	}
	close(release)

	var second Analysis
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		second = service.Analyze(context.Background(), "secure-login-example.com", ClientInfo{})
		if second.CacheHit && hasReasonContaining(second.Reasons, "tls: test background signal") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !second.CacheHit {
		t.Fatal("expected second request to use cache")
	}
	if !hasReasonContaining(second.Reasons, "tls: test background signal") ||
		!hasReasonContaining(second.Reasons, "whois: test background signal") {
		t.Fatalf("expected cached enriched reasons, got %v", second.Reasons)
	}
	if second.Score <= first.Score {
		t.Fatalf("expected enriched score to increase, first=%d second=%d", first.Score, second.Score)
	}
}

func TestFeedRevisionInvalidatesCachedAnalysis(t *testing.T) {
	service, closeService := newTestServiceWithRedis(t)
	defer closeService()

	first := service.Analyze(context.Background(), "fresh-safe-example.test", ClientInfo{})
	if first.CacheHit {
		t.Fatal("expected first analysis to be uncached")
	}
	if first.Verdict != analysis.VerdictSafe {
		t.Fatalf("expected initial lexical safe verdict, got %s", first.Verdict)
	}

	second := service.Analyze(context.Background(), "fresh-safe-example.test", ClientInfo{})
	if !second.CacheHit {
		t.Fatal("expected second analysis to hit cache before feed revision changes")
	}

	if _, err := service.redis.SetAdd(context.Background(), defaultThreatFeedKey, "fresh-safe-example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.redis.Increment(context.Background(), feed.RevisionKey(defaultThreatFeedKey)); err != nil {
		t.Fatal(err)
	}

	third := service.Analyze(context.Background(), "fresh-safe-example.test", ClientInfo{})
	if third.CacheHit {
		t.Fatal("expected cached safe result to be invalidated after feed revision bump")
	}
	if third.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected feed match after revision bump, got %s", third.Verdict)
	}

	fourth := service.Analyze(context.Background(), "fresh-safe-example.test", ClientInfo{})
	if !fourth.CacheHit {
		t.Fatal("expected updated feed result to be cached after re-analysis")
	}
	if fourth.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected cached malicious verdict, got %s", fourth.Verdict)
	}
}

func TestAnalysisRevisionInvalidatesLegacySafeCache(t *testing.T) {
	service, closeService := newTestServiceWithRedis(t)
	defer closeService()

	cacheKey := "safe-zone:analysis:dichvucong-vn.com"
	if err := service.redis.SetJSON(context.Background(), cacheKey, analysis.Result{
		Domain:     "dichvucong-vn.com",
		Verdict:    analysis.VerdictSafe,
		Confidence: 0.45,
		Score:      0,
		Reasons:    []string{"legacy cached safe"},
		Category:   "uncategorized",
	}, time.Hour); err != nil {
		t.Fatal(err)
	}

	result := service.Analyze(context.Background(), "dichvucong-vn.com", ClientInfo{})
	if result.CacheHit {
		t.Fatal("expected legacy cached safe result to be ignored after analysis revision change")
	}
	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected re-analysis to mark malicious, got %s with reasons %v", result.Verdict, result.Reasons)
	}
}

func TestAIClientSyncRespectsCooldownAndDisablesDeletedDBKey(t *testing.T) {
	service := newTestServiceWithStore(t)

	if err := service.StoreDB().SetSystemConfig("gemini_api_key", "first-key"); err != nil {
		t.Fatal(err)
	}
	if client := service.AIClient(); client == nil || !client.Enabled() {
		t.Fatal("expected AI client to be enabled after syncing DB key")
	}
	if service.cachedGeminiKey != "first-key" {
		t.Fatalf("expected cached key to be first-key, got %q", service.cachedGeminiKey)
	}

	if err := service.StoreDB().SetSystemConfig("gemini_api_key", "second-key"); err != nil {
		t.Fatal(err)
	}
	_ = service.AIClient()
	if service.cachedGeminiKey != "first-key" {
		t.Fatalf("expected cooldown to keep cached key unchanged, got %q", service.cachedGeminiKey)
	}

	service.aiMu.Lock()
	service.lastGeminiKeySync = time.Now().Add(-geminiKeySyncCooldown - time.Second)
	service.aiMu.Unlock()

	if client := service.AIClient(); client == nil || !client.Enabled() {
		t.Fatal("expected AI client to remain enabled after refreshing DB key")
	}
	if service.cachedGeminiKey != "second-key" {
		t.Fatalf("expected cached key to refresh after cooldown, got %q", service.cachedGeminiKey)
	}

	if err := service.StoreDB().SetSystemConfig("gemini_api_key", ""); err != nil {
		t.Fatal(err)
	}
	service.aiMu.Lock()
	service.lastGeminiKeySync = time.Now().Add(-geminiKeySyncCooldown - time.Second)
	service.aiMu.Unlock()

	if client := service.AIClient(); client != nil {
		t.Fatalf("expected AI client to be disabled after DB key removal, got %#v", client)
	}
	if service.cachedGeminiKey != "" {
		t.Fatalf("expected cached key to be cleared, got %q", service.cachedGeminiKey)
	}
}

func TestPolicyBlocksVietnamPublicServiceAbuseByDefault(t *testing.T) {
	service := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		RedisTimeout:   10 * time.Millisecond,
		TTLAllowed:     time.Hour,
		TTLSuspicious:  time.Hour,
		TTLBlocked:     time.Hour,
		RecentLimit:    10,
	})

	policy := service.Policy(context.Background(), "dichvucong-vn.com", ClientInfo{})
	if policy.Policy != "block" {
		t.Fatalf("expected default policy to block dichvucong-vn.com, got %s", policy.Policy)
	}
	if policy.Result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected malicious verdict, got %s", policy.Result.Verdict)
	}
}

func TestAnalyzeEscalatesWithOSINTEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<title>Cảnh báo</title>baohiem-online.com là trang giả mạo, lừa đảo.`))
	}))
	defer server.Close()

	service := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		RedisTimeout:   10 * time.Millisecond,
		TTLAllowed:     time.Hour,
		TTLSuspicious:  time.Hour,
		TTLBlocked:     time.Hour,
		RecentLimit:    10,
		OSINT: osint.NewService(osint.Options{
			Enabled:             true,
			Sources:             []string{server.URL},
			TrustedDomains:      []string{server.URL},
			AllowPrivateSources: true,
			CacheTTL:            time.Hour,
		}),
	})

	result := service.AnalyzeWithOptions(context.Background(), "baohiem-online.com", ClientInfo{}, AnalyzeOptions{IncludeEvidence: true})
	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected osint evidence to escalate to malicious, got %s with reasons %v", result.Verdict, result.Reasons)
	}
	if result.Category != "phishing" {
		t.Fatalf("expected phishing category, got %s", result.Category)
	}
	if len(result.Evidence) == 0 {
		t.Fatal("expected evidence in analysis response")
	}
}

func TestPolicyUsesCachedOSINTEvidenceOnly(t *testing.T) {
	sourceHits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceHits++
		_, _ = w.Write([]byte(`baohiem-online.com là website giả mạo, lừa đảo.`))
	}))
	defer server.Close()

	service := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		RedisTimeout:   10 * time.Millisecond,
		TTLAllowed:     time.Hour,
		TTLSuspicious:  time.Hour,
		TTLBlocked:     time.Hour,
		RecentLimit:    10,
		OSINT: osint.NewService(osint.Options{
			Enabled:             true,
			Sources:             []string{server.URL},
			TrustedDomains:      []string{server.URL},
			AllowPrivateSources: true,
			CacheTTL:            time.Hour,
		}),
	})

	firstPolicy := service.Policy(context.Background(), "baohiem-online.com", ClientInfo{})
	if sourceHits != 0 {
		t.Fatalf("policy must not perform live osint lookup, got %d source hits", sourceHits)
	}
	if firstPolicy.Policy != "allow" {
		t.Fatalf("expected first policy to allow without cached evidence, got %s", firstPolicy.Policy)
	}

	analysisResult := service.Analyze(context.Background(), "baohiem-online.com", ClientInfo{})
	if analysisResult.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected analyze to cache malicious osint result, got %s", analysisResult.Verdict)
	}

	sourceHits = 0
	secondPolicy := service.Policy(context.Background(), "baohiem-online.com", ClientInfo{})
	if sourceHits != 0 {
		t.Fatalf("policy must use cached evidence only, got %d source hits", sourceHits)
	}
	if secondPolicy.Policy != "block" {
		t.Fatalf("expected policy to block cached osint malicious verdict, got %s", secondPolicy.Policy)
	}
}

func TestThreatFeedInvalidDomain(t *testing.T) {
	service, closeService := newTestServiceWithRedis(t)
	defer closeService()

	result := service.Analyze(context.Background(), "bad test", ClientInfo{})
	if result.Verdict != analysis.VerdictInvalid {
		t.Fatalf("expected invalid verdict, got %s", result.Verdict)
	}
}

func TestThreatFeedRedisDisabledFailOpen(t *testing.T) {
	service := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		RedisTimeout:   10 * time.Millisecond,
		TTLAllowed:     time.Hour,
		TTLSuspicious:  time.Hour,
		TTLBlocked:     time.Hour,
		RecentLimit:    10,
	})

	result := service.Analyze(context.Background(), "example.com", ClientInfo{})
	if result.Verdict != analysis.VerdictSafe {
		t.Fatalf("expected lexical safe result when redis is disabled, got %s", result.Verdict)
	}
}

func TestLocalAIRefinesSuspiciousDomain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1beta/models/gemini-2.5-flash-lite:generateContent" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("key"); got != "test-key" {
			t.Fatalf("expected api key in query, got %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"candidates": []map[string]any{{
				"content": map[string]any{
					"parts": []map[string]string{{"text": `{"verdict":"MALICIOUS","confidence":0.93,"reason":"local ai escalation"}`}},
				},
			}},
		})
	}))
	defer server.Close()

	service := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		RedisTimeout:   10 * time.Millisecond,
		TTLAllowed:     time.Hour,
		TTLSuspicious:  time.Hour,
		TTLBlocked:     time.Hour,
		RecentLimit:    10,
		GeminiBaseURL:  server.URL + "/v1beta",
		GeminiAPIKey:   "test-key",
		GeminiModel:    "gemini-2.5-flash-lite",
		GeminiTimeout:  time.Second,
	})

	result := service.Analyze(context.Background(), "secure-login-example.com", ClientInfo{})
	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected local AI escalation to malicious, got %s", result.Verdict)
	}
	if result.Score < 85 {
		t.Fatalf("expected score to be upgraded, got %d", result.Score)
	}
}

func TestLocalAIFailureFailsOpen(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"candidates":[]}`))
	}))
	defer server.Close()

	service := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		RedisTimeout:   10 * time.Millisecond,
		TTLAllowed:     time.Hour,
		TTLSuspicious:  time.Hour,
		TTLBlocked:     time.Hour,
		RecentLimit:    10,
		GeminiBaseURL:  server.URL + "/v1beta",
		GeminiAPIKey:   "test-key",
		GeminiModel:    "gemini-2.5-flash-lite",
		GeminiTimeout:  time.Second,
	})

	result := service.Analyze(context.Background(), "secure-login-example.com", ClientInfo{})
	if result.Verdict != analysis.VerdictSuspicious {
		t.Fatalf("expected suspicious result to remain unchanged on ai failure, got %s", result.Verdict)
	}
}

func TestLocalAIFailureFailsOpenFromEnv(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1beta/models/gemini-2.5-flash-lite:generateContent" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"message":"upstream error"}}`))
	}))
	defer server.Close()

	t.Setenv("SAFE_ZONE_REDIS_ADDR", "")
	t.Setenv("SAFE_ZONE_GEMINI_BASE_URL", server.URL+"/v1beta")
	t.Setenv("SAFE_ZONE_GEMINI_API_KEY", "test-key")
	t.Setenv("SAFE_ZONE_GEMINI_MODEL", "gemini-2.5-flash-lite")
	t.Setenv("SAFE_ZONE_GEMINI_TIMEOUT_MS", "100")

	service := NewServiceFromEnv()
	result := service.Analyze(context.Background(), "secure-login-example.com", ClientInfo{})
	if result.Verdict != analysis.VerdictSuspicious {
		t.Fatalf("expected suspicious result to remain unchanged on ai error, got %s", result.Verdict)
	}
}

func TestLocalAITimeoutFailsOpenFromEnv(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1beta/models/gemini-2.5-flash-lite:generateContent" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"{\"verdict\":\"MALICIOUS\",\"confidence\":0.9,\"reason\":\"late response\"}"}]}}]}`))
	}))
	defer server.Close()

	t.Setenv("SAFE_ZONE_REDIS_ADDR", "")
	t.Setenv("SAFE_ZONE_GEMINI_BASE_URL", server.URL+"/v1beta")
	t.Setenv("SAFE_ZONE_GEMINI_API_KEY", "test-key")
	t.Setenv("SAFE_ZONE_GEMINI_MODEL", "gemini-2.5-flash-lite")
	t.Setenv("SAFE_ZONE_GEMINI_TIMEOUT_MS", "50")

	service := NewServiceFromEnv()
	result := service.Analyze(context.Background(), "secure-login-example.com", ClientInfo{})
	if result.Verdict != analysis.VerdictSuspicious {
		t.Fatalf("expected suspicious result to remain unchanged on ai timeout, got %s", result.Verdict)
	}
}

func TestNewServiceFromEnvForRoleSetsDefaultNodeRole(t *testing.T) {
	t.Setenv("SAFE_ZONE_REDIS_ADDR", "")
	t.Setenv("SAFE_ZONE_SQLITE_PATH", filepath.Join(t.TempDir(), "env.db"))

	service := NewServiceFromEnvForRole("dns-resolver")
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
	})

	status := service.AnalysisConfigReloadStatus()
	if status.NodeRole != "dns-resolver" {
		t.Fatalf("expected node role dns-resolver, got %q", status.NodeRole)
	}
}

func newTestServiceWithRedis(t *testing.T) (*Service, func()) {
	t.Helper()

	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}

	service := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		Redis:          cache.NewRedis(server.Addr(), "", 0),
		RedisTimeout:   100 * time.Millisecond,
		TTLAllowed:     time.Hour,
		TTLSuspicious:  time.Hour,
		TTLBlocked:     time.Hour,
		RecentLimit:    10,
	})

	return service, func() {
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
		server.Close()
	}
}

func waitForPubSubSubscribers(t *testing.T, server *miniredis.Miniredis, channel string, want int) {
	t.Helper()

	waitForCondition(t, time.Second, func() bool {
		return server.PubSubNumSub(channel)[channel] == want
	}, "expected pubsub subscriber count to match")
}

func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool, description string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	if condition() {
		return
	}
	t.Fatal(description)
}

func hasReasonContaining(reasons []string, needle string) bool {
	for _, reason := range reasons {
		if strings.Contains(reason, needle) {
			return true
		}
	}
	return false
}

func newTestServiceWithStore(t *testing.T) *Service {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	storeDB, err := store.New(dbPath, 30)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}

	service := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		RedisTimeout:   10 * time.Millisecond,
		TTLAllowed:     time.Hour,
		TTLSuspicious:  time.Hour,
		TTLBlocked:     time.Hour,
		RecentLimit:    10,
		Store:          storeDB,
	})

	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
	})

	return service
}

func TestOverrideBlocksDomain(t *testing.T) {
	service := newTestServiceWithStore(t)

	if err := service.UpsertOverride("evil.test", "block", "phishing"); err != nil {
		t.Fatalf("upsert failed: %v", err)
	}

	result := service.Analyze(context.Background(), "evil.test", ClientInfo{})
	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected malicious verdict from block override, got %s", result.Verdict)
	}
	if result.Score != 100 {
		t.Fatalf("expected score 100, got %d", result.Score)
	}
	if len(result.Reasons) == 0 || !strings.HasPrefix(result.Reasons[0], "admin override: block") {
		t.Fatalf("expected admin override block reason, got %v", result.Reasons)
	}
}

func TestOverrideAllowsDomain(t *testing.T) {
	service := newTestServiceWithStore(t)

	if err := service.UpsertOverride("trusted.test", "allow", "internal service"); err != nil {
		t.Fatalf("upsert failed: %v", err)
	}

	result := service.Analyze(context.Background(), "trusted.test", ClientInfo{})
	if result.Verdict != analysis.VerdictSafe {
		t.Fatalf("expected safe verdict from allow override, got %s", result.Verdict)
	}
	if result.Score != 0 {
		t.Fatalf("expected score 0, got %d", result.Score)
	}
	if len(result.Reasons) == 0 || !strings.HasPrefix(result.Reasons[0], "admin override: allow") {
		t.Fatalf("expected admin override allow reason, got %v", result.Reasons)
	}
}

func TestOverrideBeatsWhitelist(t *testing.T) {
	// Write a temp whitelist file so that "whitelisted.test" is whitelisted.
	whitelistPath := filepath.Join(t.TempDir(), "whitelist.txt")
	if err := os.WriteFile(whitelistPath, []byte("whitelisted.test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAFE_ZONE_FEED_FILE_ROOT", filepath.Dir(whitelistPath))

	dbPath := filepath.Join(t.TempDir(), "test.db")
	storeDB, err := store.New(dbPath, 30)
	if err != nil {
		t.Fatal(err)
	}

	service := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		RedisTimeout:   10 * time.Millisecond,
		TTLAllowed:     time.Hour,
		TTLSuspicious:  time.Hour,
		TTLBlocked:     time.Hour,
		RecentLimit:    10,
		WhitelistPath:  whitelistPath,
		Store:          storeDB,
	})
	t.Cleanup(func() { service.Close() })

	// Without override, should be whitelisted (SAFE).
	result := service.Analyze(context.Background(), "whitelisted.test", ClientInfo{})
	if result.Verdict != analysis.VerdictSafe {
		t.Fatalf("expected whitelisted domain to be safe, got %s", result.Verdict)
	}

	// Add a block override — this should win over the whitelist.
	if err := service.UpsertOverride("whitelisted.test", "block", "compromised"); err != nil {
		t.Fatal(err)
	}

	result = service.Analyze(context.Background(), "whitelisted.test", ClientInfo{})
	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected block override to beat whitelist, got %s", result.Verdict)
	}
}

func TestStoreNilFailOpen(t *testing.T) {
	// Service without store should work normally (fail-open).
	service := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		RedisTimeout:   10 * time.Millisecond,
		TTLAllowed:     time.Hour,
		TTLSuspicious:  time.Hour,
		TTLBlocked:     time.Hour,
		RecentLimit:    10,
		Store:          nil,
	})

	result := service.Analyze(context.Background(), "example.com", ClientInfo{})
	if result.Verdict != analysis.VerdictSafe {
		t.Fatalf("expected safe verdict without store, got %s", result.Verdict)
	}
}

func TestDeleteOverrideThenAnalyze(t *testing.T) {
	service := newTestServiceWithStore(t)

	if err := service.UpsertOverride("temp.test", "block", "temp block"); err != nil {
		t.Fatal(err)
	}

	// Should be blocked.
	result := service.Analyze(context.Background(), "temp.test", ClientInfo{})
	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected malicious, got %s", result.Verdict)
	}

	// Remove override.
	if err := service.DeleteOverride("temp.test"); err != nil {
		t.Fatal(err)
	}

	// Should go through normal pipeline now.
	result = service.Analyze(context.Background(), "temp.test", ClientInfo{})
	if result.Verdict == analysis.VerdictMalicious {
		t.Fatal("expected override removal to restore normal pipeline")
	}
}

func TestClientGroupPolicyDynamicEnforcement(t *testing.T) {
	service := newTestServiceWithStore(t)
	db := service.StoreDB()

	// 1. Tạo các Client Group
	// CreateGroup(name, description string, blockCategories []string, strictPhishing, strictMalware bool)
	kidsGroupID, err := db.CreateGroup("kids", "Kids group", []string{"social_media", "adult"}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	devsGroupID, err := db.CreateGroup("devs", "Devs group", []string{}, false, false)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Map IPs
	if _, err := db.AddMappingInt("ip", "192.168.1.50", kidsGroupID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddMappingInt("ip", "192.168.1.100", devsGroupID); err != nil {
		t.Fatal(err)
	}

	kidsClient := ClientInfo{IP: "192.168.1.50"}
	devsClient := ClientInfo{IP: "192.168.1.100"}

	// 3. Test Policy chặn mạng xã hội cho nhóm kids
	pKidsSoc := service.Policy(context.Background(), "facebook.com", kidsClient)
	if pKidsSoc.Policy != "block" {
		t.Fatalf("expected facebook.com to be blocked for kids group, got %s", pKidsSoc.Policy)
	}
	if pKidsSoc.Result.Category != "social_media" {
		t.Fatalf("expected category social_media, got %s", pKidsSoc.Result.Category)
	}

	// Test Policy cho phép mạng xã hội cho nhóm devs
	pDevsSoc := service.Policy(context.Background(), "facebook.com", devsClient)
	if pDevsSoc.Policy != "allow" {
		t.Fatalf("expected facebook.com to be allowed for devs group, got %s", pDevsSoc.Policy)
	}

	// 4. Test Policy chặn adult content cho nhóm kids
	pKidsAdult := service.Policy(context.Background(), "xvideos.porn", kidsClient)
	if pKidsAdult.Policy != "block" {
		t.Fatalf("expected xvideos.porn to be blocked for kids group, got %s", pKidsAdult.Policy)
	}
	if pKidsAdult.Result.Category != "adult" {
		t.Fatalf("expected category adult, got %s", pKidsAdult.Result.Category)
	}

	// 5. Test Group Override đè lên chính sách bình thường
	// Thêm group override cho group devs: block facebook.com
	if err := db.UpsertGroupOverride(devsGroupID, "facebook.com", "block", "focus time"); err != nil {
		t.Fatal(err)
	}

	pDevsSocPostOverride := service.Policy(context.Background(), "facebook.com", devsClient)
	if pDevsSocPostOverride.Policy != "block" {
		t.Fatalf("expected facebook.com to be blocked for devs after override, got %s", pDevsSocPostOverride.Policy)
	}
	if len(pDevsSocPostOverride.Result.Reasons) == 0 || !strings.Contains(pDevsSocPostOverride.Result.Reasons[0], "admin override") {
		t.Fatalf("expected admin override reason, got %v", pDevsSocPostOverride.Result.Reasons)
	}
}
