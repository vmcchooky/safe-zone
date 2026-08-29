package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/config"
	"safe-zone/internal/osint"
	"safe-zone/internal/risk"
	"safe-zone/internal/store"
)

const testThreatKey = "safe-zone:threat:feed"

const threatFeedMatchReason = "matched local threat feed"

// fakeEvidence implements the evidenceLookup contract with canned reports.
type fakeEvidence struct {
	enabled bool
	report  osint.Report
	err     error
}

func (f *fakeEvidence) Enabled() bool { return f.enabled }

func (f *fakeEvidence) Lookup(_ context.Context, domain string, _ bool) (osint.Report, error) {
	if f.err != nil {
		return osint.Report{Domain: domain}, f.err
	}
	report := f.report
	if report.Domain == "" {
		report.Domain = domain
	}
	return report, nil
}

func newBlockedReport() osint.Report {
	return osint.Report{
		ShouldBlock:   true,
		VerdictImpact: "escalate_malicious",
		Evidence: []osint.Evidence{
			{Domain: "placeholder", SourceURL: "https://gov.vn/warning", SourceType: osint.TypeOfficialWarning, Confidence: 0.95},
		},
	}
}

func newTestRedis(t *testing.T) (*miniredis.Miniredis, *cache.Redis) {
	t.Helper()
	server, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	t.Cleanup(server.Close)
	redisCache := cache.NewRedis(server.Addr(), "", 0)
	t.Cleanup(func() { _ = redisCache.Close() })
	return server, redisCache
}

func newOSINTTestTask(db *store.DB, redisCache *cache.Redis, lookup evidenceLookup, ttl time.Duration) *OSINTTask {
	return &OSINTTask{
		store:  db,
		osint:  lookup,
		redis:  redisCache,
		config: OSINTConfig{MaxPerCycle: 10, Lookback: 24 * time.Hour, ThreatKey: testThreatKey, TTL: ttl},
	}
}

func countAgentEvents(t *testing.T, db *store.DB, eventType string) []store.AgentEvent {
	t.Helper()
	events, err := db.QueryAgentEvents(context.Background(), time.Now().Add(-time.Hour), []string{eventType}, 100)
	if err != nil {
		t.Fatalf("query agent events %s: %v", eventType, err)
	}
	return events
}

// The threat feed is a ZSET scored by expiry epoch. Promotion into an
// existing ZSET must keep that type and produce a live (future) score.
func TestOSINTTaskPromotesIntoExistingZSet(t *testing.T) {
	_, redisCache := newTestRedis(t)
	db := newTestStore(t)
	domain := "nganhang-promo-existing.test"

	if _, err := redisCache.ZAdd(context.Background(), testThreatKey, redis.Z{
		Score:  float64(time.Now().Add(time.Hour).Unix()),
		Member: "already-synced.test",
	}); err != nil {
		t.Fatalf("seed existing zset: %v", err)
	}

	seedSuspiciousDomains(t, db, domain, 2)
	task := newOSINTTestTask(db, redisCache, &fakeEvidence{enabled: true, report: newBlockedReport()}, 48*time.Hour)

	if err := task.Run(context.Background()); err != nil {
		t.Fatalf("run osint task: %v", err)
	}

	keyType, err := redisCache.Type(context.Background(), testThreatKey)
	if err != nil || keyType != "zset" {
		t.Fatalf("expected key type zset, got %q (err: %v)", keyType, err)
	}
	score, err := redisCache.ZScore(context.Background(), testThreatKey, domain)
	if err != nil {
		t.Fatalf("promoted domain missing from threat zset: %v", err)
	}
	if score <= float64(time.Now().Unix()) {
		t.Fatalf("promoted score %v is not in the future", score)
	}
	if len(countAgentEvents(t, db, "threat_feed_promote")) != 1 {
		t.Fatal("expected exactly one promotion event")
	}
}

// Promotion into an empty key must create a ZSET, never a SET.
func TestOSINTTaskCreatesZSetWhenKeyMissing(t *testing.T) {
	server, redisCache := newTestRedis(t)
	if server.Exists(testThreatKey) {
		t.Fatal("precondition: threat key should not exist")
	}
	db := newTestStore(t)
	domain := "nganhang-promo-fresh.test"

	seedSuspiciousDomains(t, db, domain, 2)
	task := newOSINTTestTask(db, redisCache, &fakeEvidence{enabled: true, report: newBlockedReport()}, 48*time.Hour)

	if err := task.Run(context.Background()); err != nil {
		t.Fatalf("run osint task: %v", err)
	}

	keyType, err := redisCache.Type(context.Background(), testThreatKey)
	if err != nil || keyType != "zset" {
		t.Fatalf("expected key type zset after promotion, got %q (err: %v)", keyType, err)
	}
	if _, err := redisCache.ZScore(context.Background(), testThreatKey, domain); err != nil {
		t.Fatalf("promoted domain missing from threat zset: %v", err)
	}
}

// The promotion score must encode the configured TTL so risk.Service keeps
// matching the domain until expiry.
func TestOSINTTaskPromotionScoreMatchesConfiguredTTL(t *testing.T) {
	_, redisCache := newTestRedis(t)
	db := newTestStore(t)
	domain := "nganhang-promo-ttl.test"
	ttl := 48 * time.Hour

	seedSuspiciousDomains(t, db, domain, 2)
	task := newOSINTTestTask(db, redisCache, &fakeEvidence{enabled: true, report: newBlockedReport()}, ttl)

	if err := task.Run(context.Background()); err != nil {
		t.Fatalf("run osint task: %v", err)
	}

	score, err := redisCache.ZScore(context.Background(), testThreatKey, domain)
	if err != nil {
		t.Fatalf("promoted domain missing from threat zset: %v", err)
	}
	now := float64(time.Now().Unix())
	if score < now+float64((ttl-time.Hour).Seconds()) || score > now+float64((ttl+time.Hour).Seconds()) {
		t.Fatalf("score %v does not reflect configured TTL %v", score, ttl)
	}
}

// End to end: a promoted domain must be recognized by the risk engine via
// the threat feed, and the stale cached analysis must not shadow it.
func TestOSINTTaskPromotedDomainMatchesRiskLookup(t *testing.T) {
	_, redisCache := newTestRedis(t)
	db := newTestStore(t)
	domain := "nganhang-osint-safe.test"

	seedSuspiciousDomains(t, db, domain, 2)

	service := risk.NewService(risk.Options{
		Redis:          redisCache,
		RedisTimeout:   time.Second,
		AnalysisConfig: config.DefaultAnalysisConfig(),
		ThreatFeedKey:  testThreatKey,
	})
	defer func() { _ = service.Close() }()

	before := service.Analyze(context.Background(), domain, risk.ClientInfo{})
	for _, reason := range before.Reasons {
		if strings.Contains(reason, threatFeedMatchReason) {
			t.Fatalf("expected no threat feed match before promotion, got reasons %v", before.Reasons)
		}
	}

	task := newOSINTTestTask(db, redisCache, &fakeEvidence{enabled: true, report: newBlockedReport()}, 48*time.Hour)
	if err := task.Run(context.Background()); err != nil {
		t.Fatalf("run osint task: %v", err)
	}

	after := service.Analyze(context.Background(), domain, risk.ClientInfo{})
	if after.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected malicious verdict after promotion, got %s (reasons %v)", after.Verdict, after.Reasons)
	}
	matched := false
	for _, reason := range after.Reasons {
		if strings.Contains(reason, threatFeedMatchReason) {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("expected threat feed reason after promotion, got %v", after.Reasons)
	}
}

// A wrong-type threat key must fail the cycle loudly, must be preserved, and
// must raise a dedicated agent event for alerting.
func TestOSINTTaskWrongTypeKeyNotDeleted(t *testing.T) {
	_, redisCache := newTestRedis(t)
	db := newTestStore(t)

	if _, err := redisCache.SetAdd(context.Background(), testThreatKey, "legacy-member"); err != nil {
		t.Fatalf("seed wrong-type key: %v", err)
	}
	task := newOSINTTestTask(db, redisCache, &fakeEvidence{enabled: true, report: newBlockedReport()}, 48*time.Hour)

	err := task.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "incompatible type") {
		t.Fatalf("expected loud failure for wrong-type key, got %v", err)
	}
	keyType, typeErr := redisCache.Type(context.Background(), testThreatKey)
	if typeErr != nil || keyType != "set" {
		t.Fatalf("wrong-type key must not be deleted or retyped, got %q (err: %v)", keyType, typeErr)
	}
	if member, memberErr := redisCache.SetIsMember(context.Background(), testThreatKey, "legacy-member"); memberErr != nil || !member {
		t.Fatalf("legacy members must be preserved: %v (err: %v)", member, memberErr)
	}
	if len(countAgentEvents(t, db, "threat_feed_key_wrong_type")) != 1 {
		t.Fatal("expected a threat_feed_key_wrong_type agent event")
	}
	if len(countAgentEvents(t, db, "threat_feed_promote")) != 0 {
		t.Fatal("no promotion may be recorded against a wrong-type key")
	}
}

// A Redis failure during promotion must surface as a failure event instead
// of being swallowed, and no success event may be recorded.
func TestOSINTTaskPromotionFailureNotSwallowed(t *testing.T) {
	server, redisCache := newTestRedis(t)
	db := newTestStore(t)
	server.SetError("SIMULATED_REDIS_OUTAGE")

	task := newOSINTTestTask(db, redisCache, &fakeEvidence{enabled: true, report: newBlockedReport()}, 48*time.Hour)

	if task.promote(context.Background(), "nganhang-fail.test", 2) {
		t.Fatal("promotion must not report success when ZADD fails")
	}
	if failures := countAgentEvents(t, db, "threat_feed_promote_failed"); len(failures) != 1 {
		t.Fatalf("expected exactly one promotion failure event, got %d", len(failures))
	}
	if len(countAgentEvents(t, db, "threat_feed_promote")) != 0 {
		t.Fatal("no success event may be recorded for a failed promotion")
	}
}

// A Redis failure during the type preflight must abort the cycle with an
// error instead of proceeding blindly.
func TestOSINTTaskPreflightFailsOnRedisError(t *testing.T) {
	server, redisCache := newTestRedis(t)
	db := newTestStore(t)
	server.SetError("SIMULATED_REDIS_OUTAGE")

	task := newOSINTTestTask(db, redisCache, &fakeEvidence{enabled: true, report: newBlockedReport()}, 48*time.Hour)

	err := task.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "type check failed") {
		t.Fatalf("expected preflight redis error to surface, got %v", err)
	}
}

// OSINT reports that do not request a block must never reach the feed.
func TestOSINTTaskSkipsNonBlockingReports(t *testing.T) {
	_, redisCache := newTestRedis(t)
	db := newTestStore(t)
	domain := "nganhang-promo-clean.test"

	seedSuspiciousDomains(t, db, domain, 2)
	task := newOSINTTestTask(db, redisCache, &fakeEvidence{enabled: true, report: osint.Report{ShouldBlock: false}}, 48*time.Hour)

	if err := task.Run(context.Background()); err != nil {
		t.Fatalf("run osint task: %v", err)
	}
	if _, err := redisCache.ZScore(context.Background(), testThreatKey, domain); err == nil {
		t.Fatal("non-blocking report must not be promoted")
	}
}

// NewOSINTTask must default the promotion TTL to the feed-sync default so
// promoted and synced members expire on the same schedule.
func TestNewOSINTTaskDefaultsPromotionTTL(t *testing.T) {
	task := NewOSINTTask(nil, nil, nil, OSINTConfig{})
	if task.config.TTL != DefaultOSINTPromotionTTL {
		t.Fatalf("expected default TTL %v, got %v", DefaultOSINTPromotionTTL, task.config.TTL)
	}
	if task.config.ThreatKey != testThreatKey {
		t.Fatalf("unexpected default threat key %q", task.config.ThreatKey)
	}
	if task.config.MaxPerCycle != 50 || task.config.Lookback != 24*time.Hour {
		t.Fatalf("unexpected defaults %+v", task.config)
	}
}
