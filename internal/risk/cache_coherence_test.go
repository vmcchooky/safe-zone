package risk

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/config"
)

// M1: a delayed worker must not overwrite a newer cached evaluation with
// its stale job snapshot. The newer OSINT verdict survives; the worker
// drops its write.
func TestEnrichmentWorkerSkipsNewerCachedEvaluation(t *testing.T) {
	t.Setenv("SAFE_ZONE_ADBLOCK_ENABLED", "false")
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	svc := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		Redis:          cache.NewRedis(mr.Addr(), "", 0),
		RedisTimeout:   time.Second,
	})
	defer func() { _ = svc.Close() }()

	domain := "meadowharbor.net"
	now := time.Now().UTC()
	strong := analysis.Result{
		Domain: "meadowharbor.net", Verdict: analysis.VerdictMalicious,
		Confidence: 0.92, Score: 90, Reasons: []string{"osint: strong public warning"},
	}
	key := analysisCacheKey(domain, svc.currentMLPolicyRevision())
	before := now.Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	if err := svc.redis.SetJSON(context.Background(), key, analysisCacheEntry{
		Result:           strong,
		AnalysisRevision: analysisAlgorithmRevision,
		ConfigRevision:   svc.currentConfigRevision(),
		OSINTCheckedAt:   before,
	}, time.Hour); err != nil {
		t.Fatal(err)
	}

	staleBase := analysis.Result{
		Domain: "meadowharbor.net", Verdict: analysis.VerdictSafe,
		Confidence: 0.74, Score: 35, Reasons: []string{"high_entropy_dga_suspected"},
	}
	svc.enrichmentLookup = func(context.Context, string) enrichmentSignals {
		return enrichmentSignals{}
	}
	job := enrichmentJob{
		Domain:         domain,
		Result:         staleBase,
		ConfigRevision: svc.currentConfigRevision(),
		QueuedAt:       now.Add(-2 * time.Minute).UTC().Format(time.RFC3339Nano),
	}
	svc.processEnrichmentJob(job)

	var after analysisCacheEntry
	found, err := svc.redis.GetJSON(context.Background(), key, &after)
	if err != nil || !found {
		t.Fatalf("expected cached entry to survive, found=%v err=%v", found, err)
	}
	if after.Result.Verdict != analysis.VerdictMalicious || after.Result.Score != 90 {
		t.Fatalf("stale worker overwrote stronger evaluation: %+v", after.Result)
	}
}

// M1: a worker whose snapshot predates a fresh recompute must also stand
// down, even without enrichment markers on either side.
func TestEnrichmentWorkerSkipsFreshRecompute(t *testing.T) {
	t.Setenv("SAFE_ZONE_ADBLOCK_ENABLED", "false")
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	svc := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		Redis:          cache.NewRedis(mr.Addr(), "", 0),
		RedisTimeout:   time.Second,
	})
	defer func() { _ = svc.Close() }()

	domain := "fresh-recompute.test"
	now := time.Now().UTC()
	fresh := analysis.Result{Domain: domain, Verdict: analysis.VerdictSafe, Confidence: 0.6, Score: 20}
	key := analysisCacheKey(domain, svc.currentMLPolicyRevision())
	if err := svc.redis.SetJSON(context.Background(), key, analysisCacheEntry{
		Result:           fresh,
		AnalysisRevision: analysisAlgorithmRevision,
		ConfigRevision:   svc.currentConfigRevision(),
		AssessedAt:       now.Add(-time.Minute).UTC().Format(time.RFC3339Nano),
	}, time.Hour); err != nil {
		t.Fatal(err)
	}

	svc.enrichmentLookup = func(context.Context, string) enrichmentSignals {
		return enrichmentSignals{}
	}
	job := enrichmentJob{
		Domain:         domain,
		Result:         fresh,
		ConfigRevision: svc.currentConfigRevision(),
		QueuedAt:       now.Add(-2 * time.Minute).UTC().Format(time.RFC3339Nano),
	}
	svc.processEnrichmentJob(job)

	var after analysisCacheEntry
	if _, err := svc.redis.GetJSON(context.Background(), key, &after); err != nil {
		t.Fatal(err)
	}
	if after.EnrichedAt != "" {
		t.Fatalf("stale worker must not rewrite a fresher recompute: %+v", after)
	}
}

// M2: revision acceptance must be explicit. A failed revision read is not
// equality: the entry is unusable until revisions are readable again.
// A missing revision key (feed never synced) still matches empty entries
// so fresh no-feed deployments keep working cache.
func TestEntryMatchesRevision(t *testing.T) {
	base := cacheEpoch{
		AnalysisRevision: analysisAlgorithmRevision,
		ConfigRevision:   "cfg", ModelRevision: "model",
		FeedRevision: "4", FeedKnown: true, BrandRevision: "b1", BrandKnown: true,
	}
	entry := analysisCacheEntry{
		Result:           analysis.Result{Domain: "x.test"},
		FeedRevision:     "4",
		BrandRevision:    "b1",
		AnalysisRevision: analysisAlgorithmRevision,
		ConfigRevision:   "cfg",
		ModelRevision:    "model",
	}
	cases := map[string]struct {
		mutate func(*cacheEpoch, *analysisCacheEntry)
		want   bool
	}{
		"match":            {nil, true},
		"feed rotated":     {func(e *cacheEpoch, _ *analysisCacheEntry) { e.FeedRevision = "5" }, false},
		"brand rotated":    {func(e *cacheEpoch, _ *analysisCacheEntry) { e.BrandRevision = "b2" }, false},
		"feed read failed": {func(e *cacheEpoch, _ *analysisCacheEntry) { e.FeedKnown = false }, false},
		"brand read fail":  {func(e *cacheEpoch, _ *analysisCacheEntry) { e.BrandKnown = false }, false},
	}
	for name, tc := range cases {
		t.Run("entry/"+name, func(t *testing.T) {
			epoch := base
			if tc.mutate != nil {
				tc.mutate(&epoch, &entry)
			}
			if got := entryMatchesRevision(entry, epoch); got != tc.want {
				t.Fatalf("entryMatchesRevision = %v, want %v", got, tc.want)
			}
		})
	}

	empty := analysisCacheEntry{
		Result:           analysis.Result{Domain: "x.test"},
		AnalysisRevision: analysisAlgorithmRevision,
		ConfigRevision:   "cfg",
		ModelRevision:    "model",
	}
	t.Run("empty/no-feed-ever-matches", func(t *testing.T) {
		epoch := base
		epoch.FeedRevision, epoch.BrandRevision = "", ""
		if !entryMatchesRevision(empty, epoch) {
			t.Fatal("empty entry must match when no feed/brand epoch exists")
		}
	})
	t.Run("empty/feed-appeared-misses", func(t *testing.T) {
		epoch := base
		epoch.FeedRevision, epoch.BrandRevision = "7", ""
		if entryMatchesRevision(empty, epoch) {
			t.Fatal("appeared feed epoch must invalidate empty entry")
		}
	})
	t.Run("empty/unreadable-still-misses", func(t *testing.T) {
		epoch := base
		epoch.FeedRevision, epoch.BrandRevision, epoch.FeedKnown = "", "", false
		if entryMatchesRevision(empty, epoch) {
			t.Fatal("unreadable revision must not accept entries")
		}
	})
}
