package risk

import (
	"context"
	"testing"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/config"
	"safe-zone/internal/tlsinspect"
	"safe-zone/internal/whois"

	"github.com/alicebob/miniredis/v2"
)

// PR-05/M1: a stale enrichment snapshot must never overwrite a fresher
// cached evaluation, even when its signals would promote the verdict.
func TestWorkerStaleSnapshotNeverOverwritesFresherEntry(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	svc := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		Redis:          cache.NewRedis(server.Addr(), "", 0),
		RedisTimeout:   time.Second,
		TTLAllowed:     time.Hour,
		TTLSuspicious:  time.Hour,
		TTLBlocked:     time.Hour,
		EnrichTimeout:  time.Second,
	})
	defer func() { _ = svc.Close() }()

	domain := "cas-stale-guard-example.test"
	base := svc.analyzeLexical(domain)
	if base.Verdict != analysis.VerdictSafe {
		t.Fatalf("fixture must start safe, got %+v", base)
	}
	cfgRev := svc.currentConfigRevision()
	modelRev := svc.currentMLPolicyRevision()

	freshAt := time.Now().UTC()
	staleAt := freshAt.Add(-time.Hour)

	// Fresh snapshot first: no enrichment signals, writes base verdict.
	svc.enrichmentLookup = func(context.Context, string) enrichmentSignals { return enrichmentSignals{} }
	svc.processEnrichmentJob(enrichmentJob{
		Domain:         domain,
		Result:         base,
		ConfigRevision: cfgRev,
		ModelRevision:  modelRev,
		QueuedAt:       freshAt.Format(time.RFC3339Nano),
	})
	key := analysisCacheKey(domain, modelRev)
	var fresh analysisCacheEntry
	found, err := svc.redis.GetJSON(context.Background(), key, &fresh)
	if err != nil || !found {
		t.Fatalf("fresh job must write, found=%v err=%v", found, err)
	}

	// Stale snapshot with promoting signals must not overwrite.
	svc.enrichmentLookup = func(context.Context, string) enrichmentSignals {
		return enrichmentSignals{
			TLS:   tlsinspect.Result{Score: 25, Reasons: []string{"tls: self-signed certificate"}},
			WHOIS: whois.Result{Score: 25, Reasons: []string{"whois: test signal"}},
		}
	}
	svc.processEnrichmentJob(enrichmentJob{
		Domain:         domain,
		Result:         base,
		ConfigRevision: cfgRev,
		ModelRevision:  modelRev,
		QueuedAt:       staleAt.Format(time.RFC3339Nano),
	})
	var after analysisCacheEntry
	found, err = svc.redis.GetJSON(context.Background(), key, &after)
	if err != nil || !found {
		t.Fatalf("entry must survive, found=%v err=%v", found, err)
	}
	if after.Result.Score != fresh.Result.Score || after.Result.Verdict != fresh.Result.Verdict ||
		after.AssessedAt != fresh.AssessedAt {
		t.Fatalf("stale snapshot overwrote fresher entry: before=%+v after=%+v", fresh.Result, after.Result)
	}
}
