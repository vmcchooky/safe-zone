package risk

import (
	"context"
	"testing"
	"time"

	"safe-zone/internal/correlation"
	"safe-zone/internal/store"
)

// Every evaluation carries a decision ID: the request correlation ID when
// present, otherwise a generated eval ID. IDs must be unique per call.
func TestDecisionIDPresentAndUnique(t *testing.T) {
	svc := newParityTestService(t)
	ctx := correlation.WithRequestID(context.Background(), "req-trace-001")

	api := svc.AnalyzeWithOptions(ctx, "trace-id-example.test", ClientInfo{}, AnalyzeOptions{})
	if api.DecisionID == "" {
		t.Fatal("analyze response must carry a decision id")
	}
	if api.DecisionID != "req-trace-001" {
		t.Fatalf("decision id must reuse the request correlation id, got %q", api.DecisionID)
	}
	pol := svc.Policy(ctx, "trace-id-example.test", ClientInfo{})
	if pol.DecisionID == "" {
		t.Fatal("policy response must carry a decision id")
	}

	other := svc.Analyze(context.Background(), "trace-id-example.test", ClientInfo{})
	if other.DecisionID == "" || other.DecisionID == api.DecisionID {
		t.Fatalf("generated decision ids must be unique per evaluation, got %q and %q", api.DecisionID, other.DecisionID)
	}
}

// Layer timings use a bounded vocabulary so per-layer series cannot
// explode in cardinality. Engine paths must time the stages they run.
func TestAssessmentTimingsBoundedVocabulary(t *testing.T) {
	svc := newParityTestService(t)
	allowed := map[string]bool{
		LayerIdentity: true, LayerOverride: true, LayerWhitelist: true,
		LayerAdblock: true, LayerContentPolicy: true, LayerThreatFeed: true,
		LayerLexical: true, LayerLexicalLocal: true, LayerDomainML: true,
		LayerAIRefine: true, LayerEnrichment: true, LayerOSINT: true,
		LayerURLML: true, LayerGroupPolicy: true, LayerResultCache: true,
		LayerClientGroup: true,
	}
	api := svc.Analyze(context.Background(), "dichvucongvn.com", ClientInfo{})
	for layer, us := range api.Assessment.Timings {
		if !allowed[layer] {
			t.Fatalf("timing layer %q outside bounded vocabulary", layer)
		}
		if us < 0 {
			t.Fatalf("negative timing for %s: %d", layer, us)
		}
	}
	for _, layer := range []string{LayerThreatFeed, LayerLexical} {
		if _, ok := api.Assessment.Timings[layer]; !ok {
			t.Fatalf("engine assessment must time %s, got %+v", layer, api.Assessment.Timings)
		}
	}
	pol := svc.Policy(context.Background(), "dichvucongvn.com", ClientInfo{})
	if _, ok := pol.Assessment.Timings[LayerGroupPolicy]; !ok {
		t.Fatalf("policy assessment must time group enforcement, got %+v", pol.Assessment.Timings)
	}
}

// Trace and decision id persist to telemetry for offline analysis.
func TestTracePersistedToTelemetry(t *testing.T) {
	service, storeDB := newSemanticsTestService(t, PolicySemanticsSeparated, nil, nil)
	ctx := correlation.WithRequestID(context.Background(), "req-persist-007")
	res := service.Analyze(ctx, "trace-persist-example.test", ClientInfo{})
	if res.DecisionID == "" {
		t.Fatal("expected decision id")
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, err := storeDB.QueryRecentFiltered(ctx,
			store.TelemetryFilter{Domain: "trace-persist-example.test"}, 10, 0)
		if err != nil {
			t.Fatalf("query telemetry: %v", err)
		}
		if len(entries) >= 1 || time.Now().After(deadline) {
			if len(entries) == 0 {
				t.Fatal("expected telemetry entry")
			}
			e := entries[0]
			if e.DecisionID != res.DecisionID {
				t.Fatalf("telemetry must persist decision id %q, got %q", res.DecisionID, e.DecisionID)
			}
			if e.Trace == "" || e.Trace == "{}" {
				t.Fatalf("telemetry must persist non-empty trace, got %q", e.Trace)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}
