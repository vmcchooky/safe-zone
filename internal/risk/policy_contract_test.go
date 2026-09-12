package risk

import (
	"context"
	"testing"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
	"safe-zone/internal/domaintrie"
	"safe-zone/internal/store"
)

func newParityTestService(t *testing.T) *Service {
	t.Helper()
	t.Setenv("SAFE_ZONE_ADBLOCK_ENABLED", "false")
	svc := NewService(Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		RedisTimeout:       10 * time.Millisecond,
		TTLAllowed:         time.Hour,
		TTLSuspicious:      time.Hour,
		TTLBlocked:         time.Hour,
		RecentLimit:        10,
		DisableAdblockSync: true,
	})
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

func containsLayer(layers []string, layer string) bool {
	for _, l := range layers {
		if l == layer {
			return true
		}
	}
	return false
}

// The same engine input must yield the same security verdict on both
// endpoints. Analyze and Policy are views over one assessment; any
// divergence must carry an explicit content Decision.
func TestAnalyzePolicySecurityParity(t *testing.T) {
	svc := newParityTestService(t)
	for _, domain := range []string{"dichvucongvn.com", "quiet-benign-hostname-example.test"} {
		t.Run(domain, func(t *testing.T) {
			api := svc.Analyze(context.Background(), domain, ClientInfo{})
			pol := svc.Policy(context.Background(), domain, ClientInfo{})
			if api.Verdict != pol.Result.Verdict || api.Score != pol.Result.Score {
				t.Fatalf("security divergence for %s: api %s/%d vs policy %s/%d",
					domain, api.Verdict, api.Score, pol.Result.Verdict, pol.Result.Score)
			}
			if api.Assessment.Coverage != AssessmentCoverageDomainOnly {
				t.Fatalf("api assessment must declare domain-only coverage, got %+v", api.Assessment)
			}
			if pol.Assessment.Coverage != AssessmentCoverageDomainOnly {
				t.Fatalf("policy assessment must declare domain-only coverage, got %+v", pol.Assessment)
			}
			if pol.Decision != nil {
				t.Fatalf("engine-only domain must not carry a content decision, got %+v", pol.Decision)
			}
			for _, layer := range []string{LayerIdentity, LayerOverride, LayerWhitelist, LayerThreatFeed, LayerLexical} {
				if !containsLayer(api.Assessment.Evaluated, layer) {
					t.Fatalf("api assessment must list evaluated %s, got %+v", layer, api.Assessment)
				}
			}
			if !containsLayer(api.Assessment.Skipped, LayerWebsite+":not_observed") {
				t.Fatalf("assessment must disclose unobserved website content, got %+v", api.Assessment.Skipped)
			}
		})
	}
}

// A DNS block on a non-malicious security verdict is only expressible
// with an explicit content-policy Decision.
func TestPolicyBlockOnSafeVerdictRequiresContentDecision(t *testing.T) {
	svc := newParityTestService(t)
	t.Setenv("SAFE_ZONE_ADBLOCK_ENABLED", "true")
	trie := domaintrie.NewTrie()
	trie.Add("telemetry-fast-path.example.com")
	svc.AdblockTrieOverride(trie)
	svc.refreshAdblockEnabled()

	pol := svc.Policy(context.Background(), "telemetry-fast-path.example.com", ClientInfo{})
	if pol.Policy != "block" {
		t.Fatalf("expected content block, got %s", pol.Policy)
	}
	if pol.Result.Verdict == analysis.VerdictMalicious {
		t.Fatalf("content block must not masquerade as security malicious: %+v", pol.Result)
	}
	if pol.Decision == nil || pol.Decision.Action != "block" || pol.Decision.Kind != "content" {
		t.Fatalf("content block requires an explicit content decision, got %+v", pol.Decision)
	}
	if !containsLayer(pol.Assessment.Evaluated, LayerContentPolicy) {
		t.Fatalf("assessment must list content_policy as evaluated, got %+v", pol.Assessment)
	}
	api := svc.Analyze(context.Background(), "telemetry-fast-path.example.com", ClientInfo{})
	if api.Verdict == analysis.VerdictMalicious {
		t.Fatalf("api security verdict must stay independent of content policy, got %+v", api.Result)
	}
	if api.Decision != nil {
		t.Fatalf("api must not fuse content policy into security, got %+v", api.Decision)
	}
}

// Legacy fused rows must be attributable in telemetry: source adblock
// (not lexical) with an explicit policy block of unknown content
// category. The Result/Decision wire shape stays pinned by existing tests.
func TestLegacyAdblockTelemetryAttribution(t *testing.T) {
	service, storeDB := newSemanticsTestService(t, PolicySemanticsLegacy, []string{"legacy-attr.example.com"}, nil)

	res := service.Analyze(context.Background(), "legacy-attr.example.com", ClientInfo{})
	if res.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected legacy fused verdict, got %s", res.Verdict)
	}

	deadline := time.Now().Add(5 * time.Second)
	var entries []store.TelemetryEntry
	for {
		var err error
		entries, err = storeDB.QueryRecentFiltered(context.Background(), store.TelemetryFilter{}, 10, 0)
		if err != nil {
			t.Fatalf("query telemetry: %v", err)
		}
		if len(entries) >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(entries) == 0 {
		t.Fatal("expected telemetry entry")
	}
	entry := entries[0]
	if entry.Source != "adblock" {
		t.Fatalf("legacy adblock row must source to adblock, got %q", entry.Source)
	}
	if entry.PolicyAction != "block" || entry.PolicyCategory != "unknown" {
		t.Fatalf("legacy row must record policy block/unknown, got %q/%q", entry.PolicyAction, entry.PolicyCategory)
	}
}

// Admin and allowlist short-circuits must record their policy action
// instead of hiding inside a fabricated security verdict.
func TestOverrideAllowlistPolicyAttribution(t *testing.T) {
	service, storeDB := newSemanticsTestService(t, PolicySemanticsSeparated, nil, nil)
	ctx := context.Background()
	if err := storeDB.UpsertOverride(ctx, "operator-blocked.test", "block", "manual review"); err != nil {
		t.Fatal(err)
	}
	if err := storeDB.UpsertOverride(ctx, "operator-allowed.test", "allow", "manual review"); err != nil {
		t.Fatal(err)
	}

	blocked := service.Policy(ctx, "operator-blocked.test", ClientInfo{})
	// Pinned rollback contract: override/whitelist Policy paths carry no
	// content Decision. Attribution flows to telemetry columns instead.
	if blocked.Decision != nil {
		t.Fatalf("override policy path must not carry a decision, got %+v", blocked.Decision)
	}
	allowed := service.Policy(ctx, "operator-allowed.test", ClientInfo{})
	if allowed.Decision != nil {
		t.Fatalf("allowlist policy path must not carry a decision, got %+v", allowed.Decision)
	}
	api := service.Analyze(ctx, "operator-blocked.test", ClientInfo{})
	if api.Decision == nil || api.Decision.Action != "block" {
		t.Fatalf("api override block needs a visible policy decision, got %+v", api.Decision)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, err := storeDB.QueryRecentFiltered(ctx, store.TelemetryFilter{Source: "override"}, 10, 0)
		if err != nil {
			t.Fatalf("query telemetry: %v", err)
		}
		if len(entries) >= 2 || time.Now().After(deadline) {
			if len(entries) < 2 {
				t.Fatalf("expected override telemetry rows, got %d", len(entries))
			}
			for _, e := range entries {
				if e.PolicyAction == "" || e.PolicyCategory != "custom" {
					t.Fatalf("override row must record action/custom, got %+v", e)
				}
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}
