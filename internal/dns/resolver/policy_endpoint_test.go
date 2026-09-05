package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
	"safe-zone/internal/dns/doh"
	"safe-zone/internal/domaintrie"
	"safe-zone/internal/observability"
	"safe-zone/internal/risk"
	"safe-zone/internal/store"
)

// newPolicyEndpointTestServer spins up an HTTP mux exposing the resolver's
// real PolicyHandler, backed by a risk service with a pre-populated adblock
// trie in the requested semantics mode.
func newPolicyEndpointTestServer(t *testing.T, semantics risk.PolicySemantics, blockedDomain string) *httptest.Server {
	t.Helper()

	tempDir := t.TempDir()
	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")

	dbPath := filepath.Join(tempDir, "policy-endpoint.db")
	storeDB, err := store.New(dbPath, 30)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	if err := storeDB.SetSystemConfig(context.Background(), "adblock_enabled", "true"); err != nil {
		t.Fatalf("enable adblock: %v", err)
	}

	riskService := risk.NewService(risk.Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		RedisTimeout:       10 * time.Millisecond,
		TTLAllowed:         time.Hour,
		TTLSuspicious:      time.Hour,
		TTLBlocked:         time.Hour,
		RecentLimit:        10,
		Store:              storeDB,
		AdblockFileRoot:    tempDir,
		PolicySemantics:    semantics,
		DisableAdblockSync: true,
	})

	trie := domaintrie.NewTrie()
	trie.Add(blockedDomain)
	riskService.AdblockTrieOverride(trie)

	t.Cleanup(func() { _ = riskService.Close() })

	resolverInstance := New(riskService, observability.NewRegistry(), doh.NewUpstreamResolver("https://cloudflare-dns.com/dns-query", nil), Config{
		BlockPageIP:   "192.0.2.1",
		BlockStrategy: BlockStrategySinkhole,
		DNSTTL:        60,
	}, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/policy", resolverInstance.PolicyHandler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

// The /v1/policy response must expose policy.decision with the separated
// adblock fields and must not pollute the security result with the adblock
// reason.
func TestPolicyEndpointReportsDecisionForSeparatedAdblock(t *testing.T) {
	server := newPolicyEndpointTestServer(t, risk.PolicySemanticsSeparated, "clean-ads.example.com")

	resp, err := http.Get(server.URL + "/v1/policy?domain=clean-ads.example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var payload struct {
		Service  string               `json:"service"`
		Action   string               `json:"policy"`
		Result   analysis.Result      `json:"result"`
		Decision *risk.PolicyDecision `json:"decision"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}

	if payload.Action != "block" {
		t.Fatalf("expected policy block, got %s", payload.Action)
	}
	if payload.Decision == nil {
		t.Fatalf("expected decision in /v1/policy response, got %v", payload)
	}
	if payload.Decision.Action != "block" || payload.Decision.Kind != "content" ||
		payload.Decision.Category != "unknown" || payload.Decision.Reason != "adblock_match" ||
		payload.Decision.Source != "adblock" || payload.Decision.AssessmentMode != "lexical_local_default_brands" {
		t.Fatalf("unexpected decision: %+v", payload.Decision)
	}
	if payload.Decision.MatchedRule != "clean-ads.example.com" || payload.Decision.MatchType != "suffix" || payload.Decision.SourceID != "legacy" {
		t.Fatalf("expected rule provenance in /v1/policy decision, got %+v", payload.Decision)
	}
	if payload.Result.Domain != "clean-ads.example.com" {
		t.Fatalf("expected security result domain, got %q", payload.Result.Domain)
	}
	for _, r := range payload.Result.Reasons {
		if r == "adblock" {
			t.Fatalf("adblock must not leak into the security result reasons: %v", payload.Result.Reasons)
		}
	}
	if payload.Service != "dns-resolver" {
		t.Fatalf("expected dns-resolver service label, got %s", payload.Service)
	}
}

// Legacy semantics keep the old wire shape: no decision object, fused
// MALICIOUS/100/adware.
func TestPolicyEndpointLegacyOmitsDecision(t *testing.T) {
	server := newPolicyEndpointTestServer(t, risk.PolicySemanticsLegacy, "clean-ads.example.com")

	resp, err := http.Get(server.URL + "/v1/policy?domain=clean-ads.example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var payload struct {
		Action   string               `json:"policy"`
		Result   analysis.Result      `json:"result"`
		Decision *risk.PolicyDecision `json:"decision"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Action != "block" || payload.Result.Verdict != "MALICIOUS" || payload.Result.Score != 100 || payload.Result.Category != "adware" {
		t.Fatalf("legacy /v1/policy must reproduce the fused result, got %+v", payload)
	}
	if payload.Decision != nil {
		t.Fatalf("legacy /v1/policy must not carry a decision, got %+v", payload.Decision)
	}
}

// A scoped content exception suppresses the adblock block through the real
// HTTP endpoint: the decision carries the new content-axis fields including
// exception_id, while the security result stays independent.
func TestPolicyEndpointReportsExceptionDecision(t *testing.T) {
	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")

	tempDir := t.TempDir()

	dbPath := filepath.Join(tempDir, "policy-endpoint-exc.db")
	storeDB, err := store.New(dbPath, 30)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	if err := storeDB.SetSystemConfig(context.Background(), "adblock_enabled", "true"); err != nil {
		t.Fatalf("enable adblock: %v", err)
	}

	const domain = "app-exception.example.com"
	excPath := filepath.Join(tempDir, "exceptions.json")
	excBody := fmt.Sprintf(`{"version":1,"exceptions":[`+
		`{"id":"fp-endpoint","domain":%q,"scope":"exact","matched_rule":%q,`+
		`"source_id":"legacy","match_type":"suffix","reason":"INC-endpoint verified"}]}`,
		domain, domain)
	if err := os.WriteFile(excPath, []byte(excBody), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAFE_ZONE_ADBLOCK_EXCEPTIONS_FILE", excPath)

	riskService := risk.NewService(risk.Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		RedisTimeout:       10 * time.Millisecond,
		TTLAllowed:         time.Hour,
		TTLSuspicious:      time.Hour,
		TTLBlocked:         time.Hour,
		RecentLimit:        10,
		Store:              storeDB,
		AdblockFileRoot:    tempDir,
		PolicySemantics:    risk.PolicySemanticsSeparated,
		DisableAdblockSync: true,
	})

	trie := domaintrie.NewTrie()
	trie.Add(domain)
	riskService.AdblockTrieOverride(trie)

	t.Cleanup(func() { _ = riskService.Close() })

	resolverInstance := New(riskService, observability.NewRegistry(), doh.NewUpstreamResolver("https://cloudflare-dns.com/dns-query", nil), Config{
		BlockPageIP:   "192.0.2.1",
		BlockStrategy: BlockStrategySinkhole,
		DNSTTL:        60,
	}, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/policy", resolverInstance.PolicyHandler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/v1/policy?domain=" + domain)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var payload struct {
		Service  string               `json:"service"`
		Action   string               `json:"policy"`
		Result   analysis.Result      `json:"result"`
		Decision *risk.PolicyDecision `json:"decision"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}

	if payload.Action != "allow" {
		t.Fatalf("expected suppressed allow, got %s", payload.Action)
	}
	if payload.Decision == nil {
		t.Fatalf("expected exception decision, got %v", payload)
	}
	d := payload.Decision
	if d.Action != "allow" || d.Kind != "content" || d.Reason != "adblock_exception" ||
		d.Source != "adblock" || d.AssessmentMode != "full_security_pipeline" {
		t.Fatalf("unexpected decision: %+v", d)
	}
	if d.MatchedRule != domain || d.MatchType != "suffix" || d.SourceID != "legacy" || d.ExceptionID != "fp-endpoint" {
		t.Fatalf("expected rule provenance plus exception id: %+v", d)
	}
	raw, err := json.Marshal(payload.Decision)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["exception_id"] != "fp-endpoint" {
		t.Fatalf("exception_id must be on the wire, got %v", wire)
	}
	if _, ok := wire["reason"]; !ok {
		t.Fatal("reason must be on the wire")
	}
	for _, r := range payload.Result.Reasons {
		if r == "adblock" {
			t.Fatalf("adblock must not leak into the security result: %v", payload.Result.Reasons)
		}
	}
}
