package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
	"safe-zone/internal/domaintrie"
	"safe-zone/internal/observability"
	"safe-zone/internal/osint"
	"safe-zone/internal/risk"
)

type handlerURLClassifier struct{}

func (*handlerURLClassifier) Enabled() bool    { return true }
func (*handlerURLClassifier) Revision() string { return "handler-url-revision" }
func (*handlerURLClassifier) ClassifyURL(analysis.URLContext) (analysis.MLDecision, error) {
	return analysis.MLDecision{
		Probability:  0.98,
		Action:       analysis.MLActionPromoteMalicious,
		ModelVersion: "handler-url-v1",
		Revision:     "handler-url-revision",
	}, nil
}

func TestRecentAnalysisHandlerRequiresAuth(t *testing.T) {
	ts := newHandlerTestServer(t)

	// Unauthenticated request must be rejected server-side.
	resp, err := ts.Client.Get(ts.Server.URL + "/v1/analysis/recent")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated request, got %d", resp.StatusCode)
	}

	// A valid admin request must still work (the test server runs without
	// Redis, so an empty items list is a valid response).
	req, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/analysis/recent", nil)
	if err != nil {
		t.Fatal(err)
	}
	ts.addAdminBearer(req)

	authedResp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer authedResp.Body.Close()
	if authedResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for authenticated request, got %d", authedResp.StatusCode)
	}

	var payload struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.NewDecoder(authedResp.Body).Decode(&payload); err != nil {
		t.Fatalf("expected valid JSON payload, got %v", err)
	}
}

func TestAnalyzeEndpointStillWorks(t *testing.T) {
	ts := newHandlerTestServer(t)

	resp, err := ts.Client.Get(ts.Server.URL + "/v1/analyze?domain=secure-login-wallet-example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload["verdict"] != "MALICIOUS" {
		t.Fatalf("expected malicious verdict, got %#v", payload["verdict"])
	}
	if payload["domain"] == "" {
		t.Fatal("expected domain in response")
	}
}

// /v1/analyze returns risk.Analysis, which never carries a policy decision.
// PR1 must not change this response contract: no "decision" key may appear
// even for domains that match the adblock trie, and the security fields keep
// their meaning.
func TestAnalyzeEndpointContractUnchangedForAdblockDomain(t *testing.T) {
	ts := newHandlerTestServer(t)

	// The test server disables adblock sync but not the matcher itself: pin a
	// trie entry via the exposed test seam.
	trie := domaintrie.NewTrie()
	trie.Add("ads.example.com")
	ts.Handler.Risk.AdblockTrieOverride(trie)

	resp, err := ts.Client.Get(ts.Server.URL + "/v1/analyze?domain=ads.example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if _, hasDecision := payload["decision"]; hasDecision {
		t.Fatal("/v1/analyze must not expose a policy decision field")
	}
	for _, key := range []string{"domain", "verdict", "confidence", "score", "reasons", "cache_hit", "analyzed_at"} {
		if _, ok := payload[key]; !ok {
			t.Fatalf("/v1/analyze response lost field %q: %v", key, payload)
		}
	}
	// Under separated semantics an adblock match is not security evidence on
	// the analysis path either.
	if payload["verdict"] == "MALICIOUS" {
		if reasons, _ := payload["reasons"].([]any); len(reasons) > 0 && reasons[0] == "adblock" {
			t.Fatalf("adblock must not drive the analyze verdict, got %v", payload["reasons"])
		}
	}
}

func TestAnalyzeEndpointDetectsVietnamPublicServiceAbuse(t *testing.T) {
	ts := newHandlerTestServer(t)

	resp, err := ts.Client.Get(ts.Server.URL + "/v1/analyze?domain=dichvucong-vn.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload["verdict"] != "MALICIOUS" {
		t.Fatalf("expected malicious verdict, got %#v", payload["verdict"])
	}
}

func TestAnalyzeEndpointIncludesOSINTEvidence(t *testing.T) {
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<title>Cảnh báo giả mạo</title>baohiem-online.com là website giả mạo, lừa đảo.`))
	}))
	defer source.Close()

	handler := &Handler{
		Risk: risk.NewService(risk.Options{
			AnalysisConfig: config.DefaultAnalysisConfig(),
			RedisTimeout:   10 * time.Millisecond,
			OSINT: osint.NewService(osint.Options{
				Enabled:             true,
				Sources:             []string{source.URL},
				TrustedDomains:      []string{strings.TrimPrefix(source.URL, "http://")},
				AllowPrivateSources: true,
				CacheTTL:            time.Hour,
			}),
		}),
		Metrics: observability.NewRegistry(),
		Config:  Config{DeploymentTier: "test"},
	}
	defer func() {
		_ = handler.Risk.Close()
	}()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/analyze?domain=baohiem-online.com&include_evidence=1", nil)

	handler.AnalyzeHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var payload map[string]any
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload["verdict"] != "MALICIOUS" {
		t.Fatalf("expected malicious verdict, got %#v", payload["verdict"])
	}
	evidence, ok := payload["evidence"].([]any)
	if !ok || len(evidence) == 0 {
		t.Fatalf("expected evidence array, got %#v", payload["evidence"])
	}
}

func TestAnalyzeEndpointRejectsOversizedJSONBody(t *testing.T) {
	ts := newHandlerTestServer(t)

	hugePayload := `{"domain":"` + strings.Repeat("a", 40000) + `"}`
	resp, err := ts.Client.Post(ts.Server.URL+"/v1/analyze", "application/json", strings.NewReader(hugePayload))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAnalyzePostAcceptsURLContextOnlyForShadowObservation(t *testing.T) {
	handler := &Handler{
		Risk: risk.NewService(risk.Options{
			AnalysisConfig:  config.DefaultAnalysisConfig(),
			URLMLClassifier: &handlerURLClassifier{},
			URLMLMode:       analysis.MLModeShadow,
		}),
		Metrics: observability.NewRegistry(),
		Config:  Config{DeploymentTier: "test"},
	}
	defer func() { _ = handler.Risk.Close() }()

	body := `{"domain":"example.com","requested_url":"https://example.com/login?token=synthetic-secret","redirect_chain":[]}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/analyze", strings.NewReader(body))
	handler.AnalyzeHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "synthetic-secret") || strings.Contains(recorder.Body.String(), "requested_url") {
		t.Fatalf("response leaked raw URL context: %s", recorder.Body.String())
	}
	var payload struct {
		URLML *risk.URLMLObservation `json:"url_ml"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.URLML == nil || !payload.URLML.Evaluated || !payload.URLML.WouldPromote {
		t.Fatalf("unexpected URL observation: %+v", payload.URLML)
	}
}

func TestAnalyzeGetDoesNotAcceptURLContext(t *testing.T) {
	ts := newHandlerTestServer(t)
	resp, err := ts.Client.Get(ts.Server.URL + "/v1/analyze?domain=example.com&requested_url=https://example.com/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if _, exists := payload["url_ml"]; exists {
		t.Fatalf("GET unexpectedly accepted URL context: %#v", payload["url_ml"])
	}
}
