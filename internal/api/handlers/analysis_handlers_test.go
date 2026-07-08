package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/config"
	"safe-zone/internal/observability"
	"safe-zone/internal/osint"
	"safe-zone/internal/risk"
)

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

	hugePayload := `{"domain":"` + strings.Repeat("a", 5000) + `"}`
	resp, err := ts.Client.Post(ts.Server.URL+"/v1/analyze", "application/json", strings.NewReader(hugePayload))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}
