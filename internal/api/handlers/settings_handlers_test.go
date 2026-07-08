package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"safe-zone/internal/config"
)

func TestAnalysisConfigEndpoints(t *testing.T) {
	ts := newHandlerTestServer(t)

	cfg := config.DefaultAnalysisConfig()
	cfg.LongDomainLength = 44

	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}

	updateReq, err := http.NewRequest(http.MethodPut, ts.Server.URL+"/v1/config/analysis", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	updateReq.Header.Set("Content-Type", "application/json")
	ts.addAdminBearer(updateReq)

	updateResp, err := ts.Client.Do(updateReq)
	if err != nil {
		t.Fatal(err)
	}
	defer updateResp.Body.Close()
	if updateResp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(updateResp.Body)
		t.Fatalf("expected update 200, got %d: %s", updateResp.StatusCode, data)
	}
	if got := ts.Handler.Risk.GetAnalysisConfig().LongDomainLength; got != 44 {
		t.Fatalf("expected updated config, got %d", got)
	}

	patchReq, err := http.NewRequest(http.MethodPut, ts.Server.URL+"/v1/config/analysis", strings.NewReader(`{"keywords":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	patchReq.Header.Set("Content-Type", "application/json")
	ts.addAdminBearer(patchReq)

	patchResp, err := ts.Client.Do(patchReq)
	if err != nil {
		t.Fatal(err)
	}
	defer patchResp.Body.Close()
	if patchResp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(patchResp.Body)
		t.Fatalf("expected empty keywords update 200, got %d: %s", patchResp.StatusCode, data)
	}
	if got := ts.Handler.Risk.GetAnalysisConfig(); got.LongDomainLength != 44 {
		t.Fatalf("expected omitted fields to preserve current values, got %+v", got)
	} else if len(got.Keywords) != 0 {
		t.Fatalf("expected empty keyword list to be preserved, got %v", got.Keywords)
	}

	resetReq, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/config/analysis/reset", nil)
	if err != nil {
		t.Fatal(err)
	}
	ts.addAdminBearer(resetReq)

	resetResp, err := ts.Client.Do(resetReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resetResp.Body.Close()
	if resetResp.StatusCode != http.StatusOK {
		t.Fatalf("expected reset 200, got %d", resetResp.StatusCode)
	}
	if got := ts.Handler.Risk.GetAnalysisConfig().LongDomainLength; got != config.DefaultAnalysisConfig().LongDomainLength {
		t.Fatalf("expected default config after reset, got %d", got)
	}
}

func TestSettingsHandlerPersistsMaskedSecretsAndRetention(t *testing.T) {
	ts := newHandlerTestServer(t)

	saveReq, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/settings", strings.NewReader(`{"gemini_api_key":"abcd-secret-key","agent_webhook_url":"https://hooks.example.test/endpoint","telemetry_retention_days":14}`))
	if err != nil {
		t.Fatal(err)
	}
	saveReq.Header.Set("Content-Type", "application/json")
	ts.addAdminBearer(saveReq)

	saveResp, err := ts.Client.Do(saveReq)
	if err != nil {
		t.Fatal(err)
	}
	defer saveResp.Body.Close()
	if saveResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(saveResp.Body)
		t.Fatalf("expected save 200, got %d: %s", saveResp.StatusCode, body)
	}

	if got, err := ts.Store.GetSystemConfig(context.Background(), "gemini_api_key"); err != nil {
		t.Fatal(err)
	} else if got != "abcd-secret-key" {
		t.Fatalf("expected raw gemini key to be persisted, got %q", got)
	}
	if got, err := ts.Store.GetSystemConfig(context.Background(), "agent_webhook_url"); err != nil {
		t.Fatal(err)
	} else if got != "https://hooks.example.test/endpoint" {
		t.Fatalf("expected raw webhook URL to be persisted, got %q", got)
	}
	if got := ts.Store.GetRetentionDays(context.Background()); got != 14 {
		t.Fatalf("expected retention days 14, got %d", got)
	}

	getReq, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/settings", nil)
	if err != nil {
		t.Fatal(err)
	}
	ts.addAdminBearer(getReq)

	getResp, err := ts.Client.Do(getReq)
	if err != nil {
		t.Fatal(err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(getResp.Body)
		t.Fatalf("expected settings read 200, got %d: %s", getResp.StatusCode, body)
	}

	var payload settingsResponse
	if err := json.NewDecoder(getResp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.GeminiAPIKey != "abcd***********" {
		t.Fatalf("expected masked gemini key, got %q", payload.GeminiAPIKey)
	}
	if !strings.HasPrefix(payload.AgentWebhookURL, "http") {
		t.Fatalf("expected masked webhook url to retain prefix, got %q", payload.AgentWebhookURL)
	}
	if payload.TelemetryRetentionDays != 14 {
		t.Fatalf("expected retention days 14, got %d", payload.TelemetryRetentionDays)
	}
}
