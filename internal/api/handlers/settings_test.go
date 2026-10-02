package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"safe-zone/internal/config"
	"safe-zone/internal/risk"
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

func TestTestAIEndpointUsesSubmittedKeyWithoutSaving(t *testing.T) {
	gemini := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("key"); got != "submitted-test-key" {
			t.Fatalf("expected submitted key, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"{\"verdict\":\"SAFE\",\"confidence\":0.95,\"reason\":\"test passed\"}"}]}}]}`))
	}))
	defer gemini.Close()
	t.Setenv("SAFE_ZONE_GEMINI_BASE_URL", gemini.URL+"/v1beta")

	ts := newHandlerTestServer(t)
	req, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/settings/test-ai", strings.NewReader(`{"gemini_api_key":"submitted-test-key"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	ts.addAdminBearer(req)

	resp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected test to succeed, got %d: %s", resp.StatusCode, body)
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("expected successful test, got %v", payload)
	}
	if saved, err := ts.Store.GetSystemConfig(context.Background(), "gemini_api_key"); err != nil || saved != "" {
		t.Fatalf("submitted key must not be persisted, got %q, err=%v", saved, err)
	}
}

// postSettings sends an admin-authenticated settings mutation and returns the
// HTTP status plus the decoded body.
func postSettings(t *testing.T, ts *handlerTestServer, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/settings", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	ts.addAdminBearer(req)

	resp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var payload map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&payload)
	return resp.StatusCode, payload
}

func TestSettingsAdblockToggleRoundTrip(t *testing.T) {
	ts := newHandlerTestServer(t)

	// The GET payload must always carry the adblock switches so the UI can
	// render the real state instead of assuming the default. /v1/settings is
	// admin-only, so the request must be authenticated.
	req, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/settings", nil)
	if err != nil {
		t.Fatal(err)
	}
	ts.addAdminBearer(req)
	resp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("GET /v1/settings: got %d %s", resp.StatusCode, body)
	}
	var loaded settingsResponse
	if err := json.NewDecoder(resp.Body).Decode(&loaded); err != nil {
		t.Fatalf("decode settings: %v", err)
	}
	resp.Body.Close()
	if loaded.Adblock == nil {
		t.Fatal("GET /v1/settings must expose the adblock switches")
	}
	// newHandlerTestServer pins SAFE_ZONE_ADBLOCK_ENABLED=false for hermetic
	// tests, so the asserted default is the one that fixture produces. The
	// shipped default is asserted in internal/risk.
	if loaded.Adblock.Enabled {
		t.Fatal("expected the hermetic test fixture to report adblock disabled")
	}

	// Disabling is the emergency action, so it must succeed and persist.
	if code, body := postSettings(t, ts, `{"adblock_enabled":false}`); code != http.StatusOK {
		t.Fatalf("disable adblock: got %d %v", code, body)
	}
	if control := ts.Handler.Risk.AdblockControl(); control.Enabled {
		t.Fatal("adblock must be disabled after the API call")
	}

	if code, body := postSettings(t, ts, `{"adblock_enabled":true}`); code != http.StatusOK {
		t.Fatalf("re-enable adblock: got %d %v", code, body)
	}
	if control := ts.Handler.Risk.AdblockControl(); !control.Enabled {
		t.Fatal("adblock must be enabled again after the API call")
	}
}

func TestSettingsAdblockMatchModeRejectsUnknownValue(t *testing.T) {
	ts := newHandlerTestServer(t)

	code, _ := postSettings(t, ts, `{"adblock_match_mode":"regex"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an unsupported match mode, got %d", code)
	}
	// A rejected request must not have changed anything.
	if got := ts.Handler.Risk.AdblockControl().MatchMode; got == "regex" {
		t.Fatal("invalid match mode must not be applied")
	}

	if code, body := postSettings(t, ts, `{"adblock_match_mode":"exact"}`); code != http.StatusOK {
		t.Fatalf("set exact: got %d %v", code, body)
	}
	if got := ts.Handler.Risk.AdblockControl().MatchMode; got != "exact" {
		t.Fatalf("match mode = %q; want exact", got)
	}
}

func TestSettingsOmittedAdblockFieldsAreNotMutated(t *testing.T) {
	ts := newHandlerTestServer(t)

	if code, body := postSettings(t, ts, `{"adblock_enabled":false}`); code != http.StatusOK {
		t.Fatalf("disable: got %d %v", code, body)
	}

	// Saving an unrelated setting must not silently re-enable adblock, which
	// is the failure mode a non-pointer field would introduce.
	if code, body := postSettings(t, ts, `{"telemetry_retention_days":45}`); code != http.StatusOK {
		t.Fatalf("save retention: got %d %v", code, body)
	}
	if ts.Handler.Risk.AdblockControl().Enabled {
		t.Fatal("an unrelated settings save must not change the adblock switch")
	}
}

func TestTestAlertEndpointDoesNotFallBackWhenSubmittedURLIsInvalid(t *testing.T) {
	ts := newHandlerTestServer(t)
	if err := ts.Store.SetSystemConfig(context.Background(), "agent_webhook_url", "https://hooks.example.test/saved"); err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/settings/test-alert", strings.NewReader(`{"agent_webhook_url":"http://127.0.0.1:8080/test"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	ts.addAdminBearer(req)

	resp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected submitted URL validation error, got %d: %s", resp.StatusCode, body)
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

func TestSettingsHandlerRejectsPrivateWebhookURL(t *testing.T) {
	ts := newHandlerTestServer(t)

	saveReq, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/settings", strings.NewReader(`{"agent_webhook_url":"http://127.0.0.1:8080/hook"}`))
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
	if saveResp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(saveResp.Body)
		t.Fatalf("expected save 400, got %d: %s", saveResp.StatusCode, body)
	}
}

func TestTestAlertEndpointRequiresWebhook(t *testing.T) {
	ts := newHandlerTestServer(t)

	req, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/settings/test-alert", nil)
	if err != nil {
		t.Fatal(err)
	}
	ts.addAdminBearer(req)

	resp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected missing webhook to return 400, got %d: %s", resp.StatusCode, body)
	}

	var payload map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload["error"] != "No webhook URL configured" {
		t.Fatalf("unexpected missing webhook error: %q", payload["error"])
	}
}

// A policy document saved through the settings API must be persisted and
// applied. Before this the store key was read by the runtime but never written
// by anything, while the docs promised a runtime change reached dns-resolver
// without a restart.
func TestSettingsSavesAdblockSourcePolicies(t *testing.T) {
	ts := newHandlerTestServer(t)

	document := `{"https://a.test/hosts":{"category":"tracking","scope":"suffix"}}`
	req, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/settings", strings.NewReader(
		`{"adblock_source_policies_json":`+strconv.Quote(document)+`}`))
	if err != nil {
		t.Fatal(err)
	}
	ts.addAdminBearer(req)

	resp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("save policies = %d, want 200: %s", resp.StatusCode, body)
	}

	// Persisted, so the peer process can reconcile it.
	stored, err := ts.Store.GetSystemConfig(context.Background(), risk.SystemConfigAdblockSourcePolicies)
	if err != nil {
		t.Fatal(err)
	}
	if stored != document {
		t.Fatalf("stored document = %q, want %q", stored, document)
	}

	// Readable back, so the operator UI can round-trip it.
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
		t.Fatalf("read settings = %d, want 200", getResp.StatusCode)
	}
	var payload settingsResponse
	if err := json.NewDecoder(getResp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.AdblockSourcePoliciesJSON != document {
		t.Fatalf("read back %q, want %q", payload.AdblockSourcePoliciesJSON, document)
	}
}

// A document the runtime would silently repair must be rejected rather than
// stored: the operator's intent and the effective policy would otherwise
// differ with nothing in the response saying so.
func TestSettingsRejectsInvalidAdblockSourcePolicies(t *testing.T) {
	ts := newHandlerTestServer(t)

	cases := []struct {
		name     string
		document string
	}{
		{"not json", `{nope`},
		{"unknown category", `{"https://a.test/hosts":{"category":"banana"}}`},
		{"unknown scope", `{"https://a.test/hosts":{"scope":"sideways"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/settings", strings.NewReader(
				`{"adblock_source_policies_json":`+strconv.Quote(tc.document)+`}`))
			if err != nil {
				t.Fatal(err)
			}
			ts.addAdminBearer(req)

			resp, err := ts.Client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 for %q", resp.StatusCode, tc.document)
			}
			stored, err := ts.Store.GetSystemConfig(context.Background(), risk.SystemConfigAdblockSourcePolicies)
			if err != nil {
				t.Fatal(err)
			}
			if stored != "" {
				t.Fatalf("a rejected document was persisted: %q", stored)
			}
		})
	}
}

// Omitting the field must not clear the policies: saving some other setting
// would otherwise wipe them.
func TestSettingsOmitDoesNotClearAdblockSourcePolicies(t *testing.T) {
	ts := newHandlerTestServer(t)
	document := `{"https://a.test/hosts":{"category":"ads"}}`

	save := func(body string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/settings", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		ts.addAdminBearer(req)
		resp, err := ts.Client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	first := save(`{"adblock_source_policies_json":` + strconv.Quote(document) + `}`)
	defer first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("initial save = %d, want 200", first.StatusCode)
	}

	second := save(`{"telemetry_retention_days":14}`)
	defer second.Body.Close()
	if second.StatusCode != http.StatusOK {
		t.Fatalf("unrelated save = %d, want 200", second.StatusCode)
	}

	stored, err := ts.Store.GetSystemConfig(context.Background(), risk.SystemConfigAdblockSourcePolicies)
	if err != nil {
		t.Fatal(err)
	}
	if stored != document {
		t.Fatalf("an unrelated save changed the policies: %q", stored)
	}
}

// An explicitly empty document is the way to clear the override, and is
// distinct from omitting the field.
func TestSettingsEmptyStringClearsAdblockSourcePolicies(t *testing.T) {
	ts := newHandlerTestServer(t)

	save := func(body string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/settings", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		ts.addAdminBearer(req)
		resp, err := ts.Client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	first := save(`{"adblock_source_policies_json":"{\"https://a.test/hosts\":{\"category\":\"ads\"}}"}`)
	defer first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("initial save = %d, want 200", first.StatusCode)
	}

	second := save(`{"adblock_source_policies_json":""}`)
	defer second.Body.Close()
	if second.StatusCode != http.StatusOK {
		t.Fatalf("clear = %d, want 200", second.StatusCode)
	}

	stored, err := ts.Store.GetSystemConfig(context.Background(), risk.SystemConfigAdblockSourcePolicies)
	if err != nil {
		t.Fatal(err)
	}
	if stored != "" {
		t.Fatalf("an empty document must clear the stored value, got %q", stored)
	}
}
