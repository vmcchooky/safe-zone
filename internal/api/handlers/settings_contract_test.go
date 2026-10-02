package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"safe-zone/internal/store"

	"safe-zone/internal/api/httputil"
)

func postSettingsRaw(t *testing.T, ts *handlerTestServer, body string) *http.Response {
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

func getSystemConfig(t *testing.T, ts *handlerTestServer, key string) string {
	t.Helper()
	value, err := ts.Store.GetSystemConfig(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// A request carrying two changes must not persist the first and then reject the
// second. The webhook URL used to be validated only after the Gemini key had
// already been written, so a 400 left the key saved and the operator believing
// nothing had changed.
func TestSettingsInvalidWebhookDoesNotPersistTheKey(t *testing.T) {
	ts := newHandlerTestServer(t)

	resp := postSettingsRaw(t, ts,
		`{"gemini_api_key":"secret-key","agent_webhook_url":"http://127.0.0.1/hook"}`)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a loopback webhook", resp.StatusCode)
	}
	if got := getSystemConfig(t, ts, "gemini_api_key"); got != "" {
		t.Fatalf("gemini_api_key = %q, want it unwritten: the request was rejected", got)
	}
	if got := getSystemConfig(t, ts, "agent_webhook_url"); got != "" {
		t.Fatalf("agent_webhook_url = %q, want it unwritten", got)
	}
}

// The masked value comes back from GET, so a client that echoes it used to be
// stored as-is with a 200 saying it was saved.
func TestSettingsRejectsMaskedValuesInsteadOfSilentlySkippingThem(t *testing.T) {
	ts := newHandlerTestServer(t)

	for _, body := range []string{
		`{"gemini_api_key":"abcd****wxyz"}`,
		`{"agent_webhook_url":"https://exa****ple.com/hook"}`,
	} {
		resp := postSettingsRaw(t, ts, body)
		status := resp.StatusCode
		_ = resp.Body.Close()
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d for %s, want 400: a masked value is not a change", status, body)
		}
	}
	if got := getSystemConfig(t, ts, "gemini_api_key"); got != "" {
		t.Fatalf("gemini_api_key = %q, want it unwritten", got)
	}
}

// A non-positive retention used to be a 200 that changed nothing.
func TestSettingsRejectsRetentionOutsideTheBounds(t *testing.T) {
	ts := newHandlerTestServer(t)

	for _, days := range []string{"0", "-1", "5473788"} {
		resp := postSettingsRaw(t, ts, `{"telemetry_retention_days":`+days+`}`)
		status := resp.StatusCode
		_ = resp.Body.Close()
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d for retention %s, want 400", status, days)
		}
	}
	if got := getSystemConfig(t, ts, "telemetry_retention_days"); got != "" {
		t.Fatalf("telemetry_retention_days = %q, want it unwritten", got)
	}

	// A value inside the range still applies.
	resp := postSettingsRaw(t, ts, `{"telemetry_retention_days":14}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d for a valid retention, want 200", resp.StatusCode)
	}
	if got := getSystemConfig(t, ts, "telemetry_retention_days"); got != "14" {
		t.Fatalf("telemetry_retention_days = %q, want \"14\"", got)
	}
}

// An unknown match mode must be rejected before the adblock layer changes.
func TestSettingsRejectsUnknownMatchMode(t *testing.T) {
	ts := newHandlerTestServer(t)

	resp := postSettingsRaw(t, ts, `{"adblock_match_mode":"sideways"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// A document naming nothing this handler owns is a client mistake, not a
// success.
func TestSettingsRejectsAnEmptyDocument(t *testing.T) {
	ts := newHandlerTestServer(t)

	resp := postSettingsRaw(t, ts, `{}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d for an empty document, want 400: nothing was saved", resp.StatusCode)
	}
}

// The override filter used to be ignored when it was not "allow" or "block", so
// a typo returned the whole table and read as "no match".
func TestOverridesRejectsAnUnknownActionFilter(t *testing.T) {
	ts := newHandlerTestServer(t)

	req, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/overrides?action=alow", nil)
	if err != nil {
		t.Fatal(err)
	}
	ts.addAdminBearer(req)
	resp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d for a mistyped action filter, want 400", resp.StatusCode)
	}
}

func TestOverridesAcceptsTheValidActionFilters(t *testing.T) {
	ts := newHandlerTestServer(t)

	for _, action := range []string{"", "allow", "block"} {
		url := ts.Server.URL + "/v1/overrides"
		if action != "" {
			url += "?action=" + action
		}
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		ts.addAdminBearer(req)
		resp, err := ts.Client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		status := resp.StatusCode
		_ = resp.Body.Close()
		if status != http.StatusOK {
			t.Fatalf("status = %d for action=%q, want 200", status, action)
		}
	}
}

// A store that cannot answer must be a 503, not a 500 with an internal
// message, and never an empty list that reads as "you have none".
func TestWriteStoreErrorMapsDisabledStoreTo503(t *testing.T) {
	ts := newHandlerTestServer(t)
	if err := ts.Store.Close(); err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/groups", nil)
	if err != nil {
		t.Fatal(err)
	}
	ts.addAdminBearer(req)
	resp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 for an unusable store", resp.StatusCode)
	}
}

func TestStoreUnavailableDetectsTheSentinel(t *testing.T) {
	wrapped := fmt.Errorf("loading group: %w", store.ErrDisabled)
	if !httputil.StoreUnavailable(wrapped) {
		t.Fatal("StoreUnavailable must recognise a wrapped sentinel")
	}
	if httputil.StoreUnavailable(errors.New("some other failure")) {
		t.Fatal("StoreUnavailable must not match an unrelated error")
	}
	if httputil.StoreUnavailable(errors.New("sqlite store disabled")) {
		t.Fatal("a same-text error that is not the sentinel must not match: matching on text is what made this unreliable before")
	}
}

func TestWriteStoreErrorKeepsInternalDetailOutOfTheBody(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/groups", nil)
	httputil.WriteStoreError(rec, req, errors.New("open /var/lib/safe-zone/safe-zone.db: permission denied"), "failed to list groups")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for a non-disabled failure", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "safe-zone.db") || strings.Contains(rec.Body.String(), "permission denied") {
		t.Fatalf("response leaked an internal message: %s", rec.Body.String())
	}
}

// Enabling adblock must be applied last, whatever order the document listed the
// fields in.
//
// It is tempting to leave this as a comment. It should not be: this ordering was
// already the base behaviour, and the validate-then-apply split dropped it once
// without any test noticing. Enabling first brings the layer live against the
// previous policy document, enforces the old source rules for a moment, and then
// rebuilds a second time.
func TestSettingsApplyOrderPutsAdblockEnablementLast(t *testing.T) {
	ts := newHandlerTestServer(t)
	defer ts.Server.Close()

	for _, tc := range []struct {
		name string
		body string
		want []string
	}{
		{
			name: "enablement listed first",
			body: `{"adblock_enabled":true,"adblock_source_policies_json":"{\"https://a.test/hosts\":{\"category\":\"tracking\",\"scope\":\"suffix\"}}"}`,
			want: []string{"adblock_source_policies_json", "adblock_enabled"},
		},
		{
			name: "enablement listed last",
			body: `{"adblock_source_policies_json":"{\"https://a.test/hosts\":{\"category\":\"tracking\",\"scope\":\"suffix\"}}","adblock_enabled":true}`,
			want: []string{"adblock_source_policies_json", "adblock_enabled"},
		},
		{
			// An unrelated field must not drag enablement forward either.
			name: "enablement alongside another field",
			body: `{"adblock_enabled":true,"telemetry_retention_days":14,"adblock_source_policies_json":"{\"https://a.test/hosts\":{\"category\":\"tracking\",\"scope\":\"suffix\"}}"}`,
			want: []string{"telemetry_retention_days", "adblock_source_policies_json", "adblock_enabled"},
		},
		{
			name: "enablement alone stays a single step",
			body: `{"adblock_enabled":false}`,
			want: []string{"adblock_enabled"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var req settingsRequest
			if err := json.Unmarshal([]byte(tc.body), &req); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			steps, err := req.validate(context.Background(), ts.Store, ts.Handler.Risk)
			if err != nil {
				t.Fatalf("validate: %v", err)
			}
			got := make([]string, len(steps))
			for i, step := range steps {
				got[i] = step.field
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("apply order = %v, want %v", got, tc.want)
			}
		})
	}
}

// A store that dies between the handler's Enabled() check and the write must
// surface as a failure, not as a 200 for a change that a restart will undo.
func TestSettingsReports503WhenTheStoreDiesMidApply(t *testing.T) {
	ts := newHandlerTestServer(t)
	defer ts.Server.Close()

	if err := ts.Store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	for _, body := range []string{
		`{"adblock_enabled":true}`,
		`{"adblock_source_policies_json":"{\"https://a.test/hosts\":{\"category\":\"tracking\",\"scope\":\"suffix\"}}"}`,
	} {
		resp := postSettingsRaw(t, ts, body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("status for %s = %d, want 503", body, resp.StatusCode)
		}
	}
}

// The settings bundle is fetched on every UI load, so a disabled store has to be
// a 503 there too. It used to fall through to a 500 that echoed the store's own
// "sqlite store disabled" text into the response body.
func TestSettingsBundleReports503WhenTheStoreIsClosed(t *testing.T) {
	ts := newHandlerTestServer(t)
	defer ts.Server.Close()

	check := func(want int) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/settings/bundle", nil)
		if err != nil {
			t.Fatal(err)
		}
		ts.addAdminBearer(req)
		resp, err := ts.Client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("status = %d, want %d (body %q)", resp.StatusCode, want, body)
		}
		if bytes.Contains(body, []byte("sqlite store disabled")) {
			t.Fatalf("response leaked the internal store message: %q", body)
		}
	}

	check(http.StatusOK)
	if err := ts.Store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	check(http.StatusServiceUnavailable)
}
