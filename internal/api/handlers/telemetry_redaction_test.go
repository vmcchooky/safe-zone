package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/auth"
	"safe-zone/internal/store"
)

type telemetryRecentResponse struct {
	Items []struct {
		Domain   string `json:"domain"`
		Verdict  string `json:"verdict"`
		Source   string `json:"source"`
		ClientIP string `json:"client_ip"`
		ClientID string `json:"client_id"`
	} `json:"items"`
	Redacted bool `json:"redacted"`
}

// enableGuestAccount provisions the optional read-only guest account and
// returns a signed guest session cookie for it.
func enableGuestAccount(t *testing.T, ts *handlerTestServer) *http.Cookie {
	t.Helper()

	body := strings.NewReader(`{"password":"guestpass12"}`)
	req, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/settings/guest-access", body)
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
		t.Fatalf("guest access create = %d, want 200", resp.StatusCode)
	}

	loginResp, err := ts.Client.Post(ts.Server.URL+"/v1/auth/login", "application/json",
		strings.NewReader(`{"username":"guest","password":"guestpass12"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("guest login = %d, want 200", loginResp.StatusCode)
	}
	for _, cookie := range loginResp.Cookies() {
		if cookie.Name == "admin_session" {
			return cookie
		}
	}
	t.Fatal("guest login did not set a session cookie")
	return nil
}

func fetchTelemetryRecent(t *testing.T, ts *handlerTestServer, addAuth func(*http.Request)) telemetryRecentResponse {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/telemetry/recent", nil)
	if err != nil {
		t.Fatal(err)
	}
	if addAuth != nil {
		addAuth(req)
	}
	resp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("telemetry recent = %d, want 200", resp.StatusCode)
	}

	var payload telemetryRecentResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode telemetry recent: %v", err)
	}
	return payload
}

func seedTelemetry(t *testing.T, ts *handlerTestServer) {
	t.Helper()

	ts.Store.RecordAnalysis(store.TelemetryEntry{
		Domain:     "seed-phish.example",
		Verdict:    "BLOCKED",
		Score:      90,
		Confidence: 0.99,
		Reasons:    []string{"threat_feed"},
		Source:     "dns",
		AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
		ClientIP:   "203.0.113.7",
		ClientID:   "doh-client-abc",
	})
}

// A non-admin caller must not be able to enumerate which clients resolved
// through this server. Every recent row is written from the anonymous
// /v1/analyze path, so client_ip and client_id are client PII.
func TestTelemetryRecentRedactsClientIdentityForGuest(t *testing.T) {
	ts := newHandlerTestServer(t)
	seedTelemetry(t, ts)

	admin := fetchTelemetryRecent(t, ts, ts.addAdminBearer)
	if len(admin.Items) == 0 {
		t.Fatal("expected a seeded telemetry row")
	}
	if admin.Items[0].ClientIP != "203.0.113.7" || admin.Items[0].ClientID != "doh-client-abc" {
		t.Fatalf("admin must see client identity, got ip=%q id=%q", admin.Items[0].ClientIP, admin.Items[0].ClientID)
	}
	if admin.Redacted {
		t.Fatal("admin response must not be marked redacted")
	}

	guestCookie := enableGuestAccount(t, ts)
	guest := fetchTelemetryRecent(t, ts, func(r *http.Request) { r.AddCookie(guestCookie) })
	if len(guest.Items) == 0 {
		t.Fatal("expected the guest to still see the telemetry row")
	}
	if guest.Items[0].ClientIP != "" || guest.Items[0].ClientID != "" {
		t.Fatalf("guest must not receive client identity, got ip=%q id=%q", guest.Items[0].ClientIP, guest.Items[0].ClientID)
	}
	// The useful analysis fields must survive redaction: the guest keeps
	// dashboard visibility, only the identifiers are stripped.
	if guest.Items[0].Domain != "seed-phish.example" || guest.Items[0].Verdict != "BLOCKED" || guest.Items[0].Source != "dns" {
		t.Fatalf("guest lost non-identifying fields: %+v", guest.Items[0])
	}
	if !guest.Redacted {
		t.Fatal("guest response must be marked redacted so the UI can explain the gap")
	}
}

// The redacted fields are omitempty, so they must be absent from the payload
// rather than present and empty.
func TestTelemetryRecentOmitsIdentityKeysForGuest(t *testing.T) {
	ts := newHandlerTestServer(t)
	seedTelemetry(t, ts)
	guestCookie := enableGuestAccount(t, ts)

	req, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/telemetry/recent", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(guestCookie)
	resp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var raw struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.Items) == 0 {
		t.Fatal("expected a seeded row")
	}
	for _, key := range []string{"client_ip", "client_id"} {
		if _, present := raw.Items[0][key]; present {
			t.Fatalf("guest payload must omit %q entirely, got %#v", key, raw.Items[0][key])
		}
	}
}

// Aggregate stats stay available to guests: they carry no per-client
// identifiers and power the dashboard charts.
func TestTelemetryStatsRemainAvailableToGuest(t *testing.T) {
	ts := newHandlerTestServer(t)
	seedTelemetry(t, ts)
	guestCookie := enableGuestAccount(t, ts)

	req, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/telemetry/stats", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(guestCookie)
	resp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("guest telemetry stats = %d, want 200", resp.StatusCode)
	}
}

// Redaction is role-based, not identity-based: a bearer-key caller is an
// administrator, a guest session and any non-admin role are not. A request
// with no identity at all is also redacted, so a future route change that
// drops the auth wrapper cannot silently re-expose client PII.
func TestRedactTelemetryIdentitiesKeysOnAdminRole(t *testing.T) {
	tests := []struct {
		name     string
		identity *authIdentity
		want     bool // expected `redacted` value
	}{
		{name: "admin", identity: &authIdentity{Role: auth.RoleAdmin}, want: false},
		{name: "guest", identity: &authIdentity{Role: auth.RoleGuest}, want: true},
		{name: "unknown role", identity: &authIdentity{Role: "viewer"}, want: true},
		{name: "no identity", identity: nil, want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "/v1/telemetry/recent", nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.identity != nil {
				req = req.WithContext(withAuthIdentity(req.Context(), *tc.identity))
			}

			identity, present := authIdentityFromRequest(req)
			isAdmin := present && identity.isAdmin()
			if isAdmin == tc.want {
				t.Fatalf("isAdmin = %v, want %v", isAdmin, !tc.want)
			}

			entries := []store.TelemetryEntry{{
				Domain:   "x.example",
				ClientIP: "203.0.113.7",
				ClientID: "doh-client-abc",
			}}
			if !isAdmin {
				redactTelemetryIdentities(entries)
			}

			if entries[0].Domain != "x.example" {
				t.Fatal("redaction must not touch analysis fields")
			}
			if tc.want && (entries[0].ClientIP != "" || entries[0].ClientID != "") {
				t.Fatalf("identifiers survived: ip=%q id=%q", entries[0].ClientIP, entries[0].ClientID)
			}
			if !tc.want && (entries[0].ClientIP == "" || entries[0].ClientID == "") {
				t.Fatal("admin must keep the identifiers")
			}
		})
	}
}

// `redacted` describes the policy applied to the response, so it stays true
// for a non-admin caller even when the page is empty. Reporting "did we change
// a row" made it false exactly when a client could not otherwise tell whether
// it had been filtered.
func TestRedactedFlagReportsPolicyNotRowChanges(t *testing.T) {
	ts := newHandlerTestServer(t)
	guestCookie := enableGuestAccount(t, ts)

	// No telemetry rows at all, so nothing could have been modified.
	empty := fetchTelemetryRecent(t, ts, func(r *http.Request) { r.AddCookie(guestCookie) })
	if len(empty.Items) != 0 {
		t.Fatalf("expected an empty page, got %d rows", len(empty.Items))
	}
	if !empty.Redacted {
		t.Fatal("an empty guest page must still report redacted=true: the policy applied")
	}

	// Seed, then confirm the flag is unchanged and the row is still stripped.
	seedTelemetry(t, ts)
	after := fetchTelemetryRecent(t, ts, func(r *http.Request) { r.AddCookie(guestCookie) })
	if len(after.Items) == 0 {
		t.Fatal("expected the seeded row")
	}
	if !after.Redacted {
		t.Fatal("redacted must stay true for a guest with rows present")
	}
	if after.Items[0].ClientIP != "" {
		t.Fatalf("guest still received client_ip %q", after.Items[0].ClientIP)
	}
}
