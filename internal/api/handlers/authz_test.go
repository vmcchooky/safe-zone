package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/auth"
	"safe-zone/internal/config"
	"safe-zone/internal/observability"
	"safe-zone/internal/risk"
	"safe-zone/internal/store"
)

func newGuestAuthTestServer(t *testing.T) (*Handler, *store.DB, *httptest.Server) {
	t.Helper()

	tempDir := t.TempDir()
	t.Setenv("SAFE_ZONE_ADBLOCK_ENABLED", "false")

	dbPath := filepath.Join(tempDir, "guest-auth.db")
	storeDB, err := store.New(dbPath, 30)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	if err := storeDB.SetSystemConfig(context.Background(), "adblock_enabled", "false"); err != nil {
		t.Fatalf("disable background adblock sync: %v", err)
	}

	service := risk.NewService(risk.Options{
		AnalysisConfig:  config.DefaultAnalysisConfig(),
		RedisTimeout:    10 * time.Millisecond,
		Store:           storeDB,
		AdblockFileRoot: tempDir,
	})
	t.Cleanup(func() {
		_ = service.Close()
	})

	handler := New(service, observability.NewRegistry(), Config{
		DeploymentTier: "test",
		SessionSecret:  []byte("0123456789abcdef0123456789abcdef"),
		AdminPassword:  "adminpass1234",
		AdminAPIKey:    "adminkey123456789012345678",
		PublicHost:     "",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/login", handler.AuthLoginHandler)
	mux.HandleFunc("/v1/auth/logout", handler.AuthLogoutHandler)
	mux.HandleFunc("/v1/auth/session", handler.RequireAuthFunc(handler.AuthSessionHandler))
	mux.HandleFunc("/v1/settings/guest-access", handler.RequireAdminFunc(handler.GuestAccessHandler))
	mux.HandleFunc("/v1/settings/bundle", handler.RequireAdminFunc(handler.SettingsBundleHandler))
	mux.HandleFunc("/v1/overrides", handler.RequireAdminForMutationFunc(handler.OverridesHandler))
	mux.HandleFunc("/v1/settings", handler.RequireAdminFunc(handler.SettingsHandler))
	mux.HandleFunc("/v1/status", handler.StatusHandler)
	mux.HandleFunc("/dashboard", handler.DashboardHandler)
	mux.HandleFunc("/dashboard/", handler.DashboardHandler)

	testServer := httptest.NewServer(mux)
	t.Cleanup(testServer.Close)

	return handler, storeDB, testServer
}

func TestGuestAccessLifecycleAndPermissions(t *testing.T) {
	handler, storeDB, testServer := newGuestAuthTestServer(t)
	client := testServer.Client()

	createReq, err := http.NewRequest(http.MethodPost, testServer.URL+"/v1/settings/guest-access", strings.NewReader(`{"enabled":true,"password":"guestpass12"}`))
	if err != nil {
		t.Fatal(err)
	}
	createReq.Header.Set("Authorization", "Bearer "+handler.Config.AdminAPIKey)
	createReq.Header.Set("Content-Type", "application/json")

	createResp, err := client.Do(createReq)
	if err != nil {
		t.Fatal(err)
	}
	defer createResp.Body.Close()
	if createResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(createResp.Body)
		t.Fatalf("expected guest create 200, got %d: %s", createResp.StatusCode, body)
	}

	rawGuestConfig, err := storeDB.GetSystemConfig(context.Background(), guestAccessConfigKey)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rawGuestConfig, "guestpass12") {
		t.Fatal("guest password must not be stored in plaintext")
	}

	loginResp, err := client.Post(testServer.URL+"/v1/auth/login", "application/json", strings.NewReader(`{"username":"guest","password":"guestpass12"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(loginResp.Body)
		t.Fatalf("expected guest login 200, got %d: %s", loginResp.StatusCode, body)
	}

	var sessionCookie *http.Cookie
	for _, cookie := range loginResp.Cookies() {
		if cookie.Name == "admin_session" {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session cookie from guest login")
	}

	claims, err := auth.VerifySessionClaims(sessionCookie.Value, handler.Config.SessionSecret)
	if err != nil {
		t.Fatalf("verify guest session: %v", err)
	}
	if claims.Role != auth.RoleGuest {
		t.Fatalf("expected guest role in session claims, got %q", claims.Role)
	}

	dashboardReq, err := http.NewRequest(http.MethodGet, testServer.URL+"/dashboard", nil)
	if err != nil {
		t.Fatal(err)
	}
	dashboardReq.AddCookie(sessionCookie)
	dashboardResp, err := client.Do(dashboardReq)
	if err != nil {
		t.Fatal(err)
	}
	defer dashboardResp.Body.Close()
	if dashboardResp.StatusCode != http.StatusOK {
		t.Fatalf("expected dashboard 200 for guest, got %d", dashboardResp.StatusCode)
	}
	dashboardBody, _ := io.ReadAll(dashboardResp.Body)
	if !strings.Contains(string(dashboardBody), "Safe Zone Dashboard") {
		t.Fatalf("expected dashboard HTML for guest, got %s", dashboardBody)
	}

	sessionReq, err := http.NewRequest(http.MethodGet, testServer.URL+"/v1/auth/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	sessionReq.AddCookie(sessionCookie)
	sessionResp, err := client.Do(sessionReq)
	if err != nil {
		t.Fatal(err)
	}
	defer sessionResp.Body.Close()
	if sessionResp.StatusCode != http.StatusOK {
		t.Fatalf("expected session endpoint 200 for guest, got %d", sessionResp.StatusCode)
	}

	var sessionInfo authSessionResponse
	if err := json.NewDecoder(sessionResp.Body).Decode(&sessionInfo); err != nil {
		t.Fatal(err)
	}
	if sessionInfo.Role != auth.RoleGuest || !sessionInfo.ReadOnly || sessionInfo.CanMutate || sessionInfo.CanViewSettings {
		t.Fatalf("unexpected guest session info: %+v", sessionInfo)
	}
	if sessionInfo.GuestMessage != guestReadOnlyMessage {
		t.Fatalf("expected guest banner message, got %q", sessionInfo.GuestMessage)
	}

	listReq, err := http.NewRequest(http.MethodGet, testServer.URL+"/v1/overrides", nil)
	if err != nil {
		t.Fatal(err)
	}
	listReq.AddCookie(sessionCookie)
	listResp, err := client.Do(listReq)
	if err != nil {
		t.Fatal(err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("expected guest read-only overrides access 200, got %d: %s", listResp.StatusCode, body)
	}

	mutateReq, err := http.NewRequest(http.MethodPost, testServer.URL+"/v1/overrides", strings.NewReader(`{"domain":"guest-block.test","action":"block"}`))
	if err != nil {
		t.Fatal(err)
	}
	mutateReq.Header.Set("Content-Type", "application/json")
	mutateReq.Header.Set("Origin", testServer.URL)
	mutateReq.AddCookie(sessionCookie)
	mutateResp, err := client.Do(mutateReq)
	if err != nil {
		t.Fatal(err)
	}
	defer mutateResp.Body.Close()
	if mutateResp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(mutateResp.Body)
		t.Fatalf("expected guest mutation to be blocked with 403, got %d: %s", mutateResp.StatusCode, body)
	}
	body, _ := io.ReadAll(mutateResp.Body)
	if !strings.Contains(string(body), guestReadOnlyMessage) {
		t.Fatalf("expected guest read-only error message, got %s", body)
	}

	settingsReq, err := http.NewRequest(http.MethodGet, testServer.URL+"/v1/settings", nil)
	if err != nil {
		t.Fatal(err)
	}
	settingsReq.AddCookie(sessionCookie)
	settingsResp, err := client.Do(settingsReq)
	if err != nil {
		t.Fatal(err)
	}
	defer settingsResp.Body.Close()
	if settingsResp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(settingsResp.Body)
		t.Fatalf("expected guest settings access 403, got %d: %s", settingsResp.StatusCode, body)
	}

	disableReq, err := http.NewRequest(http.MethodPut, testServer.URL+"/v1/settings/guest-access", strings.NewReader(`{"enabled":false}`))
	if err != nil {
		t.Fatal(err)
	}
	disableReq.Header.Set("Authorization", "Bearer "+handler.Config.AdminAPIKey)
	disableReq.Header.Set("Content-Type", "application/json")
	disableResp, err := client.Do(disableReq)
	if err != nil {
		t.Fatal(err)
	}
	defer disableResp.Body.Close()
	if disableResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(disableResp.Body)
		t.Fatalf("expected guest disable 200, got %d: %s", disableResp.StatusCode, body)
	}

	sessionAfterDisableReq, err := http.NewRequest(http.MethodGet, testServer.URL+"/v1/auth/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	sessionAfterDisableReq.AddCookie(sessionCookie)
	sessionAfterDisableResp, err := client.Do(sessionAfterDisableReq)
	if err != nil {
		t.Fatal(err)
	}
	defer sessionAfterDisableResp.Body.Close()
	if sessionAfterDisableResp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(sessionAfterDisableResp.Body)
		t.Fatalf("expected disabled guest session to be rejected with 401, got %d: %s", sessionAfterDisableResp.StatusCode, body)
	}

	dashboardAfterDisableReq, err := http.NewRequest(http.MethodGet, testServer.URL+"/dashboard", nil)
	if err != nil {
		t.Fatal(err)
	}
	dashboardAfterDisableReq.AddCookie(sessionCookie)
	dashboardAfterDisableResp, err := client.Do(dashboardAfterDisableReq)
	if err != nil {
		t.Fatal(err)
	}
	defer dashboardAfterDisableResp.Body.Close()
	if dashboardAfterDisableResp.StatusCode != http.StatusOK {
		t.Fatalf("expected disabled guest dashboard fallback to login page, got %d", dashboardAfterDisableResp.StatusCode)
	}
	dashboardAfterDisableBody, _ := io.ReadAll(dashboardAfterDisableResp.Body)
	if !strings.Contains(string(dashboardAfterDisableBody), "Sentinel Command OS") {
		t.Fatalf("expected login HTML after guest disable, got %s", dashboardAfterDisableBody)
	}

	loginDisabledResp, err := client.Post(testServer.URL+"/v1/auth/login", "application/json", strings.NewReader(`{"username":"guest","password":"guestpass12"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer loginDisabledResp.Body.Close()
	if loginDisabledResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected disabled guest login to fail with 401, got %d", loginDisabledResp.StatusCode)
	}

	deleteReq, err := http.NewRequest(http.MethodDelete, testServer.URL+"/v1/settings/guest-access", nil)
	if err != nil {
		t.Fatal(err)
	}
	deleteReq.Header.Set("Authorization", "Bearer "+handler.Config.AdminAPIKey)
	deleteResp, err := client.Do(deleteReq)
	if err != nil {
		t.Fatal(err)
	}
	defer deleteResp.Body.Close()
	if deleteResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(deleteResp.Body)
		t.Fatalf("expected guest delete 200, got %d: %s", deleteResp.StatusCode, body)
	}

	statusReq, err := http.NewRequest(http.MethodGet, testServer.URL+"/v1/settings/guest-access", nil)
	if err != nil {
		t.Fatal(err)
	}
	statusReq.Header.Set("Authorization", "Bearer "+handler.Config.AdminAPIKey)
	statusResp, err := client.Do(statusReq)
	if err != nil {
		t.Fatal(err)
	}
	defer statusResp.Body.Close()
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("expected guest status 200, got %d", statusResp.StatusCode)
	}

	var guestStatus guestAccessStatusResponse
	if err := json.NewDecoder(statusResp.Body).Decode(&guestStatus); err != nil {
		t.Fatal(err)
	}
	if guestStatus.Exists || guestStatus.Enabled {
		t.Fatalf("expected guest account to be deleted, got %+v", guestStatus)
	}
}

func TestDashboardEmbedsAdminSessionBootstrap(t *testing.T) {
	_, _, testServer := newGuestAuthTestServer(t)
	client := testServer.Client()

	loginResp, err := client.Post(testServer.URL+"/v1/auth/login", "application/json", strings.NewReader(`{"username":"admin","password":"adminpass1234"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(loginResp.Body)
		t.Fatalf("expected admin login 200, got %d: %s", loginResp.StatusCode, body)
	}

	var sessionCookie *http.Cookie
	for _, cookie := range loginResp.Cookies() {
		if cookie.Name == "admin_session" {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected admin session cookie")
	}

	dashboardReq, err := http.NewRequest(http.MethodGet, testServer.URL+"/dashboard", nil)
	if err != nil {
		t.Fatal(err)
	}
	dashboardReq.AddCookie(sessionCookie)
	dashboardResp, err := client.Do(dashboardReq)
	if err != nil {
		t.Fatal(err)
	}
	defer dashboardResp.Body.Close()
	if dashboardResp.StatusCode != http.StatusOK {
		t.Fatalf("expected dashboard 200 for admin, got %d", dashboardResp.StatusCode)
	}

	body, err := io.ReadAll(dashboardResp.Body)
	if err != nil {
		t.Fatal(err)
	}
	content := string(body)
	for _, fragment := range []string{
		`id="session-bootstrap"`,
		`"username":"admin"`,
		`"role":"admin"`,
		`"read_only":false`,
		`"can_view_settings":true`,
	} {
		if !strings.Contains(content, fragment) {
			t.Fatalf("expected dashboard bootstrap to contain %q, got %s", fragment, content)
		}
	}
}

func TestSettingsBundleHandler(t *testing.T) {
	handler, storeDB, testServer := newGuestAuthTestServer(t)
	client := testServer.Client()

	if err := storeDB.SetSystemConfig(context.Background(), "gemini_api_key", "abcd-secret-key"); err != nil {
		t.Fatal(err)
	}
	if err := storeDB.SetSystemConfig(context.Background(), "agent_webhook_url", "https://hooks.example.test/endpoint"); err != nil {
		t.Fatal(err)
	}

	createReq, err := http.NewRequest(http.MethodPost, testServer.URL+"/v1/settings/guest-access", strings.NewReader(`{"enabled":true,"password":"guestpass12"}`))
	if err != nil {
		t.Fatal(err)
	}
	createReq.Header.Set("Authorization", "Bearer "+handler.Config.AdminAPIKey)
	createReq.Header.Set("Content-Type", "application/json")
	createResp, err := client.Do(createReq)
	if err != nil {
		t.Fatal(err)
	}
	defer createResp.Body.Close()
	if createResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(createResp.Body)
		t.Fatalf("expected guest create 200, got %d: %s", createResp.StatusCode, body)
	}

	bundleReq, err := http.NewRequest(http.MethodGet, testServer.URL+"/v1/settings/bundle", nil)
	if err != nil {
		t.Fatal(err)
	}
	bundleReq.Header.Set("Authorization", "Bearer "+handler.Config.AdminAPIKey)
	bundleResp, err := client.Do(bundleReq)
	if err != nil {
		t.Fatal(err)
	}
	defer bundleResp.Body.Close()
	if bundleResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(bundleResp.Body)
		t.Fatalf("expected settings bundle 200, got %d: %s", bundleResp.StatusCode, body)
	}

	var bundle settingsBundleResponse
	if err := json.NewDecoder(bundleResp.Body).Decode(&bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Settings.GeminiAPIKey != "abcd***********" {
		t.Fatalf("expected masked gemini api key, got %q", bundle.Settings.GeminiAPIKey)
	}
	if bundle.Settings.AgentWebhookURL == "" || !strings.HasPrefix(bundle.Settings.AgentWebhookURL, "http") {
		t.Fatalf("expected masked webhook url to retain prefix, got %q", bundle.Settings.AgentWebhookURL)
	}
	if !bundle.GuestAccess.Exists || !bundle.GuestAccess.Enabled {
		t.Fatalf("expected enabled guest access in bundle, got %+v", bundle.GuestAccess)
	}
	if bundle.AnalysisConfig.LongDomainLength == 0 {
		t.Fatalf("expected analysis config in bundle, got %+v", bundle.AnalysisConfig)
	}
}
