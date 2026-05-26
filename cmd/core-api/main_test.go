package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/auth"
	"safe-zone/internal/buildinfo"
	"safe-zone/internal/config"
	"safe-zone/internal/observability"
	"safe-zone/internal/osint"
	"safe-zone/internal/risk"
	"safe-zone/internal/serve"
	"safe-zone/internal/store"
)

func TestStatusEndpointHTTP(t *testing.T) {
	app := &app{risk: risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond}), metrics: observability.NewRegistry()}
	app.deploymentTier = "budget-vps"
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.statusHandler)
	mux.HandleFunc("/metrics", app.metricsHandler)
	testServer := httptest.NewServer(serve.WithRequestID(logRequests("core-api", mux, app.metrics)))
	defer testServer.Close()

	response, err := http.Get(testServer.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
	if got := response.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected application/json content type, got %q", got)
	}
	if response.Header.Get("X-Request-ID") == "" {
		t.Fatal("expected X-Request-ID response header")
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}

	var payload statusResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}

	if payload.Service != "core-api" {
		t.Fatalf("expected service core-api, got %s", payload.Service)
	}
	if payload.Status != "ok" {
		t.Fatalf("expected ok status, got %s", payload.Status)
	}
	if payload.Mode != "api" {
		t.Fatalf("expected api mode, got %s", payload.Mode)
	}
	if payload.DeploymentTier != "budget-vps" {
		t.Fatalf("expected budget-vps deployment tier, got %s", payload.DeploymentTier)
	}
	if payload.Redis == nil || payload.Redis.Status != "disabled" {
		t.Fatalf("expected disabled redis status, got %#v", payload.Redis)
	}
	if payload.FeedSync == nil || payload.FeedSync.Status != "disabled" {
		t.Fatalf("expected disabled feed sync status, got %#v", payload.FeedSync)
	}
	if len(payload.Endpoints) == 0 {
		t.Fatal("expected endpoint list")
	}
	if payload.Time == "" {
		t.Fatal("expected timestamp")
	}
}

func TestAnalyzeEndpointStillWorks(t *testing.T) {
	app := &app{risk: risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond}), metrics: observability.NewRegistry(), deploymentTier: "budget-vps"}
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/analyze?domain=secure-login-wallet-example.com", nil)

	app.analyzeHandler(recorder, request)

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
	if payload["domain"] == "" {
		t.Fatal("expected domain in response")
	}
}

func TestAnalyzeEndpointDetectsVietnamPublicServiceAbuse(t *testing.T) {
	app := &app{risk: risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond}), metrics: observability.NewRegistry(), deploymentTier: "budget-vps"}
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/analyze?domain=dichvucong-vn.com", nil)

	app.analyzeHandler(recorder, request)

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
}

func TestAnalyzeEndpointIncludesOSINTEvidence(t *testing.T) {
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<title>Cảnh báo giả mạo</title>baohiem-online.com là website giả mạo, lừa đảo.`))
	}))
	defer source.Close()

	app := &app{
		risk: risk.NewService(risk.Options{
			AnalysisConfig: config.DefaultAnalysisConfig(),
			RedisTimeout:   10 * time.Millisecond,
			OSINT: osint.NewService(osint.Options{
				Enabled:             true,
				Sources:             []string{source.URL},
				TrustedDomains:      []string{source.URL},
				AllowPrivateSources: true,
				CacheTTL:            time.Hour,
			}),
		}),
		metrics:        observability.NewRegistry(),
		deploymentTier: "budget-vps",
	}
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/analyze?domain=baohiem-online.com&include_evidence=1", nil)
	app.analyzeHandler(recorder, request)

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

func TestMetricsEndpointHTTP(t *testing.T) {
	app := &app{risk: risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond}), metrics: observability.NewRegistry(), deploymentTier: "budget-vps"}
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", app.metricsHandler)
	testServer := httptest.NewServer(serve.WithRequestID(logRequests("core-api", mux, app.metrics)))
	defer testServer.Close()

	response, err := http.Get(testServer.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}

	var payload map[string]any
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload["service"] != "core-api" {
		t.Fatalf("expected core-api service, got %#v", payload["service"])
	}
	feedSync, ok := payload["feed_sync"].(map[string]any)
	if !ok {
		t.Fatalf("expected feed_sync object, got %#v", payload["feed_sync"])
	}
	if feedSync["status"] != "disabled" {
		t.Fatalf("expected disabled feed_sync status, got %#v", feedSync["status"])
	}
	metrics, ok := payload["metrics"].(map[string]any)
	if !ok {
		t.Fatalf("expected metrics object, got %#v", payload["metrics"])
	}
	if _, ok := metrics["request_summary"].(map[string]any); !ok {
		t.Fatalf("expected request_summary map, got %#v", metrics["request_summary"])
	}
}

func TestVersionEndpointReportsBuildMetadata(t *testing.T) {
	restore := overrideBuildInfo("1.3.0", "abc123def", "2026-05-26T12:00:00Z", "safe-zone-core-api:1.3.0-abc123def", "https://github.com/quorix/safe-zone")
	defer restore()

	app := &app{deploymentTier: "shared-vps"}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/version", nil)
	app.versionHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var payload buildinfo.Metadata
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}

	if payload.Service != "core-api" {
		t.Fatalf("expected core-api service, got %q", payload.Service)
	}
	if payload.Version != "1.3.0" {
		t.Fatalf("expected version 1.3.0, got %q", payload.Version)
	}
	if payload.GitCommit != "abc123def" {
		t.Fatalf("expected git commit abc123def, got %q", payload.GitCommit)
	}
	if payload.BuildTime != "2026-05-26T12:00:00Z" {
		t.Fatalf("expected build time, got %q", payload.BuildTime)
	}
	if payload.ImageTag != "safe-zone-core-api:1.3.0-abc123def" {
		t.Fatalf("expected image tag, got %q", payload.ImageTag)
	}
	if payload.SourceRepo != "https://github.com/quorix/safe-zone" {
		t.Fatalf("expected source repo, got %q", payload.SourceRepo)
	}
	if payload.DeploymentTier != "shared-vps" {
		t.Fatalf("expected deployment tier shared-vps, got %q", payload.DeploymentTier)
	}
}

func TestVersionEndpointRejectsNonGet(t *testing.T) {
	app := &app{deploymentTier: "budget-vps"}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/version", nil)
	app.versionHandler(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", recorder.Code)
	}
}

func TestLogRequestsSkipsMetricsAfterRecoveredPanic(t *testing.T) {
	metrics := observability.NewRegistry()
	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})
	handler := serve.WithRequestID(logRequests("core-api", serve.Recovery(panicHandler, metrics), metrics))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/panic", nil)

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}
	snapshot := metrics.Snapshot()
	summary, ok := snapshot.RequestSummary["GET /panic 500"]
	if !ok {
		t.Fatalf("expected panic request metric, got %#v", snapshot.RequestSummary)
	}
	if summary.Count != 1 {
		t.Fatalf("expected panic request metric to be observed once, got %d", summary.Count)
	}
}

func overrideBuildInfo(version, gitCommit, buildTime, imageTag, sourceRepo string) func() {
	prevVersion := buildinfo.Version
	prevGitCommit := buildinfo.GitCommit
	prevBuildTime := buildinfo.BuildTime
	prevImageTag := buildinfo.ImageTag
	prevSourceRepo := buildinfo.SourceRepo

	buildinfo.Version = version
	buildinfo.GitCommit = gitCommit
	buildinfo.BuildTime = buildTime
	buildinfo.ImageTag = imageTag
	buildinfo.SourceRepo = sourceRepo

	return func() {
		buildinfo.Version = prevVersion
		buildinfo.GitCommit = prevGitCommit
		buildinfo.BuildTime = prevBuildTime
		buildinfo.ImageTag = prevImageTag
		buildinfo.SourceRepo = prevSourceRepo
	}
}

func TestBlockPageHandlerRendersBlockedContext(t *testing.T) {
	app := &app{
		risk:           risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond}),
		metrics:        observability.NewRegistry(),
		deploymentTier: "budget-vps",
	}
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/block?category=phishing&reason=Matched+Safe+Zone+policy", nil)
	request.Header.Set("X-Blocked-Domain", "login.example.com")
	request.Header.Set("X-Original-Path", "/signin")

	app.blockPageHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	body := recorder.Body.String()
	for _, fragment := range []string{"login.example.com", "/signin", "Matched Safe Zone policy", "Submit False-Positive Report"} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("expected block page to contain %q, got: %s", fragment, body)
		}
	}
}

func TestBlockReportHandlerStoresFalsePositiveReport(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "block-report.db")
	storeDB, err := store.New(dbPath, 30)
	if err != nil {
		t.Fatal(err)
	}

	app := &app{
		risk: risk.NewService(risk.Options{
			AnalysisConfig: config.DefaultAnalysisConfig(),
			RedisTimeout:   10 * time.Millisecond,
			Store:          storeDB,
		}),
		metrics:        observability.NewRegistry(),
		deploymentTier: "budget-vps",
	}
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	form := url.Values{
		"domain":         {"maybe-blocked.example"},
		"requested_path": {"/login"},
		"contact":        {"ops@example.com"},
		"note":           {"Business login page. Please review."},
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/block/report", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	app.blockReportHandler(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", recorder.Code)
	}
	if location := recorder.Header().Get("Location"); !strings.Contains(location, "/block?reported=1") {
		t.Fatalf("expected redirect back to block page, got %q", location)
	}

	events, err := storeDB.QueryAgentEvents(time.Now().Add(-1*time.Hour), []string{"false_positive_report"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 stored report event, got %d", len(events))
	}
	if events[0].Domain != "maybe-blocked.example" {
		t.Fatalf("expected stored report domain, got %q", events[0].Domain)
	}
	if !strings.Contains(events[0].Details, "Business login page") {
		t.Fatalf("expected report note in details, got %q", events[0].Details)
	}
}

func TestDashboardEndpointHTTP(t *testing.T) {
	sessionSecret := []byte("test_session_secret_32_bytes_long_!!!")
	app := &app{
		risk:           risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond}),
		metrics:        observability.NewRegistry(),
		deploymentTier: "budget-vps",
		sessionSecret:  sessionSecret,
		adminPassword:  "testpass",
		adminAPIKey:    "testkey",
	}
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard", app.dashboardHandler)
	mux.HandleFunc("/dashboard/", app.dashboardHandler)
	testServer := httptest.NewServer(serve.WithRequestID(logRequests("core-api", mux, app.metrics)))
	defer testServer.Close()

	// 1. Without cookie, it should show login HTML
	response, err := http.Get(testServer.URL + "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	content := string(body)
	if !strings.Contains(content, "Admin Authentication") || !strings.Contains(content, "login-form") {
		t.Fatalf("expected login page, got: %s", content)
	}

	// 2. With valid cookie, it should show dashboard HTML
	cookieVal, err := auth.GenerateSessionCookieValue("admin", 1*time.Hour, sessionSecret)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodGet, testServer.URL+"/dashboard", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{
		Name:  "admin_session",
		Value: cookieVal,
	})

	client := &http.Client{}
	response2, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response2.Body.Close()

	if response2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response2.StatusCode)
	}

	body2, err := io.ReadAll(response2.Body)
	if err != nil {
		t.Fatal(err)
	}
	content2 := string(body2)
	for _, fragment := range []string{"Safe Zone Dashboard", "Analyze domain"} {
		if !strings.Contains(content2, fragment) {
			t.Fatalf("expected dashboard content to contain %q, got: %s", fragment, content2)
		}
	}
}

func TestRestrictedAPIsAuth(t *testing.T) {
	sessionSecret := []byte("test_session_secret_32_bytes_long_!!!")
	app := &app{
		risk:           risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond}),
		metrics:        observability.NewRegistry(),
		deploymentTier: "budget-vps",
		sessionSecret:  sessionSecret,
		adminPassword:  "testpass",
		adminAPIKey:    "testkey",
	}
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/login", app.authLoginHandler)
	mux.HandleFunc("/v1/auth/logout", app.authLogoutHandler)
	mux.HandleFunc("/v1/overrides", app.requireAuthFunc(app.overridesHandler))
	mux.HandleFunc("/v1/agent/trigger", app.requireAuthFunc(agentTriggerHandler(nil)))
	testServer := httptest.NewServer(serve.WithRequestID(logRequests("core-api", mux, app.metrics)))
	defer testServer.Close()

	client := &http.Client{}

	// 1. Check REST API /v1/overrides with NO auth (expected 401 Unauthorized)
	req1, _ := http.NewRequest(http.MethodGet, testServer.URL+"/v1/overrides", nil)
	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", resp1.StatusCode)
	}

	// 2. Check REST API with WRONG Bearer Key (expected 401 Unauthorized)
	req2, _ := http.NewRequest(http.MethodGet, testServer.URL+"/v1/overrides", nil)
	req2.Header.Set("Authorization", "Bearer wrong_key")
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", resp2.StatusCode)
	}

	// 3. Check REST API with CORRECT Bearer Key (expected 200 OK)
	req3, _ := http.NewRequest(http.MethodGet, testServer.URL+"/v1/overrides", nil)
	req3.Header.Set("Authorization", "Bearer testkey")
	resp3, err := client.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp3.StatusCode)
	}

	// 4. Check REST API with CORRECT Session Cookie (expected 200 OK)
	cookieVal, err := auth.GenerateSessionCookieValue("admin", 1*time.Hour, sessionSecret)
	if err != nil {
		t.Fatal(err)
	}
	req4, _ := http.NewRequest(http.MethodGet, testServer.URL+"/v1/overrides", nil)
	req4.AddCookie(&http.Cookie{
		Name:  "admin_session",
		Value: cookieVal,
	})
	resp4, err := client.Do(req4)
	if err != nil {
		t.Fatal(err)
	}
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp4.StatusCode)
	}

	// 5. Test Login API with wrong credentials
	loginBodyWrong := `{"username": "admin", "password": "wrong_password"}`
	resp5, err := client.Post(testServer.URL+"/v1/auth/login", "application/json", strings.NewReader(loginBodyWrong))
	if err != nil {
		t.Fatal(err)
	}
	defer resp5.Body.Close()
	if resp5.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized on wrong login, got %d", resp5.StatusCode)
	}

	// 6. Test Login API with correct credentials
	loginBodyCorrect := `{"username": "admin", "password": "testpass"}`
	resp6, err := client.Post(testServer.URL+"/v1/auth/login", "application/json", strings.NewReader(loginBodyCorrect))
	if err != nil {
		t.Fatal(err)
	}
	defer resp6.Body.Close()
	if resp6.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on correct login, got %d", resp6.StatusCode)
	}

	// Read cookies from login response
	cookies := resp6.Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "admin_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected admin_session cookie to be returned")
	}

	// 7. Verify the returned cookie is valid and works for overrides API
	req7, _ := http.NewRequest(http.MethodGet, testServer.URL+"/v1/overrides", nil)
	req7.AddCookie(sessionCookie)
	resp7, err := client.Do(req7)
	if err != nil {
		t.Fatal(err)
	}
	defer resp7.Body.Close()
	if resp7.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK with login cookie, got %d", resp7.StatusCode)
	}

	reqCookiePost, _ := http.NewRequest(http.MethodPost, testServer.URL+"/v1/agent/trigger", nil)
	reqCookiePost.Header.Set("Content-Type", "application/json")
	reqCookiePost.AddCookie(sessionCookie)
	respCookiePost, err := client.Do(reqCookiePost)
	if err != nil {
		t.Fatal(err)
	}
	defer respCookiePost.Body.Close()
	if respCookiePost.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for cookie POST without Origin, got %d", respCookiePost.StatusCode)
	}

	reqOriginPost, _ := http.NewRequest(http.MethodPost, testServer.URL+"/v1/agent/trigger", nil)
	reqOriginPost.Header.Set("Content-Type", "application/json")
	reqOriginPost.Header.Set("Origin", testServer.URL)
	reqOriginPost.AddCookie(sessionCookie)
	respOriginPost, err := client.Do(reqOriginPost)
	if err != nil {
		t.Fatal(err)
	}
	defer respOriginPost.Body.Close()
	if respOriginPost.StatusCode == http.StatusForbidden || respOriginPost.StatusCode == http.StatusUnauthorized {
		t.Fatalf("expected same-origin cookie POST past auth/csrf, got %d", respOriginPost.StatusCode)
	}

	reqBearerPost, _ := http.NewRequest(http.MethodPost, testServer.URL+"/v1/agent/trigger", nil)
	reqBearerPost.Header.Set("Content-Type", "application/json")
	reqBearerPost.Header.Set("Authorization", "Bearer testkey")
	respBearerPost, err := client.Do(reqBearerPost)
	if err != nil {
		t.Fatal(err)
	}
	defer respBearerPost.Body.Close()
	if respBearerPost.StatusCode == http.StatusForbidden || respBearerPost.StatusCode == http.StatusUnauthorized {
		t.Fatalf("expected bearer POST past auth/csrf, got %d", respBearerPost.StatusCode)
	}

	// 8. Test Logout API
	req8, _ := http.NewRequest(http.MethodPost, testServer.URL+"/v1/auth/logout", nil)
	resp8, err := client.Do(req8)
	if err != nil {
		t.Fatal(err)
	}
	defer resp8.Body.Close()
	if resp8.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on logout, got %d", resp8.StatusCode)
	}

	// Verify logout cookie is expired
	logoutCookies := resp8.Cookies()
	var logoutCookie *http.Cookie
	for _, c := range logoutCookies {
		if c.Name == "admin_session" {
			logoutCookie = c
			break
		}
	}
	if logoutCookie == nil {
		t.Fatal("expected admin_session cookie to be returned in logout response")
	}
	if logoutCookie.MaxAge != -1 {
		t.Fatalf("expected MaxAge of logout cookie to be -1, got %d", logoutCookie.MaxAge)
	}
}

func TestSecurityAuditLimits(t *testing.T) {
	app := &app{
		risk:           risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond}),
		metrics:        observability.NewRegistry(),
		deploymentTier: "budget-vps",
		adminAPIKey:    "testkey",
	}
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/analyze", app.analyzeHandler)
	mux.HandleFunc("/v1/overrides", app.requireAuthFunc(app.overridesHandler))
	mux.HandleFunc("/v1/telemetry/recent", app.requireAuthFunc(app.telemetryRecentHandler))
	testServer := httptest.NewServer(mux)
	defer testServer.Close()

	client := &http.Client{}

	// 1. Send huge body (5KB) to /v1/analyze (POST) -> expect 400 Bad Request due to MaxBytesReader capping at 4KB
	hugePayload := `{"domain": "` + strings.Repeat("a", 5000) + `"}`
	resp1, err := client.Post(testServer.URL+"/v1/analyze", "application/json", strings.NewReader(hugePayload))
	if err != nil {
		t.Fatal(err)
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", resp1.StatusCode)
	}

	// 2. Send valid small body (100 bytes) to /v1/analyze (POST) -> expect 200 OK
	validPayload := `{"domain": "example.com"}`
	resp2, err := client.Post(testServer.URL+"/v1/analyze", "application/json", strings.NewReader(validPayload))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp2.StatusCode)
	}

	// 3. Test limit parameter capping in telemetry recent -> expect 200 OK and limit to be handled correctly
	req3, _ := http.NewRequest(http.MethodGet, testServer.URL+"/v1/telemetry/recent?limit=200", nil)
	req3.Header.Set("Authorization", "Bearer testkey")
	resp3, err := client.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp3.StatusCode)
	}
}
