package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/auth"
	"safe-zone/internal/config"
	"safe-zone/internal/observability"
	"safe-zone/internal/risk"
	"safe-zone/internal/serve"
	"safe-zone/internal/store"
)

type handlerTestServer struct {
	Handler *Handler
	Store   *store.DB
	Server  *httptest.Server
	Client  *http.Client
}

func newHandlerTestServer(t *testing.T) *handlerTestServer {
	t.Helper()

	tempDir := t.TempDir()
	t.Setenv("SAFE_ZONE_ADBLOCK_ENABLED", "false")

	dbPath := filepath.Join(tempDir, "handlers.db")
	storeDB, err := store.New(dbPath, 30)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	if err := storeDB.SetSystemConfig(context.Background(), "adblock_enabled", "false"); err != nil {
		t.Fatalf("disable adblock sync: %v", err)
	}

	riskService := risk.NewService(risk.Options{
		AnalysisConfig:           config.DefaultAnalysisConfig(),
		RedisTimeout:             10 * time.Millisecond,
		ConfigReloadEnabled:      true,
		Store:                    storeDB,
		AdblockFileRoot:          tempDir,
		ConfigReloadPollInterval: 50 * time.Millisecond,
	})
	t.Cleanup(func() {
		_ = riskService.Close()
	})

	handler := New(riskService, observability.NewRegistry(), Config{
		DeploymentTier:    "test",
		SessionSecret:     []byte("0123456789abcdef0123456789abcdef"),
		AdminPasswordHash: testAdminPasswordHash(),
		AdminAPIKey:       "adminkey123456789012345678",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/", handler.StatusHandler)
	mux.HandleFunc("/v1/status", handler.StatusHandler)
	mux.HandleFunc("/metrics", handler.MetricsHandler)
	mux.HandleFunc("/v1/version", handler.VersionHandler)
	mux.HandleFunc("/block", handler.BlockPageHandler)
	mux.HandleFunc("/block/report", handler.BlockReportHandler)
	mux.HandleFunc("/v1/analyze", handler.AnalyzeHandler)
	mux.HandleFunc("/v1/analysis/recent", handler.RequireAuthFunc(handler.RecentAnalysisHandler))
	mux.HandleFunc("/v1/auth/login", handler.AuthLoginHandler)
	mux.HandleFunc("/v1/auth/logout", handler.AuthLogoutHandler)
	mux.HandleFunc("/v1/auth/session", handler.RequireAuthFunc(handler.AuthSessionHandler))
	mux.HandleFunc("/v1/settings/guest-access", handler.RequireAdminFunc(handler.GuestAccessHandler))
	mux.HandleFunc("/v1/settings", handler.RequireAdminFunc(handler.SettingsHandler))
	mux.HandleFunc("/v1/settings/bundle", handler.RequireAdminFunc(handler.SettingsBundleHandler))
	mux.HandleFunc("/v1/settings/test-ai", handler.RequireAdminFunc(handler.TestAIHandler))
	mux.HandleFunc("/v1/settings/test-alert", handler.RequireAdminFunc(handler.TestAlertHandler))
	mux.HandleFunc("/v1/config/analysis", handler.RequireAdminFunc(handler.AnalysisConfigHandler))
	mux.HandleFunc("/v1/config/analysis/reset", handler.RequireAdminFunc(handler.AnalysisConfigResetHandler))
	mux.HandleFunc("/v1/overrides", handler.RequireAdminForMutationFunc(handler.OverridesHandler))
	mux.HandleFunc("/v1/overrides/review-false-positive", handler.RequireAdminFunc(handler.ReviewFalsePositiveHandler))
	mux.HandleFunc("/v1/telemetry/recent", handler.RequireAuthFunc(handler.TelemetryRecentHandler))
	mux.HandleFunc("/v1/reports", handler.RequireAdminFunc(handler.ListReportsHandler))
	mux.HandleFunc("/v1/reports/status", handler.RequireAdminFunc(handler.UpdateReportStatusHandler))
	mux.HandleFunc("/v1/agent/trigger", handler.RequireAdminFunc(AgentTriggerHandler(nil)))
	mux.HandleFunc("/dashboard", handler.DashboardHandler)
	mux.HandleFunc("/dashboard/", handler.DashboardHandler)

	server := httptest.NewServer(serve.WithRequestID(httputil.LogRequests("core-api", handler.Metrics)(mux)))
	t.Cleanup(server.Close)

	return &handlerTestServer{
		Handler: handler,
		Store:   storeDB,
		Server:  server,
		Client:  server.Client(),
	}
}

func (s *handlerTestServer) addAdminBearer(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+s.Handler.Config.AdminAPIKey)
}

func (s *handlerTestServer) adminSessionCookie(t *testing.T) *http.Cookie {
	t.Helper()
	return s.adminSessionCookieWithTTL(t, time.Hour)
}

// adminSessionCookieWithTTL mints a revocable admin session: the fingerprint
// is persisted in the store, exactly like the real login handler does.
func (s *handlerTestServer) adminSessionCookieWithTTL(t *testing.T, ttl time.Duration) *http.Cookie {
	t.Helper()

	sessionID, err := auth.GenerateSecureRandomString(32)
	if err != nil {
		t.Fatalf("generate session id: %v", err)
	}
	if err := s.Store.CreateAdminSession(context.Background(), auth.SessionFingerprint(sessionID), "admin", time.Now().Add(ttl)); err != nil {
		t.Fatalf("persist admin session: %v", err)
	}
	token, err := auth.GenerateSessionCookieValueForRole("admin", auth.RoleAdmin, sessionID, ttl, s.Handler.Config.SessionSecret)
	if err != nil {
		t.Fatalf("generate admin session cookie: %v", err)
	}
	return &http.Cookie{
		Name:  "admin_session",
		Value: token,
	}
}

var (
	testAdminHashOnce sync.Once
	testAdminHash     string
)

// testAdminPasswordHash computes the bcrypt hash for "adminpass1234" once
// per test binary.
func testAdminPasswordHash() string {
	testAdminHashOnce.Do(func() {
		hash, err := auth.HashPassword("adminpass1234")
		if err != nil {
			panic(err)
		}
		testAdminHash = hash
	})
	return testAdminHash
}
