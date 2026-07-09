package server

import (
	"io/fs"
	"net/http"

	"safe-zone/internal/agent"
	apiapp "safe-zone/internal/api/app"
	"safe-zone/internal/api/handlers"
	"safe-zone/internal/serve"
)

// NewRouter constructs a new ServeMux with all the routes registered.
func NewRouter(h *handlers.Handler, agentEngine *agent.Engine, assetsFS fs.FS, appFS fs.FS) *http.ServeMux {
	mux := http.NewServeMux()

	// System & Health
	mux.HandleFunc("/", h.StatusHandler)
	mux.HandleFunc("/v1/status", h.StatusHandler)
	mux.HandleFunc("/healthz", handlers.HealthHandler("core-api"))
	mux.HandleFunc("/readyz", handlers.HealthHandler("core-api"))
	mux.HandleFunc("/v1/version", h.VersionHandler)
	mux.HandleFunc("/metrics", h.MetricsHandler)

	// Block Pages
	mux.HandleFunc("/block", h.BlockPageHandler)
	mux.HandleFunc("/block/report", h.BlockReportHandler)

	// Authentication
	mux.HandleFunc("/v1/auth/login", h.AuthLoginHandler)
	mux.HandleFunc("/v1/auth/logout", h.AuthLogoutHandler)
	mux.HandleFunc("/v1/auth/session", h.RequireAuthFunc(h.AuthSessionHandler))

	// Analysis & OSINT
	mux.HandleFunc("/v1/analyze", h.AnalyzeHandler)
	mux.HandleFunc("/v1/analyze/raw", h.RawDataHandler)
	mux.HandleFunc("/v1/osint/evidence", h.RequireAuthFunc(h.OsintEvidenceHandler))
	mux.HandleFunc("/v1/analysis/recent", h.RecentAnalysisHandler)

	// Admin / Overrides
	mux.HandleFunc("/v1/overrides", h.RequireAdminForMutationFunc(h.OverridesHandler))
	mux.HandleFunc("/v1/overrides/review-false-positive", h.RequireAdminFunc(h.ReviewFalsePositiveHandler))

	// Reports
	mux.HandleFunc("/v1/reports", h.RequireAuthFunc(h.ListReportsHandler))
	mux.HandleFunc("/v1/reports/status", h.RequireAdminFunc(h.UpdateReportStatusHandler))

	// Brands
	mux.HandleFunc("/v1/brands", h.RequireAdminForMutationFunc(serve.BrandHandler(h.Risk)))

	// Telemetry
	mux.HandleFunc("/v1/telemetry/recent", h.RequireAuthFunc(h.TelemetryRecentHandler))
	mux.HandleFunc("/v1/telemetry/stats", h.RequireAuthFunc(h.TelemetryStatsHandler))

	// Agent & System control
	mux.HandleFunc("/v1/agent/status", h.RequireAuthFunc(h.AgentStatusHandler(agentEngine)))
	mux.HandleFunc("/v1/agent/trigger", h.RequireAdminFunc(handlers.AgentTriggerHandler(agentEngine)))

	// Groups & Mappings
	mux.HandleFunc("/v1/groups", h.RequireAdminForMutationFunc(h.GroupsHandler))
	mux.HandleFunc("/v1/mappings", h.RequireAdminForMutationFunc(h.MappingsHandler))
	mux.HandleFunc("/v1/group-overrides", h.RequireAdminForMutationFunc(h.GroupOverridesHandler))

	// Settings & Testing
	mux.HandleFunc("/v1/settings", h.RequireAdminFunc(h.SettingsHandler))
	mux.HandleFunc("/v1/settings/bundle", h.RequireAdminFunc(h.SettingsBundleHandler))
	mux.HandleFunc("/v1/settings/test-ai", h.RequireAdminFunc(h.TestAIHandler))
	mux.HandleFunc("/v1/settings/test-alert", h.RequireAdminFunc(h.TestAlertHandler))
	mux.HandleFunc("/v1/settings/guest-access", h.RequireAdminFunc(h.GuestAccessHandler))

	// Config
	mux.HandleFunc("/v1/config/analysis", h.RequireAdminFunc(h.AnalysisConfigHandler))
	mux.HandleFunc("/v1/config/analysis/reset", h.RequireAdminFunc(h.AnalysisConfigResetHandler))

	// Static Assets & Dashboard
	if assetsFS != nil {
		mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(assetsFS))))
	}
	if appFS != nil {
		mux.HandleFunc(apiapp.MountPath, apiapp.RedirectRoot)
		mux.Handle(apiapp.MountPath+"/", apiapp.NewHandler(appFS))
	}
	mux.HandleFunc("/dashboard", h.DashboardHandler)
	mux.HandleFunc("/dashboard/", h.DashboardHandler)

	return mux
}
