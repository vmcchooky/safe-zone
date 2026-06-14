package server

import (
	"io/fs"
	"net/http"

	"safe-zone/internal/agent"
	"safe-zone/internal/api/handlers"
	"safe-zone/internal/serve"
)

// NewRouter constructs a new ServeMux with all the routes registered.
func NewRouter(h *handlers.Handler, agentEngine *agent.Engine, assetsFS fs.FS) *http.ServeMux {
	mux := http.NewServeMux()

	// System & Health
	mux.HandleFunc("/", h.StatusHandler)
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

	// Analysis & OSINT
	mux.HandleFunc("/v1/analyze", h.AnalyzeHandler)
	mux.HandleFunc("/v1/osint/evidence", h.RequireAuthFunc(h.OsintEvidenceHandler))
	mux.HandleFunc("/v1/analysis/recent", h.RecentAnalysisHandler)

	// Admin / Overrides
	mux.HandleFunc("/v1/overrides", h.RequireAuthFunc(h.OverridesHandler))
	mux.HandleFunc("/v1/overrides/review-false-positive", h.RequireAuthFunc(h.ReviewFalsePositiveHandler))

	// Reports
	mux.HandleFunc("/v1/reports", h.RequireAuthFunc(h.ListReportsHandler))
	mux.HandleFunc("/v1/reports/status", h.RequireAuthFunc(h.UpdateReportStatusHandler))

	// Brands
	mux.HandleFunc("/v1/brands", h.RequireAuthFunc(serve.BrandHandler(h.Risk)))

	// Telemetry
	mux.HandleFunc("/v1/telemetry/recent", h.RequireAuthFunc(h.TelemetryRecentHandler))
	mux.HandleFunc("/v1/telemetry/stats", h.RequireAuthFunc(h.TelemetryStatsHandler))

	// Agent & System control
	mux.HandleFunc("/v1/agent/status", h.RequireAuthFunc(h.AgentStatusHandler(agentEngine)))
	mux.HandleFunc("/v1/agent/trigger", h.RequireAuthFunc(handlers.AgentTriggerHandler(agentEngine)))

	// Groups & Mappings
	mux.HandleFunc("/v1/groups", h.RequireAuthFunc(h.GroupsHandler))
	mux.HandleFunc("/v1/mappings", h.RequireAuthFunc(h.MappingsHandler))
	mux.HandleFunc("/v1/group-overrides", h.RequireAuthFunc(h.GroupOverridesHandler))

	// Settings & Testing
	mux.HandleFunc("/v1/settings", h.RequireAuthFunc(h.SettingsHandler))
	mux.HandleFunc("/v1/settings/test-ai", h.RequireAuthFunc(h.TestAIHandler))
	mux.HandleFunc("/v1/settings/test-alert", h.RequireAuthFunc(h.TestAlertHandler))

	// Config
	mux.HandleFunc("/v1/config/analysis", h.RequireAuthFunc(h.AnalysisConfigHandler))
	mux.HandleFunc("/v1/config/analysis/reset", h.RequireAuthFunc(h.AnalysisConfigResetHandler))

	// Static Assets & Dashboard
	if assetsFS != nil {
		mux.Handle("/assets/", http.FileServer(http.FS(assetsFS)))
	}
	mux.HandleFunc("/dashboard", h.DashboardHandler)
	mux.HandleFunc("/dashboard/", h.DashboardHandler)

	return mux
}
