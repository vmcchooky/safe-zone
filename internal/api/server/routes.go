package server

import (
	"net/http"

	"safe-zone/internal/agent"
	"safe-zone/internal/api/handlers"
	"safe-zone/internal/serve"
)

// RouteAuth mirrors the middleware wrapper NewRouter applies to a route. It
// is part of the registered-route contract the OpenAPI parity test asserts
// against docs/openapi/safe-zone.yaml: a route's auth label must match the
// security declarations on its spec path.
type RouteAuth string

const (
	// AuthPublic routes answer without credentials.
	AuthPublic RouteAuth = "public"
	// AuthAttachIdentity routes are public but annotate an authenticated
	// caller when credentials are presented (/v1/analyze).
	AuthAttachIdentity RouteAuth = "attach-identity"
	// AuthAny routes accept the admin API key or any session (admin or
	// read-only guest).
	AuthAny RouteAuth = "auth"
	// AuthAdmin routes require the admin role for every method.
	AuthAdmin RouteAuth = "admin"
	// AuthAdminMutation routes accept any session for reads but require the
	// admin role for POST/PUT/PATCH/DELETE.
	AuthAdminMutation RouteAuth = "admin-mutation"
)

// RouteSpec is one API route registered by NewRouter. Methods lists the
// methods the handler answers with non-404/405; the handler itself remains
// the method authority (they can change without touching this table), while
// Path and Auth are the contract: NewRouter registers exactly this table and
// the OpenAPI parity test diffs it against the spec.
type RouteSpec struct {
	Path    string
	Methods []string
	Auth    RouteAuth
}

// apiRoutes is the registration table for every API route NewRouter serves —
// the "/" catch-all and the static/operator-UI mounts below NewRouter's loop
// are deliberately outside it. Registration order is preserved here.
func apiRoutes() []RouteSpec {
	return []RouteSpec{
		// System & health
		{Path: "/v1/status", Methods: []string{"GET"}, Auth: AuthAny},
		{Path: "/healthz", Methods: []string{"GET"}, Auth: AuthPublic},
		{Path: "/readyz", Methods: []string{"GET"}, Auth: AuthPublic},
		{Path: "/v1/version", Methods: []string{"GET"}, Auth: AuthPublic},
		// /metrics is admin-only: the per-endpoint request summary lets any
		// authenticated caller fingerprint the API surface and read
		// 401/403/429 rates — a brute-force progress signal. The read-only
		// guest role passes RequireAuthFunc, so this stays RequireAdminFunc;
		// see ops/alerts/safe-zone-alert-rules.yaml and
		// ops/grafana/safe-zone-dashboard.json.
		{Path: "/metrics", Methods: []string{"GET"}, Auth: AuthAdmin},
		{Path: "/metrics/prometheus", Methods: []string{"GET"}, Auth: AuthAdmin},
		{Path: "/v1/cache/flush", Methods: []string{"POST"}, Auth: AuthAdminMutation},
		{Path: "/v1/logs/export", Methods: []string{"GET"}, Auth: AuthAdmin},

		// Block pages
		{Path: "/block", Methods: []string{"GET"}, Auth: AuthPublic},
		{Path: "/block/report", Methods: []string{"POST"}, Auth: AuthPublic},

		// Authentication
		{Path: "/v1/auth/login", Methods: []string{"POST"}, Auth: AuthPublic},
		// Logout is wrapped so the CSRF gate runs: it revokes the persisted
		// session, so a cross-site POST must not be able to force a revocation.
		{Path: "/v1/auth/logout", Methods: []string{"POST"}, Auth: AuthAny},
		{Path: "/v1/auth/session", Methods: []string{"GET"}, Auth: AuthAny},

		// Analysis & OSINT. /v1/analyze stays public, but AttachAuthIdentity
		// annotates authed callers so AnalyzeHandler can gate force_osint
		// (outbound OSINT) on authentication instead of any anonymous client.
		{Path: "/v1/analyze", Methods: []string{"GET", "POST"}, Auth: AuthAttachIdentity},
		{Path: "/v1/url-ml/feedback", Methods: []string{"POST"}, Auth: AuthAny},
		{Path: "/v1/analyze/raw", Methods: []string{"GET"}, Auth: AuthAny},
		{Path: "/v1/osint/evidence", Methods: []string{"GET"}, Auth: AuthAny},
		{Path: "/v1/analysis/recent", Methods: []string{"GET"}, Auth: AuthAny},

		// Overrides & reports
		{Path: "/v1/overrides", Methods: []string{"GET", "POST", "DELETE"}, Auth: AuthAdminMutation},
		{Path: "/v1/overrides/review-false-positive", Methods: []string{"POST"}, Auth: AuthAdmin},
		{Path: "/v1/reports", Methods: []string{"GET"}, Auth: AuthAdmin},
		{Path: "/v1/reports/status", Methods: []string{"POST"}, Auth: AuthAdmin},

		// Brands
		{Path: "/v1/brands", Methods: []string{"GET", "POST", "PUT", "DELETE"}, Auth: AuthAdminMutation},

		// Telemetry
		{Path: "/v1/telemetry/recent", Methods: []string{"GET"}, Auth: AuthAny},
		{Path: "/v1/telemetry/stats", Methods: []string{"GET"}, Auth: AuthAny},

		// Agent
		{Path: "/v1/agent/status", Methods: []string{"GET"}, Auth: AuthAny},
		{Path: "/v1/agent/trigger", Methods: []string{"POST"}, Auth: AuthAdmin},
		{Path: "/v1/agent/proposals", Methods: []string{"GET", "POST"}, Auth: AuthAdminMutation},

		// Whitelist rollback. The allow list is replaced wholesale by an
		// import, so the operator needs a way to inspect the rollback copies
		// and to undo a bad one. Both endpoints are admin-only: a rollback
		// changes what the resolver answers with.
		{Path: "/v1/whitelist/snapshots", Methods: []string{"GET"}, Auth: AuthAdmin},
		{Path: "/v1/whitelist/rollback", Methods: []string{"POST"}, Auth: AuthAdmin},

		// Groups & mappings
		{Path: "/v1/groups", Methods: []string{"GET", "POST", "PUT", "DELETE"}, Auth: AuthAdminMutation},
		{Path: "/v1/mappings", Methods: []string{"GET", "POST", "DELETE"}, Auth: AuthAdminMutation},
		{Path: "/v1/group-overrides", Methods: []string{"GET", "POST", "PUT", "DELETE"}, Auth: AuthAdminMutation},

		// Settings
		{Path: "/v1/settings", Methods: []string{"GET", "POST"}, Auth: AuthAdmin},
		{Path: "/v1/settings/bundle", Methods: []string{"GET"}, Auth: AuthAdmin},
		{Path: "/v1/settings/test-ai", Methods: []string{"POST"}, Auth: AuthAdmin},
		{Path: "/v1/settings/test-alert", Methods: []string{"POST"}, Auth: AuthAdmin},
		{Path: "/v1/settings/guest-access", Methods: []string{"GET", "POST", "PUT", "DELETE"}, Auth: AuthAdmin},

		// Analysis config
		{Path: "/v1/config/analysis", Methods: []string{"GET", "PUT"}, Auth: AuthAdmin},
		{Path: "/v1/config/analysis/reset", Methods: []string{"POST"}, Auth: AuthAdmin},
	}
}

// apiHandlers maps every path in apiRoutes to its raw (unwrapped) handler.
// NewRouter applies the middleware from the route's Auth label, so the map
// must never carry a pre-wrapped handler. A table path without a handler is
// an invariant violation and fails router construction loudly.
func apiHandlers(h *handlers.Handler, agentEngine *agent.Engine) map[string]http.Handler {
	return map[string]http.Handler{
		"/v1/status":          http.HandlerFunc(h.StatusHandler),
		"/healthz":            handlers.HealthHandler("core-api"),
		"/readyz":             serve.ReadinessHandler("core-api", h.Metrics, h.Risk.ReadinessChecks()...),
		"/v1/version":         http.HandlerFunc(h.VersionHandler),
		"/metrics":            http.HandlerFunc(h.MetricsHandler),
		"/metrics/prometheus": http.HandlerFunc(h.MetricsPrometheusHandler),
		"/v1/cache/flush":     http.HandlerFunc(h.CacheFlushHandler),
		"/v1/logs/export":     http.HandlerFunc(h.LogsExportHandler),

		"/block":        http.HandlerFunc(h.BlockPageHandler),
		"/block/report": http.HandlerFunc(h.BlockReportHandler),

		"/v1/auth/login":   http.HandlerFunc(h.AuthLoginHandler),
		"/v1/auth/logout":  http.HandlerFunc(h.AuthLogoutHandler),
		"/v1/auth/session": http.HandlerFunc(h.AuthSessionHandler),

		"/v1/analyze":         http.HandlerFunc(h.AnalyzeHandler),
		"/v1/url-ml/feedback": http.HandlerFunc(h.URLMLFeedbackHandler),
		"/v1/analyze/raw":     http.HandlerFunc(h.RawDataHandler),
		"/v1/osint/evidence":  http.HandlerFunc(h.OsintEvidenceHandler),
		"/v1/analysis/recent": http.HandlerFunc(h.RecentAnalysisHandler),

		"/v1/overrides":                       http.HandlerFunc(h.OverridesHandler),
		"/v1/overrides/review-false-positive": http.HandlerFunc(h.ReviewFalsePositiveHandler),
		"/v1/reports":                         http.HandlerFunc(h.ListReportsHandler),
		"/v1/reports/status":                  http.HandlerFunc(h.UpdateReportStatusHandler),

		"/v1/brands": serve.BrandHandler(h.Risk),

		"/v1/telemetry/recent": http.HandlerFunc(h.TelemetryRecentHandler),
		"/v1/telemetry/stats":  http.HandlerFunc(h.TelemetryStatsHandler),

		"/v1/agent/status":    h.AgentStatusHandler(agentEngine),
		"/v1/agent/trigger":   handlers.AgentTriggerHandler(agentEngine),
		"/v1/agent/proposals": http.HandlerFunc(h.AgentProposalsHandler),

		"/v1/whitelist/snapshots": http.HandlerFunc(h.WhitelistSnapshotHandler),
		"/v1/whitelist/rollback":  http.HandlerFunc(h.WhitelistRollbackHandler),

		"/v1/groups":          http.HandlerFunc(h.GroupsHandler),
		"/v1/mappings":        http.HandlerFunc(h.MappingsHandler),
		"/v1/group-overrides": http.HandlerFunc(h.GroupOverridesHandler),

		"/v1/settings":              http.HandlerFunc(h.SettingsHandler),
		"/v1/settings/bundle":       http.HandlerFunc(h.SettingsBundleHandler),
		"/v1/settings/test-ai":      http.HandlerFunc(h.TestAIHandler),
		"/v1/settings/test-alert":   http.HandlerFunc(h.TestAlertHandler),
		"/v1/settings/guest-access": http.HandlerFunc(h.GuestAccessHandler),

		"/v1/config/analysis":       http.HandlerFunc(h.AnalysisConfigHandler),
		"/v1/config/analysis/reset": http.HandlerFunc(h.AnalysisConfigResetHandler),
	}
}

func applyRouteAuth(h *handlers.Handler, auth RouteAuth, handler http.Handler) http.Handler {
	switch auth {
	case AuthPublic:
		return handler
	case AuthAttachIdentity:
		return h.AttachAuthIdentityFunc(handler.ServeHTTP)
	case AuthAny:
		return h.RequireAuthFunc(handler.ServeHTTP)
	case AuthAdmin:
		return h.RequireAdminFunc(handler.ServeHTTP)
	case AuthAdminMutation:
		return h.RequireAdminForMutationFunc(handler.ServeHTTP)
	default:
		panic("unknown route auth: " + string(auth))
	}
}

// SpecRoutes returns the registered API route table for the OpenAPI parity
// test. It must stay in sync with registerAPIRoutes by construction: both
// consume apiRoutes.
func SpecRoutes() []RouteSpec {
	return apiRoutes()
}

// registerAPIRoutes mounts every entry of apiRoutes with the middleware its
// Auth label calls for. It is used by NewRouter and kept here so the table,
// the handler map and the wrapper application live in one file.
func registerAPIRoutes(mux *http.ServeMux, h *handlers.Handler, agentEngine *agent.Engine) {
	handlersByPath := apiHandlers(h, agentEngine)
	for _, route := range apiRoutes() {
		handler, ok := handlersByPath[route.Path]
		if !ok {
			panic("route table has no handler for " + route.Path)
		}
		mux.Handle(route.Path, applyRouteAuth(h, route.Auth, handler))
	}
}
