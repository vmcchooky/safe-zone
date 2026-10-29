package server

import (
	"io/fs"
	"net/http"

	"safe-zone/internal/agent"
	apiapp "safe-zone/internal/api/app"
	"safe-zone/internal/api/handlers"
)

// NewRouter constructs a new ServeMux with all the routes registered.
//
// API routes come from the table in routes.go, which is the single source of
// truth for paths and auth wrappers and the contract the OpenAPI parity test
// asserts against docs/openapi/safe-zone.yaml. The "/" catch-all and the
// static/operator-UI mounts below are presentation concerns and stay outside
// that table.
func NewRouter(h *handlers.Handler, agentEngine *agent.Engine, assetsFS fs.FS, appFS fs.FS) *http.ServeMux {
	mux := http.NewServeMux()

	var rootHandler http.HandlerFunc
	if appFS != nil {
		rootHandler = apiapp.RedirectPublicRoot
	} else {
		// UI-less builds must not leak the full status payload on "/".
		rootHandler = h.RequireAuthFunc(h.StatusHandler)
	}
	mux.HandleFunc("/", rootHandler)

	registerAPIRoutes(mux, h, agentEngine)

	// Static Assets & Operator UI
	if assetsFS != nil {
		mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(assetsFS))))
	}
	if appFS != nil {
		mux.HandleFunc("/app-background.avif", apiapp.RedirectLegacyBackground)
		mux.HandleFunc("/favicon.ico", apiapp.RedirectFavicon)
		mux.HandleFunc("/robots.txt", apiapp.Robots)
		mux.HandleFunc(apiapp.MountPath, apiapp.RedirectRoot)
		mux.Handle(apiapp.MountPath+"/", apiapp.NewHandler(appFS))
	}
	// Preserve existing dashboard bookmarks while making the React UI the only operator interface.
	mux.HandleFunc("/dashboard", apiapp.RedirectLegacyDashboard)
	mux.HandleFunc("/dashboard/", apiapp.RedirectLegacyDashboard)

	return mux
}
