package handlers

import (
	"embed"
	"net/http"
	"safe-zone/internal/api/httputil"
	"safe-zone/internal/auth"
)

//go:embed dashboard.html
var dashboardHTML string

//go:embed login.html
var loginHTML string

//go:embed assets/*
var AssetsFS embed.FS

func (h *Handler) DashboardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Read cookie
	cookie, err := r.Cookie("admin_session")
	if err != nil || cookie.Value == "" {
		_, _ = w.Write([]byte(loginHTML))
		return
	}

	// Verify cookie
	_, err = auth.VerifySessionCookieValue(cookie.Value, h.Config.SessionSecret)
	if err != nil {
		// Session is invalid or expired; clear cookie and show login page
		http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure is dynamically set via isHTTPS(r)
			Name:     "admin_session",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   isHTTPS(r),
			SameSite: http.SameSiteLaxMode,
		})
		_, _ = w.Write([]byte(loginHTML))
		return
	}

	_, _ = w.Write([]byte(dashboardHTML))
}
