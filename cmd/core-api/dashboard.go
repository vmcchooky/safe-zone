package main

import (
	"embed"
	"net/http"
	"safe-zone/internal/auth"
)

//go:embed dashboard.html
var dashboardHTML string

//go:embed login.html
var loginHTML string

//go:embed assets/*
var assetsFS embed.FS

func (a *app) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
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
	_, err = auth.VerifySessionCookieValue(cookie.Value, a.sessionSecret)
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
