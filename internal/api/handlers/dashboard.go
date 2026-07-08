package handlers

import (
	"net/http"
	"safe-zone/internal/api/httputil"
	"safe-zone/internal/api/views"
	"safe-zone/internal/auth"
)

func (h *Handler) DashboardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Read cookie
	cookie, err := r.Cookie("admin_session")
	if err != nil || cookie.Value == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(views.Login()))
		return
	}

	// Verify cookie
	claims, err := auth.VerifySessionClaims(cookie.Value, h.Config.SessionSecret)
	if err != nil {
		// Session is invalid or expired; clear cookie and show login page
		clearSessionCookie(w, r)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(views.Login()))
		return
	}

	if err := h.ensureGuestSessionActive(r.Context(), claims); err != nil {
		if err == errGuestAccessRevoked {
			clearSessionCookie(w, r)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(views.Login()))
			return
		}
		http.Error(w, "guest access validation unavailable", http.StatusServiceUnavailable)
		return
	}

	page, err := views.Dashboard(authSessionFromIdentity(authIdentity{
		Username:   claims.Username,
		Role:       claims.Role,
		AuthMethod: "cookie",
	}))
	if err != nil {
		http.Error(w, "failed to render dashboard", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page))
}
