package handlers

import (
	"embed"
	"encoding/json"
	"net/http"
	"safe-zone/internal/api/httputil"
	"safe-zone/internal/auth"
	"safe-zone/internal/buildinfo"
	"strings"
)

//go:embed dashboard.html
var dashboardHTML string

//go:embed login.html
var loginHTML string

//go:embed assets/*
var AssetsFS embed.FS

const sessionBootstrapPlaceholder = "__SAFE_ZONE_SESSION_BOOTSTRAP__"
const assetRevisionPlaceholder = "__SAFE_ZONE_ASSET_REV__"

func assetRevision() string {
	rev := strings.TrimSpace(buildinfo.GitCommit)
	if rev == "" || rev == "unknown" {
		rev = strings.TrimSpace(buildinfo.Version)
	}
	if rev == "" {
		rev = "dev"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	return rev
}

func renderHTMLAssets(base string) string {
	return strings.ReplaceAll(base, assetRevisionPlaceholder, assetRevision())
}

func renderLoginHTML() string {
	return renderHTMLAssets(loginHTML)
}

func renderDashboardHTML(session authSessionResponse) (string, error) {
	payload, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	page := renderHTMLAssets(dashboardHTML)
	page = strings.Replace(page, sessionBootstrapPlaceholder, string(payload), 1)
	return page, nil
}

func (h *Handler) DashboardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Read cookie
	cookie, err := r.Cookie("admin_session")
	if err != nil || cookie.Value == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(renderLoginHTML()))
		return
	}

	// Verify cookie
	claims, err := auth.VerifySessionClaims(cookie.Value, h.Config.SessionSecret)
	if err != nil {
		// Session is invalid or expired; clear cookie and show login page
		clearSessionCookie(w, r)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(renderLoginHTML()))
		return
	}

	if err := h.ensureGuestSessionActive(r.Context(), claims); err != nil {
		if err == errGuestAccessRevoked {
			clearSessionCookie(w, r)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(renderLoginHTML()))
			return
		}
		http.Error(w, "guest access validation unavailable", http.StatusServiceUnavailable)
		return
	}

	page, err := renderDashboardHTML(authSessionFromIdentity(authIdentity{
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
