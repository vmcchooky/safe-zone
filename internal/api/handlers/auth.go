package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/auth"
	"safe-zone/internal/logjson"
)

const (
	adminSessionTTL    = 12 * time.Hour
	adminSessionIDSize = 32
)

func (h *Handler) AuthLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Limit request body size to 4KB to prevent JSON memory exhaustion DoS attacks
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	defer func() { _ = r.Body.Close() }()

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	username := strings.TrimSpace(strings.ToLower(req.Username))

	role := ""
	var sessionID string
	switch username {
	case auth.RoleAdmin:
		if h.adminPasswordMatches(req.Password) {
			role = auth.RoleAdmin
		} else {
			// Equalize the response timing of a wrong admin password with
			// the bcrypt cost of a successful one.
			auth.CompareDummyPassword(req.Password)
		}
	case auth.RoleGuest:
		cfg, err := h.loadGuestAccessConfig(r.Context())
		if err != nil {
			logjson.Warn("guest access config unavailable at login", map[string]any{
				"service": "core-api",
				"error":   err.Error(),
			})
			httputil.WriteError(w, http.StatusServiceUnavailable, "authentication store unavailable")
			return
		}
		if cfg.Exists() && cfg.Enabled && auth.VerifyPasswordHash(cfg.PasswordHash, req.Password) == nil {
			role = auth.RoleGuest
		} else {
			auth.CompareDummyPassword(req.Password)
		}
	default:
		auth.CompareDummyPassword(req.Password)
	}

	if role == "" {
		httputil.WriteError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	// Admin sessions are persisted (fingerprint only) so they can be
	// revoked; a database failure must fail closed without issuing a cookie.
	if role == auth.RoleAdmin {
		store := h.Risk.StoreDB()
		if store == nil || !store.Enabled() {
			logjson.Warn("admin login rejected: session store unavailable", map[string]any{
				"service": "core-api",
			})
			httputil.WriteError(w, http.StatusServiceUnavailable, "session store unavailable")
			return
		}
		generated, err := auth.GenerateSecureRandomString(adminSessionIDSize)
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "failed to generate session")
			return
		}
		sessionID = generated
		if err := store.CreateAdminSession(r.Context(), auth.SessionFingerprint(sessionID), username, time.Now().Add(adminSessionTTL)); err != nil {
			logjson.Warn("admin session persistence failed", map[string]any{
				"service": "core-api",
				"error":   err.Error(),
			})
			httputil.WriteError(w, http.StatusServiceUnavailable, "session store unavailable")
			return
		}
		// Opportunistic bounded cleanup of expired/revoked rows.
		if _, err := store.CleanupExpiredAdminSessions(r.Context()); err != nil {
			logjson.Warn("admin session cleanup failed", map[string]any{
				"service": "core-api",
				"error":   err.Error(),
			})
		}
	}

	token, err := auth.GenerateSessionCookieValueForRole(username, role, sessionID, adminSessionTTL, h.Config.SessionSecret)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to generate session")
		return
	}

	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure is dynamically set via isHTTPS(r)
		Name:     "admin_session",
		Value:    token,
		Path:     "/",
		MaxAge:   int(adminSessionTTL / time.Second),
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// adminPasswordMatches compares the presented password against the bcrypt
// hash loaded at startup. An empty hash means misconfiguration: the login
// must not succeed, so it fails closed.
func (h *Handler) adminPasswordMatches(password string) bool {
	if h.Config.AdminPasswordHash == "" {
		return false
	}
	return auth.VerifyPasswordHash(h.Config.AdminPasswordHash, password) == nil
}

func (h *Handler) AuthLogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Revoke the persisted admin session before clearing the cookie so a
	// stolen copy of it is rejected on the next request. A failed revocation
	// must not be reported as success: the cookie stays in place so the
	// operator can retry while the session row remains revocable.
	if cookie, err := r.Cookie("admin_session"); err == nil && cookie.Value != "" {
		if claims, verifyErr := auth.VerifySessionClaims(cookie.Value, h.Config.SessionSecret); verifyErr == nil &&
			claims.Role == auth.RoleAdmin && claims.SessionID != "" {
			store := h.Risk.StoreDB()
			if store == nil || !store.Enabled() {
				logjson.Warn("admin logout unavailable: session store disabled", map[string]any{
					"service": "core-api",
				})
				httputil.WriteError(w, http.StatusServiceUnavailable, "session store unavailable")
				return
			}
			if err := store.RevokeAdminSession(r.Context(), auth.SessionFingerprint(claims.SessionID)); err != nil {
				logjson.Warn("admin session revoke failed", map[string]any{
					"service": "core-api",
					"error":   err.Error(),
				})
				httputil.WriteError(w, http.StatusServiceUnavailable, "session store unavailable")
				return
			}
		}
	}

	clearSessionCookie(w, r)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
