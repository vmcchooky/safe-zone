package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/auth"
)

func (h *Handler) AuthLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Limit request body size to 4KB to prevent JSON memory exhaustion DoS attacks
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	defer r.Body.Close()

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	username := strings.TrimSpace(strings.ToLower(req.Username))

	// Use ConstantTimeCompare with SHA-256 hashing to secure comparisons against timing attacks
	userHash := sha256.Sum256([]byte(username))
	expectedUserHash := sha256.Sum256([]byte(auth.RoleAdmin))
	passHash := sha256.Sum256([]byte(req.Password))
	expectedPassHash := sha256.Sum256([]byte(h.Config.AdminPassword))

	userMatch := subtle.ConstantTimeCompare(userHash[:], expectedUserHash[:]) == 1
	passMatch := subtle.ConstantTimeCompare(passHash[:], expectedPassHash[:]) == 1

	role := ""
	if userMatch && passMatch {
		role = auth.RoleAdmin
	} else if username == auth.RoleGuest {
		cfg, err := h.loadGuestAccessConfig(r.Context())
		if err != nil {
			httputil.WriteError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		if cfg.Exists() && cfg.Enabled && auth.VerifyPasswordHash(cfg.PasswordHash, req.Password) == nil {
			role = auth.RoleGuest
		}
	}

	if role == "" {
		httputil.WriteError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	token, err := auth.GenerateSessionCookieValueForRole(username, role, 12*time.Hour, h.Config.SessionSecret)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to generate session")
		return
	}

	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure is dynamically set via isHTTPS(r)
		Name:     "admin_session",
		Value:    token,
		Path:     "/",
		MaxAge:   int(12 * time.Hour / time.Second),
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) AuthLogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	clearSessionCookie(w, r)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
