package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/auth"
	"safe-zone/internal/config"
)

func (h *Handler) RequireAuthFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Check Authorization Header for static API Key
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")

			// Use ConstantTimeCompare with SHA-256 hashing to secure token comparisons against timing attacks
			tokenHash := sha256.Sum256([]byte(token))
			expectedHash := sha256.Sum256([]byte(h.Config.AdminAPIKey))

			if subtle.ConstantTimeCompare(tokenHash[:], expectedHash[:]) == 1 {
				identity := authIdentity{Username: auth.RoleAdmin, Role: auth.RoleAdmin, AuthMethod: "bearer"}
				next(w, r.WithContext(withAuthIdentity(r.Context(), identity)))
				return
			}
		}

		// 2. Check Session Cookie
		cookie, err := r.Cookie("admin_session")
		if err == nil && cookie.Value != "" {
			claims, err := auth.VerifySessionClaims(cookie.Value, h.Config.SessionSecret)
			if err == nil {
				if err := h.ensureGuestSessionActive(r.Context(), claims); err != nil {
					if err == errGuestAccessRevoked {
						clearSessionCookie(w, r)
						httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
						return
					}
					httputil.WriteError(w, http.StatusServiceUnavailable, "guest access validation unavailable")
					return
				}

				// Cookie auth is active. Enforce CSRF protection for state-modifying requests.
				if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
					if csrfErr := h.VerifyCSRF(r); csrfErr != nil {
						httputil.WriteError(w, http.StatusForbidden, "CSRF verification failed: "+csrfErr.Error())
						return
					}
				}
				identity := authIdentity{
					Username:   claims.Username,
					Role:       claims.Role,
					AuthMethod: "cookie",
				}
				next(w, r.WithContext(withAuthIdentity(r.Context(), identity)))
				return
			}
		}

		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
	}
}

func isStateChangingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func (h *Handler) ValidCSRFSources(r *http.Request) bool {
	source := strings.TrimSpace(r.Header.Get("Origin"))
	if source == "" {
		source = strings.TrimSpace(r.Header.Get("Referer"))
	}
	if source == "" {
		return false
	}

	parsed, err := url.Parse(source)
	if err != nil || parsed.Host == "" {
		return false
	}

	sourceHost := canonicalRequestHost(parsed.Host)
	for _, allowed := range []string{r.Host, h.Config.PublicHost, config.String("SAFE_ZONE_PUBLIC_HOST", "")} {
		if sourceHost == canonicalRequestHost(allowed) {
			return true
		}
	}
	return false
}

func (h *Handler) VerifyCSRF(r *http.Request) error {
	if !h.ValidCSRFSources(r) {
		return fmt.Errorf("invalid csrf origin or referer")
	}
	return nil
}

func canonicalRequestHost(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil {
			value = parsed.Host
		}
	}
	value = strings.TrimSuffix(value, "/")
	if host, port, err := net.SplitHostPort(value); err == nil {
		if port == "80" || port == "443" {
			return host
		}
		return net.JoinHostPort(host, port)
	}
	return value
}
