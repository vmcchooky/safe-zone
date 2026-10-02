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

func hasBearerPrefix(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// bearerMatches reports whether the request presents the configured admin
// API key. Both the enforcing and the annotating auth path call this so the
// two can never disagree about what counts as a valid bearer credential.
//
// An empty presented token and an empty configured key never match. Without
// that guard the comparison degenerates to sha256("") == sha256(""), which
// authenticates a bare "Authorization: Bearer " header as admin on every
// route whenever AdminAPIKey is unset (e.g. an embedder that constructs
// handlers.Config itself).
//
// The comparison uses ConstantTimeCompare over SHA-256 digests to keep the
// check free of length- and byte-dependent timing.
func (h *Handler) bearerMatches(r *http.Request) bool {
	if !hasBearerPrefix(r) {
		return false
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" || h.Config.AdminAPIKey == "" {
		return false
	}

	tokenHash := sha256.Sum256([]byte(token))
	expectedHash := sha256.Sum256([]byte(h.Config.AdminAPIKey))
	return subtle.ConstantTimeCompare(tokenHash[:], expectedHash[:]) == 1
}

func (h *Handler) RequireAuthFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Check Authorization Header for static API Key
		if h.bearerMatches(r) {
			identity := authIdentity{Username: h.adminUsername(), Role: auth.RoleAdmin, AuthMethod: "bearer"}
			next(w, r.WithContext(withAuthIdentity(r.Context(), identity)))
			return
		}

		// 2. Check Session Cookie
		cookie, err := r.Cookie("admin_session")
		if err == nil && cookie.Value != "" {
			claims, err := auth.VerifySessionClaims(cookie.Value, h.Config.SessionSecret)
			if err == nil {
				if claims.Role == auth.RoleAdmin {
					// Admin sessions are revocable: the signed claims carry a
					// session ID whose fingerprint must be active in the
					// store. Legacy stateless tokens (no session ID) are
					// rejected, forcing a fresh login.
					if claims.SessionID == "" {
						clearSessionCookie(w, r)
						httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
						return
					}
					store := h.Risk.StoreDB()
					if store == nil || !store.Enabled() {
						httputil.WriteError(w, http.StatusServiceUnavailable, "session validation unavailable")
						return
					}
					active, dbErr := store.AdminSessionActive(r.Context(), auth.SessionFingerprint(claims.SessionID))
					if dbErr != nil {
						// Fail closed: an unavailable session store must not
						// wave authenticated requests through.
						httputil.WriteError(w, http.StatusServiceUnavailable, "session validation unavailable")
						return
					}
					if !active {
						clearSessionCookie(w, r)
						httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
						return
					}
				}
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
				if isStateChangingMethod(r.Method) {
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

// AttachAuthIdentityFunc annotates the request with the caller identity
// when valid credentials are present, but never rejects. It exists for
// endpoints that stay public while gating specific capabilities on
// authenticated callers (e.g. force_osint on /v1/analyze, which triggers
// outbound OSINT fetches). Side-effect free: unlike RequireAuthFunc it
// never clears cookies and never writes error responses.
func (h *Handler) AttachAuthIdentityFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if identity, ok := h.tryAuthIdentity(r); ok {
			next(w, r.WithContext(withAuthIdentity(r.Context(), identity)))
			return
		}
		next(w, r)
	}
}

// tryAuthIdentity mirrors the credential validation of RequireAuthFunc
// (constant-time bearer compare, revocable admin sessions, guest config
// check) without any of its side effects.
//
// It deliberately fails closed on a *present but invalid* bearer token
// instead of falling through to the cookie, so a caller cannot reach an
// authenticated capability by sending a stale Authorization header. The
// bearer comparison itself is shared with RequireAuthFunc via
// bearerMatches; only this fall-through policy is specific to the
// annotating variant.
func (h *Handler) tryAuthIdentity(r *http.Request) (authIdentity, bool) {
	if hasBearerPrefix(r) {
		if !h.bearerMatches(r) {
			return authIdentity{}, false
		}
		return authIdentity{Username: h.adminUsername(), Role: auth.RoleAdmin, AuthMethod: "bearer"}, true
	}
	cookie, err := r.Cookie("admin_session")
	if err != nil || cookie.Value == "" {
		return authIdentity{}, false
	}
	claims, err := auth.VerifySessionClaims(cookie.Value, h.Config.SessionSecret)
	if err != nil {
		return authIdentity{}, false
	}
	if claims.Role == auth.RoleAdmin {
		if claims.SessionID == "" {
			return authIdentity{}, false
		}
		store := h.Risk.StoreDB()
		if store == nil || !store.Enabled() {
			return authIdentity{}, false
		}
		active, dbErr := store.AdminSessionActive(r.Context(), auth.SessionFingerprint(claims.SessionID))
		if dbErr != nil || !active {
			return authIdentity{}, false
		}
	}
	if err := h.ensureGuestSessionActive(r.Context(), claims); err != nil {
		return authIdentity{}, false
	}
	return authIdentity{Username: claims.Username, Role: claims.Role, AuthMethod: "cookie"}, true
}
