package handlers

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/auth"
	"safe-zone/internal/config"
	"safe-zone/internal/logjson"
	"safe-zone/internal/ratelimit"
)

type authIdentity struct {
	Username   string `json:"username"`
	Role       string `json:"role"`
	AuthMethod string `json:"auth_method,omitempty"`
}

type authIdentityContextKey struct{}

func (id authIdentity) isAdmin() bool {
	return id.Role == auth.RoleAdmin
}

func authSessionFromIdentity(id authIdentity) authSessionResponse {
	resp := authSessionResponse{
		Username:        id.Username,
		Role:            id.Role,
		ReadOnly:        !id.isAdmin(),
		CanMutate:       id.isAdmin(),
		CanViewSettings: id.isAdmin(),
	}
	if !id.isAdmin() {
		resp.GuestMessage = guestReadOnlyMessage
	}
	return resp
}

func withAuthIdentity(ctx context.Context, identity authIdentity) context.Context {
	return context.WithValue(ctx, authIdentityContextKey{}, identity)
}

func authIdentityFromContext(ctx context.Context) (authIdentity, bool) {
	identity, ok := ctx.Value(authIdentityContextKey{}).(authIdentity)
	return identity, ok
}

func authIdentityFromRequest(r *http.Request) (authIdentity, bool) {
	if r == nil {
		return authIdentity{}, false
	}
	return authIdentityFromContext(r.Context())
}

func writeGuestReadOnlyError(w http.ResponseWriter) {
	httputil.WriteError(w, http.StatusForbidden, guestReadOnlyMessage)
}

// secureCookieEnv forces the Secure cookie attribute regardless of how the
// request arrived. It exists for deployments that terminate TLS somewhere the
// app cannot observe.
const secureCookieEnv = "SAFE_ZONE_FORCE_SECURE_COOKIES"

// forceSecureCookies reports the operator's explicit Secure-cookie policy.
func forceSecureCookies() bool {
	return config.Bool(secureCookieEnv, config.IsProduction())
}

// forwardedProtoWarned keeps the warning to one line per process. The
// condition is a deployment mistake, not an event, so it must not become log
// noise on every login.
var forwardedProtoWarned sync.Once

// isHTTPS decides whether the session cookie must carry the Secure
// attribute. It never trusts a client-supplied value on its own: a bare
// "X-Forwarded-Proto: http" header from an attacker would otherwise strip
// Secure from the cookie the app is about to issue, letting the admin
// session travel over plaintext.
//
// The forwarded header is only considered when the socket peer is an
// operator-declared trusted proxy (SAFE_ZONE_TRUSTED_PROXIES, shared with
// the rate limiter so there is one trust boundary). Otherwise the decision
// comes from configuration, which the client cannot influence.
//
// That fallback is a behaviour regression to watch for: before this change a
// proxy's header was always honoured, so a deployment that terminates TLS
// somewhere and forgot to declare the proxy would have gotten Secure=true.
// It now falls back to configuration instead, which can be false outside
// production. Hence the warning.
func isHTTPS(r *http.Request) bool {
	if r == nil {
		return forceSecureCookies()
	}
	if r.TLS != nil {
		return true
	}
	forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if forwarded != "" {
		if requestFromTrustedProxy(r) {
			if strings.EqualFold(forwarded, "https") {
				return true
			}
		} else {
			forwardedProtoWarned.Do(func() {
				logjson.Warn("ignoring X-Forwarded-Proto from an untrusted peer; add the proxy to SAFE_ZONE_TRUSTED_PROXIES if it terminates TLS", map[string]any{
					"service":           "core-api",
					"remote_addr":       r.RemoteAddr,
					"forwarded_proto":   forwarded,
					"env":               ratelimit.TrustedProxiesEnv,
					"secure_cookie_env": secureCookieEnv,
				})
			})
		}
	}
	return forceSecureCookies()
}

// requestFromTrustedProxy reports whether the request's socket address is
// inside the operator-declared trusted proxy list.
func requestFromTrustedProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	for _, network := range ratelimit.TrustedProxies() {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure is dynamically set via isHTTPS(r)
		Name:     "admin_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}
