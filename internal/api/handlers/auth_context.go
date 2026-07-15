package handlers

import (
	"context"
	"net/http"
	"strings"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/auth"
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

func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.ToLower(r.Header.Get("X-Forwarded-Proto")) == "https" {
		return true
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
