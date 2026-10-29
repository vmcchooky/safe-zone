package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestValidCSRFSources pins the CSRF origin gate end to end: the allowed
// candidate set is (in order) the request Host, the configured PublicHost,
// and SAFE_ZONE_PUBLIC_HOST; the evidence header is Origin first with
// Referer as the fallback; hosts are compared after canonicalisation, which
// strips the default ports but keeps non-default ones significant.
func TestValidCSRFSources(t *testing.T) {
	handler := &Handler{Config: Config{PublicHost: "dash.example.com"}}

	tests := []struct {
		name          string
		host          string
		origin        string
		referer       string
		publicHostEnv string
		want          bool
	}{
		{name: "same-host origin accepted", host: "api.example.com", origin: "http://api.example.com", want: true},
		{name: "same-host with default port accepted", host: "api.example.com", origin: "https://api.example.com:443", want: true},
		{name: "same-host with odd port rejected", host: "api.example.com", origin: "https://api.example.com:8443", want: false},
		{name: "referer used when origin absent", host: "api.example.com", referer: "https://api.example.com/app/settings", want: true},
		{name: "origin wins over cross-site referer", host: "api.example.com", origin: "https://api.example.com", referer: "https://evil.example/x", want: true},
		{name: "cross-site origin rejected", host: "api.example.com", origin: "https://evil.example", want: false},
		{name: "no evidence headers rejected", host: "api.example.com", want: false},
		{name: "configured PublicHost accepted", host: "api.example.com", origin: "https://dash.example.com", want: true},
		{name: "env public host accepted", host: "api.example.com", origin: "https://zone.example.vn", publicHostEnv: "zone.example.vn", want: true},
		{name: "host case-insensitive", host: "api.example.com", origin: "https://API.EXAMPLE.COM", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SAFE_ZONE_PUBLIC_HOST", tt.publicHostEnv)
			req := httptest.NewRequest(http.MethodPost, "/v1/overrides", nil)
			req.Host = tt.host
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}

			if got := handler.ValidCSRFSources(req); got != tt.want {
				t.Fatalf("ValidCSRFSources = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestBearerCredentialsTakePrecedenceOverSessionCookie covers the one
// credential-combination the existing tests leave open: a request carrying a
// valid bearer key AND a valid session cookie takes the bearer path, which
// is exempt from the CSRF gate — observable as a cookie-mutation succeeding
// with no Origin header while the cookie session itself stays untouched.
func TestBearerCredentialsTakePrecedenceOverSessionCookie(t *testing.T) {
	ts := newHandlerTestServer(t)
	sessionCookie := ts.adminSessionCookie(t)

	both := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	both.Host = ts.Server.Listener.Addr().String()
	both.Header.Set("Authorization", "Bearer adminkey123456789012345678")
	both.AddCookie(sessionCookie)
	bothRec := httptest.NewRecorder()
	ts.Handler.RequireAuthFunc(ts.Handler.AuthLogoutHandler)(bothRec, both)

	if bothRec.Code != http.StatusOK {
		t.Fatalf("bearer+cookie logout = %d, want 200 (bearer path skips the CSRF gate)", bothRec.Code)
	}

	// Contrast: the same request with the cookie alone is CSRF-rejected
	// before the handler runs (TestLogoutRequiresCSRFForCookieSessions), so
	// the 200 above can only come from the bearer path.
}
