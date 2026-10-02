package handlers

import (
	"crypto/tls"
	"net/http/httptest"
	"strings"
	"testing"

	"safe-zone/internal/ratelimit"
)

func trustLoopbackOnly(t *testing.T) {
	t.Helper()
	previous := ratelimit.TrustedProxies()
	loopback, err := ratelimit.ParseTrustedProxies(ratelimit.DefaultTrustedProxies)
	if err != nil {
		t.Fatalf("parse loopback list: %v", err)
	}
	ratelimit.SetTrustedProxies(loopback)
	t.Cleanup(func() { ratelimit.SetTrustedProxies(previous) })
}

func trustComposeBridge(t *testing.T) {
	t.Helper()
	previous := ratelimit.TrustedProxies()
	trusted, err := ratelimit.ParseTrustedProxies("172.16.0.0/12")
	if err != nil {
		t.Fatalf("parse trusted list: %v", err)
	}
	ratelimit.SetTrustedProxies(trusted)
	t.Cleanup(func() { ratelimit.SetTrustedProxies(previous) })
}

// cookieSecureFlag performs a real admin login and reports the Secure
// attribute of the issued session cookie. It goes through the login handler
// rather than calling isHTTPS directly, so the test observes the cookie a
// browser would actually receive.
func cookieSecureFlag(t *testing.T, ts *handlerTestServer, remoteAddr, forwardedProto string) bool {
	t.Helper()

	r := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(`{"username":"admin","password":"adminpass1234"}`))
	r.RemoteAddr = remoteAddr
	if forwardedProto != "" {
		r.Header.Set("X-Forwarded-Proto", forwardedProto)
	}

	rec := httptest.NewRecorder()
	ts.Handler.AuthLoginHandler(rec, r)

	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "admin_session" {
			return cookie.Secure
		}
	}
	t.Fatalf("login did not issue a session cookie (status %d)", rec.Code)
	return false
}

// The core regression: a client-supplied header must not be able to clear the
// Secure attribute from the session cookie. With no TLS and an operator
// policy of "always secure", a spoofed X-Forwarded-Proto: http must still
// yield a Secure cookie.
func TestSessionCookieStaysSecureDespiteClientHeader(t *testing.T) {
	trustLoopbackOnly(t)
	t.Setenv("SAFE_ZONE_FORCE_SECURE_COOKIES", "true")
	ts := newHandlerTestServer(t)

	for _, header := range []string{"http", "HTTP", "", "https", "https, http", "http, https"} {
		name := header
		if name == "" {
			name = "(absent)"
		}
		t.Run(name, func(t *testing.T) {
			if !cookieSecureFlag(t, ts, "203.0.113.9:1234", header) {
				t.Fatalf("cookie must be Secure for forwarded-proto %q", header)
			}
		})
	}
}

// When the operator has not forced Secure and the request did not arrive over
// TLS, the cookie follows plain HTTP. This is the local-dev path and must not
// break, or the dashboard is unusable over http://localhost.
func TestSessionCookieOmitsSecureWhenOperatorAllowsPlainHTTP(t *testing.T) {
	trustLoopbackOnly(t)
	t.Setenv("SAFE_ZONE_FORCE_SECURE_COOKIES", "false")
	t.Setenv("SAFE_ZONE_ENV", "local")
	ts := newHandlerTestServer(t)

	if cookieSecureFlag(t, ts, "203.0.113.9:1234", "http") {
		t.Fatal("cookie must not be Secure when the operator allows plain HTTP")
	}
}

// A trusted reverse proxy terminating TLS is the supported production
// topology, so its forwarded header must still be honoured. The same header
// from a peer outside the trust list is ignored.
func TestSessionCookieHonoursForwardedProtoFromTrustedProxy(t *testing.T) {
	t.Setenv("SAFE_ZONE_FORCE_SECURE_COOKIES", "false")
	ts := newHandlerTestServer(t)

	trustComposeBridge(t)
	if !cookieSecureFlag(t, ts, "172.18.0.5:5000", "https") {
		t.Fatal("a trusted proxy reporting https must produce a Secure cookie")
	}

	trustLoopbackOnly(t)
	if cookieSecureFlag(t, ts, "203.0.113.9:1234", "https") {
		t.Fatal("an untrusted peer must not be able to set the cookie's Secure attribute")
	}
}

// A direct TLS connection is always secure regardless of configuration.
func TestSessionCookieSecureOnDirectTLS(t *testing.T) {
	trustLoopbackOnly(t)
	t.Setenv("SAFE_ZONE_FORCE_SECURE_COOKIES", "false")

	r := httptest.NewRequest("GET", "/v1/auth/session", nil)
	r.TLS = &tls.ConnectionState{}
	if !isHTTPS(r) {
		t.Fatal("a direct TLS connection must count as secure")
	}
}

// isHTTPS must not panic on a nil request. Neither call site passes one today,
// but the sibling accessors in this file (authIdentityFromRequest) do
// nil-check, so the asymmetry was a trap for the next caller.
func TestIsHTTPSHandlesNilRequest(t *testing.T) {
	t.Setenv("SAFE_ZONE_FORCE_SECURE_COOKIES", "true")
	if !isHTTPS(nil) {
		t.Fatal("a nil request must fall back to the operator policy, which forces Secure here")
	}
	t.Setenv("SAFE_ZONE_FORCE_SECURE_COOKIES", "false")
	if isHTTPS(nil) {
		t.Fatal("a nil request must not claim TLS")
	}
}

// A malformed or absent RemoteAddr must fail closed to "not a trusted proxy"
// rather than panic.
func TestRequestFromTrustedProxyHandlesOddAddresses(t *testing.T) {
	trustComposeBridge(t)

	for _, addr := range []string{"", "not-an-ip", "203.0.113.9", "203.0.113.9:99999", "unix", "[::1]"} {
		r := httptest.NewRequest("GET", "/v1/auth/session", nil)
		r.RemoteAddr = addr
		if requestFromTrustedProxy(r) {
			t.Fatalf("RemoteAddr %q must not be treated as a trusted proxy", addr)
		}
	}
}
