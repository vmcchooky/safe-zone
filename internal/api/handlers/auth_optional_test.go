package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"safe-zone/internal/auth"
)

// AttachAuthIdentityFunc must annotate valid credentials but never reject:
// anonymous and wrong-credential callers proceed without an identity.
func TestAttachAuthIdentityNeverRejects(t *testing.T) {
	ts := newHandlerTestServer(t)

	var got authIdentity
	var ok bool
	next := func(_ http.ResponseWriter, r *http.Request) {
		got, ok = authIdentityFromRequest(r)
	}
	wrapped := ts.Handler.AttachAuthIdentityFunc(next)

	// Anonymous: proceeds, no identity (force_osint stays off downstream).
	req := httptest.NewRequest(http.MethodGet, "/v1/analyze?domain=x.test&force_osint=1", nil)
	wrapped(httptest.NewRecorder(), req)
	if ok {
		t.Fatalf("anonymous request must not carry identity, got %+v", got)
	}

	// Wrong bearer: proceeds, no identity.
	req = httptest.NewRequest(http.MethodGet, "/v1/analyze?domain=x.test", nil)
	req.Header.Set("Authorization", "Bearer wrongkey")
	wrapped(httptest.NewRecorder(), req)
	if ok {
		t.Fatalf("wrong bearer must not carry identity, got %+v", got)
	}

	// Correct bearer: admin identity attached.
	req = httptest.NewRequest(http.MethodGet, "/v1/analyze?domain=x.test", nil)
	ts.addAdminBearer(req)
	wrapped(httptest.NewRecorder(), req)
	if !ok || !got.isAdmin() {
		t.Fatalf("valid bearer must attach admin identity, got %+v ok=%v", got, ok)
	}

	// Admin session cookie: identity attached.
	req = httptest.NewRequest(http.MethodGet, "/v1/analyze?domain=x.test", nil)
	req.AddCookie(ts.adminSessionCookie(t))
	wrapped(httptest.NewRecorder(), req)
	if !ok || !got.isAdmin() {
		t.Fatalf("valid admin cookie must attach identity, got %+v ok=%v", got, ok)
	}

	// Empty bearer token against an empty key must never match
	// (stricter than the legacy RequireAuthFunc comparison).
	bare := &Handler{}
	req = httptest.NewRequest(http.MethodGet, "/v1/analyze?domain=x.test", nil)
	req.Header.Set("Authorization", "Bearer ")
	bare.AttachAuthIdentityFunc(next)(httptest.NewRecorder(), req)
	if ok {
		t.Fatal("empty bearer must not match empty key")
	}
}

// force_osint=1 only takes effect for authenticated callers; anonymous
// callers get normal analysis without forced outbound OSINT.
func TestForceOSINTForRequestRequiresAuth(t *testing.T) {
	anon := httptest.NewRequest(http.MethodGet, "/v1/analyze?domain=x.test&force_osint=1", nil)
	if forceOSINTForRequest(anon) {
		t.Fatal("anonymous force_osint=1 must be ignored")
	}

	authed := httptest.NewRequest(http.MethodGet, "/v1/analyze?domain=x.test&force_osint=1", nil)
	authed = authed.WithContext(withAuthIdentity(authed.Context(),
		authIdentity{Username: "admin", Role: auth.RoleAdmin, AuthMethod: "bearer"}))
	if !forceOSINTForRequest(authed) {
		t.Fatal("authenticated force_osint=1 must be honored")
	}

	noParam := httptest.NewRequest(http.MethodGet, "/v1/analyze?domain=x.test", nil)
	noParam = noParam.WithContext(withAuthIdentity(noParam.Context(),
		authIdentity{Username: "admin", Role: auth.RoleAdmin, AuthMethod: "bearer"}))
	if forceOSINTForRequest(noParam) {
		t.Fatal("missing force_osint must stay off even when authenticated")
	}
}
