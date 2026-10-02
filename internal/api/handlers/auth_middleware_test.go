package handlers

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// Regression probe for the empty-bearer admin bypass, written against the
// exported middleware only so it compiles against both the vulnerable and the
// fixed code. A bare "Authorization: Bearer " header against a Handler whose
// AdminAPIKey was never configured must be rejected, not hashed-and-accepted
// as admin (sha256("") == sha256("")) on every route.
func TestRequireAuthFuncRejectsEmptyBearerWhenAPIKeyUnset(t *testing.T) {
	handler := &Handler{Config: Config{AdminUsername: "admin"}}

	for _, header := range []string{"Bearer ", "Bearer", "Bearer  "} {
		t.Run(strconv.Quote(header), func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/settings", nil)
			req.Header.Set("Authorization", header)

			rec := httptest.NewRecorder()
			handler.RequireAuthFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401: an unset API key must never accept a bearer token", rec.Code)
			}
		})
	}
}

// bearerCredentialCase pins one (Authorization header, configured API key)
// pair to the verdict every auth path must agree on.
type bearerCredentialCase struct {
	name       string
	authHeader string
	apiKey     string
	wantBearer bool
}

// bearerCredentialCases is the shared matrix. The empty-token/empty-key row
// is the regression this file exists for: sha256("") == sha256("") made a
// bare "Authorization: Bearer " header authenticate as admin on every route
// whenever handlers.Config.AdminAPIKey was left empty. Only the annotating
// path (tryAuthIdentity) had the guard; the enforcing path did not.
var bearerCredentialCases = []bearerCredentialCase{
	{name: "no authorization header", authHeader: "", apiKey: "adminkey123456789012345678", wantBearer: false},
	{name: "configured key presented", authHeader: "Bearer adminkey123456789012345678", apiKey: "adminkey123456789012345678", wantBearer: true},
	{name: "wrong key presented", authHeader: "Bearer wrongkey", apiKey: "adminkey123456789012345678", wantBearer: false},
	{name: "key differing only in case", authHeader: "Bearer ADMINKEY123456789012345678", apiKey: "adminkey123456789012345678", wantBearer: false},
	{name: "empty token against configured key", authHeader: "Bearer ", apiKey: "adminkey123456789012345678", wantBearer: false},
	{name: "real token against empty configured key", authHeader: "Bearer adminkey123456789012345678", apiKey: "", wantBearer: false},
	{name: "empty token against empty configured key", authHeader: "Bearer ", apiKey: "", wantBearer: false},
	{name: "scheme without separator space", authHeader: "Bearer", apiKey: "adminkey123456789012345678", wantBearer: false},
	{name: "token is only whitespace", authHeader: "Bearer  ", apiKey: "adminkey123456789012345678", wantBearer: false},
	{name: "key without scheme", authHeader: "adminkey123456789012345678", apiKey: "adminkey123456789012345678", wantBearer: false},
}

func newBearerRequest(authHeader string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/v1/settings", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	return req
}

// bearerMatches is the single source of truth for what a valid bearer
// credential is.
func TestBearerMatchesRejectsDegenerateCredentials(t *testing.T) {
	for _, tc := range bearerCredentialCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &Handler{Config: Config{AdminAPIKey: tc.apiKey}}
			if got := handler.bearerMatches(newBearerRequest(tc.authHeader)); got != tc.wantBearer {
				t.Fatalf("bearerMatches = %v, want %v", got, tc.wantBearer)
			}
		})
	}
}

// The enforcing and annotating paths used to drift: the annotating path
// guarded against an empty token while the enforcing path did not, so the
// same request could be treated as admin by one and anonymous by the other.
// Every row must now produce the same verdict on both.
func TestAuthPathsAgreeOnBearerCredential(t *testing.T) {
	for _, tc := range bearerCredentialCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &Handler{Config: Config{AdminAPIKey: tc.apiKey}}

			// Enforcing path: 200 only for a valid bearer (no cookie present).
			rec := httptest.NewRecorder()
			handler.RequireAuthFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})(rec, newBearerRequest(tc.authHeader))

			wantCode := http.StatusUnauthorized
			if tc.wantBearer {
				wantCode = http.StatusOK
			}
			if rec.Code != wantCode {
				t.Fatalf("RequireAuthFunc = %d, want %d", rec.Code, wantCode)
			}

			// Annotating path: identity present exactly when the bearer is valid.
			identity, ok := handler.tryAuthIdentity(newBearerRequest(tc.authHeader))
			if ok != tc.wantBearer {
				t.Fatalf("tryAuthIdentity ok = %v, want %v", ok, tc.wantBearer)
			}
			if ok && !identity.isAdmin() {
				t.Fatalf("valid bearer must yield an admin identity, got %+v", identity)
			}
		})
	}
}

// A valid bearer must attach the admin identity through the annotating path
// exactly as the enforcing path does, so force_osint gating and admin routes
// cannot disagree about who the caller is.
func TestValidBearerYieldsAdminIdentityOnBothPaths(t *testing.T) {
	const apiKey = "adminkey123456789012345678"
	handler := &Handler{Config: Config{AdminAPIKey: apiKey, AdminUsername: "admin"}}

	var enforced authIdentity
	handler.RequireAuthFunc(func(w http.ResponseWriter, r *http.Request) {
		enforced, _ = authIdentityFromRequest(r)
		w.WriteHeader(http.StatusOK)
	})(httptest.NewRecorder(), newBearerRequest("Bearer "+apiKey))

	annotated, ok := handler.tryAuthIdentity(newBearerRequest("Bearer " + apiKey))
	if !ok {
		t.Fatal("tryAuthIdentity must accept the configured key")
	}
	if enforced != annotated {
		t.Fatalf("paths disagree: enforcing=%+v annotating=%+v", enforced, annotated)
	}
	if !enforced.isAdmin() || enforced.AuthMethod != "bearer" {
		t.Fatalf("expected admin bearer identity, got %+v", enforced)
	}
}

// tryAuthIdentity fails closed on a present-but-invalid bearer instead of
// falling back to the cookie, so a stale Authorization header cannot be used
// to reach an authenticated capability while a valid session cookie is also
// attached. RequireAuthFunc keeps its original fall-through for cookie
// clients; this test pins that the difference is deliberate.
func TestInvalidBearerFailsClosedOnAnnotatingPathOnly(t *testing.T) {
	ts := newHandlerTestServer(t)
	cookie := ts.adminSessionCookie(t)

	annotating := &Handler{Config: Config{AdminAPIKey: ts.Handler.Config.AdminAPIKey, SessionSecret: ts.Handler.Config.SessionSecret, AdminUsername: "admin"}}

	req := newBearerRequest("Bearer stale-token")
	req.AddCookie(cookie)
	if _, ok := annotating.tryAuthIdentity(req); ok {
		t.Fatal("tryAuthIdentity must reject an invalid bearer even with a valid cookie")
	}

	enforcing := ts.Handler
	rec := httptest.NewRecorder()
	var sawIdentity bool
	enforcing.RequireAuthFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, sawIdentity = authIdentityFromRequest(r)
	})(rec, req)
	if rec.Code != http.StatusOK || !sawIdentity {
		t.Fatalf("RequireAuthFunc must fall through to the cookie, got code=%d identity=%v", rec.Code, sawIdentity)
	}
}
