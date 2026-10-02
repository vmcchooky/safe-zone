package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Logout revokes the persisted admin session row, so it must be protected by
// the same CSRF gate as every other state-changing cookie route. It was
// registered without an auth wrapper, so a cross-site form POST could force a
// revocation (session denial) against a logged-in operator.
func TestLogoutRequiresCSRFForCookieSessions(t *testing.T) {
	ts := newHandlerTestServer(t)
	sessionCookie := ts.adminSessionCookie(t)

	// A cross-site POST carries the cookie but an Origin from another site.
	// The request Host stays the real server so the Origin is the only
	// thing that does not match.
	crossSite := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	crossSite.RemoteAddr = "203.0.113.9:1234"
	crossSite.Host = ts.Server.Listener.Addr().String()
	crossSite.Header.Set("Origin", "https://evil.example")
	crossSite.AddCookie(sessionCookie)
	crossSiteRec := httptest.NewRecorder()
	ts.Handler.RequireAuthFunc(ts.Handler.AuthLogoutHandler)(crossSiteRec, crossSite)

	if crossSiteRec.Code != http.StatusForbidden {
		t.Fatalf("cross-site logout = %d, want 403: the session row must not be revoked", crossSiteRec.Code)
	}

	// The session must still be usable afterwards.
	stillValid := httptest.NewRequest(http.MethodGet, "/v1/auth/session", nil)
	stillValid.AddCookie(sessionCookie)
	stillValidRec := httptest.NewRecorder()
	ts.Handler.RequireAuthFunc(ts.Handler.AuthSessionHandler)(stillValidRec, stillValid)
	if stillValidRec.Code != http.StatusOK {
		t.Fatalf("session was revoked by a cross-site logout: %d", stillValidRec.Code)
	}

	// A same-origin POST is allowed through and does revoke the session.
	sameOrigin := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	sameOrigin.Host = ts.Server.Listener.Addr().String()
	sameOrigin.Header.Set("Origin", "http://"+sameOrigin.Host)
	sameOrigin.AddCookie(sessionCookie)
	sameOriginRec := httptest.NewRecorder()
	ts.Handler.RequireAuthFunc(ts.Handler.AuthLogoutHandler)(sameOriginRec, sameOrigin)
	if sameOriginRec.Code != http.StatusOK {
		t.Fatalf("same-origin logout = %d, want 200", sameOriginRec.Code)
	}

	afterLogout := httptest.NewRequest(http.MethodGet, "/v1/auth/session", nil)
	afterLogout.AddCookie(sessionCookie)
	afterLogoutRec := httptest.NewRecorder()
	ts.Handler.RequireAuthFunc(ts.Handler.AuthSessionHandler)(afterLogoutRec, afterLogout)
	if afterLogoutRec.Code != http.StatusUnauthorized {
		t.Fatalf("session survived a legitimate logout: %d", afterLogoutRec.Code)
	}
}

// A bearer-token request is not cookie-authenticated, so the CSRF gate must
// not apply to it and must not block a legitimate API client that sends no
// Origin at all.
func TestLogoutAllowsBearerWithoutOrigin(t *testing.T) {
	ts := newHandlerTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	ts.addAdminBearer(req)
	rec := httptest.NewRecorder()
	ts.Handler.RequireAuthFunc(ts.Handler.AuthLogoutHandler)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bearer logout = %d, want 200: CSRF must not apply to a bearer client", rec.Code)
	}

	// The clearing cookie is still issued, so a browser that happens to send
	// a bearer header is logged out of its session too.
	cleared := false
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "admin_session" && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("logout must clear the session cookie")
	}
}

func TestRestrictedAPIsAuth(t *testing.T) {
	ts := newHandlerTestServer(t)

	req1, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/overrides", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp1, err := ts.Client.Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", resp1.StatusCode)
	}

	req2, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/overrides", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Authorization", "Bearer wrong_key")
	resp2, err := ts.Client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong bearer key, got %d", resp2.StatusCode)
	}

	req3, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/overrides", nil)
	if err != nil {
		t.Fatal(err)
	}
	ts.addAdminBearer(req3)
	resp3, err := ts.Client.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with admin bearer key, got %d", resp3.StatusCode)
	}

	req4, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/overrides", nil)
	if err != nil {
		t.Fatal(err)
	}
	req4.AddCookie(ts.adminSessionCookie(t))
	resp4, err := ts.Client.Do(req4)
	if err != nil {
		t.Fatal(err)
	}
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with admin session cookie, got %d", resp4.StatusCode)
	}

	loginWrongResp, err := ts.Client.Post(ts.Server.URL+"/v1/auth/login", "application/json", strings.NewReader(`{"username":"admin","password":"wrong_password"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer loginWrongResp.Body.Close()
	if loginWrongResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on wrong login, got %d", loginWrongResp.StatusCode)
	}

	loginResp, err := ts.Client.Post(ts.Server.URL+"/v1/auth/login", "application/json", strings.NewReader(`{"username":"admin","password":"adminpass1234"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on correct login, got %d", loginResp.StatusCode)
	}

	var sessionCookie *http.Cookie
	for _, cookie := range loginResp.Cookies() {
		if cookie.Name == "admin_session" {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected admin_session cookie to be returned")
	}

	req5, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/overrides", nil)
	if err != nil {
		t.Fatal(err)
	}
	req5.AddCookie(sessionCookie)
	resp5, err := ts.Client.Do(req5)
	if err != nil {
		t.Fatal(err)
	}
	defer resp5.Body.Close()
	if resp5.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with login cookie, got %d", resp5.StatusCode)
	}

	reqCookiePost, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/agent/trigger", nil)
	if err != nil {
		t.Fatal(err)
	}
	reqCookiePost.AddCookie(sessionCookie)
	respCookiePost, err := ts.Client.Do(reqCookiePost)
	if err != nil {
		t.Fatal(err)
	}
	defer respCookiePost.Body.Close()
	if respCookiePost.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for cookie POST without Origin, got %d", respCookiePost.StatusCode)
	}

	reqOriginPost, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/agent/trigger", nil)
	if err != nil {
		t.Fatal(err)
	}
	reqOriginPost.Header.Set("Origin", ts.Server.URL)
	reqOriginPost.AddCookie(sessionCookie)
	respOriginPost, err := ts.Client.Do(reqOriginPost)
	if err != nil {
		t.Fatal(err)
	}
	defer respOriginPost.Body.Close()
	if respOriginPost.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 once auth/csrf passes and agent is disabled, got %d", respOriginPost.StatusCode)
	}

	reqBearerPost, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/agent/trigger", nil)
	if err != nil {
		t.Fatal(err)
	}
	ts.addAdminBearer(reqBearerPost)
	respBearerPost, err := ts.Client.Do(reqBearerPost)
	if err != nil {
		t.Fatal(err)
	}
	defer respBearerPost.Body.Close()
	if respBearerPost.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for bearer POST with disabled agent engine, got %d", respBearerPost.StatusCode)
	}

	logoutReq, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/auth/logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Logout requires authentication now, so an anonymous POST is 401. The
	// bearer path is used here to reach the handler and assert the cookie is
	// cleared.
	ts.addAdminBearer(logoutReq)
	logoutResp, err := ts.Client.Do(logoutReq)
	if err != nil {
		t.Fatal(err)
	}
	defer logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on logout, got %d", logoutResp.StatusCode)
	}

	var logoutCookie *http.Cookie
	for _, cookie := range logoutResp.Cookies() {
		if cookie.Name == "admin_session" {
			logoutCookie = cookie
			break
		}
	}
	if logoutCookie == nil {
		t.Fatal("expected admin_session cookie on logout response")
	}
	if logoutCookie.MaxAge != -1 {
		t.Fatalf("expected logout cookie MaxAge -1, got %d", logoutCookie.MaxAge)
	}
}
