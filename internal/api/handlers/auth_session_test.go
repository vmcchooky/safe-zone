package handlers

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/auth"
)

func loginAdmin(t *testing.T, ts *handlerTestServer, password string) (*http.Response, *http.Cookie) {
	t.Helper()
	resp, err := ts.Client.Post(ts.Server.URL+"/v1/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"`+password+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	var sessionCookie *http.Cookie
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "admin_session" {
			sessionCookie = cookie
		}
	}
	return resp, sessionCookie
}

func sessionCookieFlags(t *testing.T, cookie *http.Cookie) {
	t.Helper()
	if !cookie.HttpOnly {
		t.Fatal("session cookie must be HttpOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie must be SameSite=Lax, got %v", cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Fatalf("session cookie path must be /, got %q", cookie.Path)
	}
}

// A correct admin login mints a revocable session: the cookie works on
// authed routes and the flags stay intact.
func TestAdminLoginCreatesActiveSession(t *testing.T) {
	ts := newHandlerTestServer(t)

	resp, cookie := loginAdmin(t, ts, "adminpass1234")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on admin login, got %d", resp.StatusCode)
	}
	if cookie == nil {
		t.Fatal("expected admin_session cookie")
	}
	sessionCookieFlags(t, cookie)

	req, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/overrides", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	authResp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with minted admin session, got %d", authResp.StatusCode)
	}
}

// Wrong credentials must fail uniformly without issuing a cookie.
func TestAdminLoginRejectsWrongCredentials(t *testing.T) {
	ts := newHandlerTestServer(t)

	resp, cookie := loginAdmin(t, ts, "wrong-password")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	if cookie != nil {
		t.Fatal("no cookie may be issued on failed login")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "invalid username or password") {
		t.Fatalf("expected uniform error message, got %s", string(body))
	}
}

// Logout must revoke the persisted session: a stolen copy of the cookie is
// rejected afterwards.
func TestLogoutRevokesSessionAndReplayFails(t *testing.T) {
	ts := newHandlerTestServer(t)

	resp, cookie := loginAdmin(t, ts, "adminpass1234")
	defer resp.Body.Close()
	if cookie == nil {
		t.Fatal("expected admin_session cookie")
	}

	// The "stolen" copy: same token, independent request.
	stolen := &http.Cookie{Name: "admin_session", Value: cookie.Value}

	logoutReq, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/auth/logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	logoutReq.AddCookie(cookie)
	logoutResp, err := ts.Client.Do(logoutReq)
	if err != nil {
		t.Fatal(err)
	}
	defer logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on logout, got %d", logoutResp.StatusCode)
	}

	replayReq, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/overrides", nil)
	if err != nil {
		t.Fatal(err)
	}
	replayReq.AddCookie(stolen)
	replayResp, err := ts.Client.Do(replayReq)
	if err != nil {
		t.Fatal(err)
	}
	defer replayResp.Body.Close()
	if replayResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for replayed cookie after logout, got %d", replayResp.StatusCode)
	}
}

// Expired and legacy stateless admin tokens must be rejected.
func TestExpiredAndLegacyAdminSessionsRejected(t *testing.T) {
	ts := newHandlerTestServer(t)

	expired := ts.adminSessionCookieWithTTL(t, -time.Minute)
	req, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/overrides", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(expired)
	resp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired session, got %d", resp.StatusCode)
	}

	legacyToken, err := auth.GenerateSessionCookieValueForRole("admin", auth.RoleAdmin, "", time.Hour, ts.Handler.Config.SessionSecret)
	if err != nil {
		t.Fatal(err)
	}
	legacyReq, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/overrides", nil)
	if err != nil {
		t.Fatal(err)
	}
	legacyReq.AddCookie(&http.Cookie{Name: "admin_session", Value: legacyToken})
	legacyResp, err := ts.Client.Do(legacyReq)
	if err != nil {
		t.Fatal(err)
	}
	defer legacyResp.Body.Close()
	if legacyResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for legacy stateless admin token, got %d", legacyResp.StatusCode)
	}
}

// An unavailable session store must fail closed for both login and session
// validation, while the bearer API key path keeps working.
func TestSessionStoreUnavailableFailsClosed(t *testing.T) {
	ts := newHandlerTestServer(t)

	// Mint a valid session while the store is still alive.
	adminCookie := ts.adminSessionCookie(t)

	if err := ts.Store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	resp, cookie := loginAdmin(t, ts, "adminpass1234")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 login without session store, got %d", resp.StatusCode)
	}
	if cookie != nil {
		t.Fatal("no cookie may be issued when the session store is unavailable")
	}

	// A previously valid admin session cannot be validated anymore: 503,
	// never an accidental pass-through.
	req, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/overrides", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(adminCookie)
	authResp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 session validation without store, got %d", authResp.StatusCode)
	}

	// The bearer API key path does not depend on the session store.
	bearerReq, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/overrides", nil)
	if err != nil {
		t.Fatal(err)
	}
	ts.addAdminBearer(bearerReq)
	bearerResp, err := ts.Client.Do(bearerReq)
	if err != nil {
		t.Fatal(err)
	}
	defer bearerResp.Body.Close()
	if bearerResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for bearer auth without session store, got %d", bearerResp.StatusCode)
	}
}

// Logout must not report success when the revocation itself fails: the
// cookie stays in place (retryable) and the session row stays revocable.
// The revocation failure is injected by calling the handler with a canceled
// request context after the cookie has been verified — i.e. the failure
// happens post-validation, during the revoke step.
func TestLogoutRevokeFailureDoesNotReportSuccess(t *testing.T) {
	ts := newHandlerTestServer(t)

	cookie := ts.adminSessionCookie(t)

	revokeCtx, cancel := context.WithCancel(context.Background())
	cancel()

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	req.AddCookie(cookie)
	req = req.WithContext(revokeCtx)
	recorder := httptest.NewRecorder()
	ts.Handler.AuthLogoutHandler(recorder, req)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when revocation fails, got %d", recorder.Code)
	}
	if setCookie := recorder.Header().Get("Set-Cookie"); setCookie != "" {
		t.Fatalf("failed logout must not clear the cookie, got Set-Cookie %q", setCookie)
	}

	// The session must still be active in the store: revocation did not
	// happen, so the (stolen) cookie copy remains usable until a real
	// revocation succeeds.
	active, err := ts.Store.AdminSessionActive(context.Background(), auth.SessionFingerprint(sessionIDFromCookie(t, ts, cookie)))
	if err != nil || !active {
		t.Fatalf("expected session to remain active after failed revocation (active=%v, err=%v)", active, err)
	}

	// Retry with a working request context: revocation succeeds, cookie is
	// cleared, and the stolen copy is rejected afterwards.
	retryReq := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	retryReq.AddCookie(cookie)
	retryRecorder := httptest.NewRecorder()
	ts.Handler.AuthLogoutHandler(retryRecorder, retryReq)

	if retryRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 on retry after recovery, got %d", retryRecorder.Code)
	}
	if setCookie := retryRecorder.Header().Get("Set-Cookie"); !strings.Contains(setCookie, "Max-Age=0") {
		t.Fatalf("successful logout must clear the cookie, got Set-Cookie %q", setCookie)
	}
	active, err = ts.Store.AdminSessionActive(context.Background(), auth.SessionFingerprint(sessionIDFromCookie(t, ts, cookie)))
	if err != nil || active {
		t.Fatalf("expected session revoked after retry (active=%v, err=%v)", active, err)
	}
}

// sessionIDFromCookie recovers the raw session ID from a signed cookie so
// tests can compute the stored fingerprint.
func sessionIDFromCookie(t *testing.T, ts *handlerTestServer, cookie *http.Cookie) string {
	t.Helper()
	claims, err := auth.VerifySessionClaims(cookie.Value, ts.Handler.Config.SessionSecret)
	if err != nil {
		t.Fatalf("verify session cookie: %v", err)
	}
	return claims.SessionID
}

// A disabled session store must likewise refuse logout instead of silently
// reporting success while the row stays active.
func TestLogoutWithDisabledStoreFailsClosed(t *testing.T) {
	ts := newHandlerTestServer(t)
	cookie := ts.adminSessionCookie(t)

	if err := ts.Store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	req.AddCookie(cookie)
	recorder := httptest.NewRecorder()
	ts.Handler.AuthLogoutHandler(recorder, req)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 with disabled session store, got %d", recorder.Code)
	}
	if setCookie := recorder.Header().Get("Set-Cookie"); setCookie != "" {
		t.Fatalf("failed logout must not clear the cookie, got Set-Cookie %q", setCookie)
	}
}
