package handlers

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDashboardEndpointHTTP(t *testing.T) {
	ts := newHandlerTestServer(t)

	loginResp, err := ts.Client.Get(ts.Server.URL + "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	defer loginResp.Body.Close()

	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", loginResp.StatusCode)
	}

	loginBody, err := io.ReadAll(loginResp.Body)
	if err != nil {
		t.Fatal(err)
	}
	loginHTML := string(loginBody)
	if !strings.Contains(loginHTML, "Sentinel Command OS") || !strings.Contains(loginHTML, "adminLoginForm") {
		t.Fatalf("expected login page HTML, got: %s", loginHTML)
	}

	req, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/dashboard", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(ts.adminSessionCookie(t))

	dashboardResp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer dashboardResp.Body.Close()

	if dashboardResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", dashboardResp.StatusCode)
	}

	body, err := io.ReadAll(dashboardResp.Body)
	if err != nil {
		t.Fatal(err)
	}
	content := string(body)
	for _, fragment := range []string{"Safe Zone Dashboard", "Domain Inspection", "Analysis Scoring", "setting-analysis-config", "dashboard-features.js"} {
		if !strings.Contains(content, fragment) {
			t.Fatalf("expected dashboard content to contain %q, got: %s", fragment, content)
		}
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
