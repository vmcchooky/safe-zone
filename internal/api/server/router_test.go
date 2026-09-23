package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"safe-zone/internal/agent"
	"safe-zone/internal/api/handlers"
)

func TestNewRouterServesAssetsWithStripPrefix(t *testing.T) {
	mux := NewRouter(&handlers.Handler{}, (*agent.Engine)(nil), fstest.MapFS{
		"safe-zone.css": &fstest.MapFile{Data: []byte("body{color:#fff}")},
	}, nil)

	req := httptest.NewRequest(http.MethodGet, "/assets/safe-zone.css", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "body{color:#fff}" {
		t.Fatalf("unexpected asset body: %q", body)
	}
}

func TestNewRouterMountsReactAppAtAppPrefix(t *testing.T) {
	mux := NewRouter(&handlers.Handler{}, (*agent.Engine)(nil), nil, fstest.MapFS{
		"index.html":      &fstest.MapFile{Data: []byte("<html>spa</html>")},
		"assets/index.js": &fstest.MapFile{Data: []byte("console.log('app')")},
	})

	redirectReq := httptest.NewRequest(http.MethodGet, "/app", nil)
	redirectRec := httptest.NewRecorder()
	mux.ServeHTTP(redirectRec, redirectReq)

	if redirectRec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected /app redirect 307, got %d", redirectRec.Code)
	}
	if got := redirectRec.Header().Get("Location"); got != "/app/" {
		t.Fatalf("unexpected redirect location %q", got)
	}

	routeReq := httptest.NewRequest(http.MethodGet, "/app/telemetry", nil)
	routeRec := httptest.NewRecorder()
	mux.ServeHTTP(routeRec, routeReq)

	if routeRec.Code != http.StatusOK {
		t.Fatalf("expected app route 200, got %d", routeRec.Code)
	}

	body, err := io.ReadAll(routeRec.Body)
	if err != nil {
		t.Fatalf("read route body: %v", err)
	}
	if string(body) != "<html>spa</html>" {
		t.Fatalf("unexpected app route body: %q", body)
	}
}

func TestRouterRequiresAuthForAnalyzeRaw(t *testing.T) {
	// F3: /v1/analyze/raw triggers outbound DNS/TLS/WHOIS for an
	// attacker-chosen domain; it must not be anonymously reachable
	// (it is publicly proxied by Caddy like every other API route).
	mux := NewRouter(&handlers.Handler{}, (*agent.Engine)(nil), nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/analyze/raw?domain=example.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected anonymous /v1/analyze/raw to return 401, got %d", rec.Code)
	}
}

func TestRouterRequiresAuthForURLMLFeedback(t *testing.T) {
	// Low finding: label-feedback writes counters; anonymous submissions
	// pollute the calibration denominator. Same RequireAuth precedent as F3.
	mux := NewRouter(&handlers.Handler{}, (*agent.Engine)(nil), nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/v1/url-ml/feedback", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected anonymous /v1/url-ml/feedback to return 401, got %d", rec.Code)
	}
}

func TestRouterAuthMethodsAndPaths(t *testing.T) {
	mux := NewRouter(&handlers.Handler{}, (*agent.Engine)(nil), nil, nil)

	cases := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		// wantOKExactly pins deterministic behavior; otherwise only the
		// no-bypass property (never 200) is asserted to avoid coupling
		// to net/http mux-version path-cleaning details.
		wantOKExactly bool
	}{
		// Authed debug/counter writers: every method must 401 first
		// (auth middleware runs before handler method checks).
		{"raw POST anon", http.MethodPost, "/v1/analyze/raw?domain=x.test", http.StatusUnauthorized, true},
		{"raw PUT anon", http.MethodPut, "/v1/analyze/raw?domain=x.test", http.StatusUnauthorized, true},
		{"feedback GET anon", http.MethodGet, "/v1/url-ml/feedback", http.StatusUnauthorized, true},
		// Path confusion must never resolve to a 200 from the handler.
		{"raw trailing slash", http.MethodGet, "/v1/analyze/raw/", 0, false},
		{"raw doubled slash", http.MethodGet, "//v1/analyze/raw", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if tc.wantOKExactly && rec.Code != tc.wantStatus {
				t.Fatalf("expected %d, got %d", tc.wantStatus, rec.Code)
			}
			if rec.Code == http.StatusOK {
				t.Fatalf("path confusion must never yield 200, got it for %s %s", tc.method, tc.path)
			}
		})
	}
}

func TestNewRouterRedirectsPublicRootToReactApp(t *testing.T) {
	mux := NewRouter(&handlers.Handler{}, (*agent.Engine)(nil), nil, fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<html>spa</html>")},
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected root redirect 307, got %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/app/" {
		t.Fatalf("unexpected root redirect location %q", got)
	}
}

func TestNewRouterRedirectsLegacyDashboardToReactApp(t *testing.T) {
	mux := NewRouter(&handlers.Handler{}, (*agent.Engine)(nil), nil, fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<html>spa</html>")},
	})

	req := httptest.NewRequest(http.MethodGet, "/dashboard?tab=telemetry", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected dashboard redirect 307, got %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/app/?tab=telemetry" {
		t.Fatalf("unexpected redirect location %q", got)
	}
}

func TestNewRouterRequiresAuthForStatus(t *testing.T) {
	mux := NewRouter(&handlers.Handler{}, (*agent.Engine)(nil), nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated /v1/status to be 401, got %d", rec.Code)
	}
}
