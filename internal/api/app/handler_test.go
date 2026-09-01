package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func TestNewHandlerServesIndexForAppRoutes(t *testing.T) {
	handler := NewHandler(fstest.MapFS{
		"index.html":       &fstest.MapFile{Data: []byte("<html>spa</html>")},
		"assets/index.js":  &fstest.MapFile{Data: []byte("console.log('app')")},
		"assets/index.css": &fstest.MapFile{Data: []byte("body{}")},
	})

	for _, requestPath := range []string{"/app/", "/app/telemetry", "/app/settings/operators"} {
		req := httptest.NewRequest(http.MethodGet, requestPath, nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", requestPath, rec.Code)
		}

		body, err := io.ReadAll(rec.Body)
		if err != nil {
			t.Fatalf("%s: read body: %v", requestPath, err)
		}
		if string(body) != "<html>spa</html>" {
			t.Fatalf("%s: unexpected body %q", requestPath, body)
		}
	}
}

func TestNewHandlerServesStaticAssets(t *testing.T) {
	handler := NewHandler(fstest.MapFS{
		"index.html":      &fstest.MapFile{Data: []byte("<html>spa</html>")},
		"assets/index.js": &fstest.MapFile{Data: []byte("console.log('app')")},
	})

	req := httptest.NewRequest(http.MethodGet, "/app/assets/index.js", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "console.log('app')" {
		t.Fatalf("unexpected asset body %q", body)
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("unexpected asset cache policy %q", got)
	}
}

func TestNewHandlerReturnsNotFoundForMissingStaticAssets(t *testing.T) {
	handler := NewHandler(fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<html>spa</html>")},
	})

	req := httptest.NewRequest(http.MethodGet, "/app/assets/missing.js", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestRedirectPublicRootToApp(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?domain=example.com", nil)
	rec := httptest.NewRecorder()

	RedirectPublicRoot(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307, got %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/app/?domain=example.com" {
		t.Fatalf("unexpected redirect location %q", got)
	}
}

func TestRedirectPublicRootRejectsNonGet(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()

	RedirectPublicRoot(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("unexpected Allow header %q", got)
	}
}

func TestRedirectRoot(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/app", nil)
	rec := httptest.NewRecorder()

	RedirectRoot(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307, got %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/app/" {
		t.Fatalf("unexpected redirect location %q", got)
	}
}

func TestRedirectRootKeepsQueryWithinAppMount(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/app?next=https://attacker.example/landing", nil)
	rec := httptest.NewRecorder()

	RedirectRoot(rec, req)

	if got := rec.Header().Get("Location"); got != "/app/?next=https://attacker.example/landing" {
		t.Fatalf("unexpected redirect location %q", got)
	}
}

func TestRedirectLegacyDashboardToApp(t *testing.T) {
	for _, requestPath := range []string{
		"/dashboard",
		"/dashboard/",
		"/dashboard/legacy?tab=telemetry",
	} {
		req := httptest.NewRequest(http.MethodGet, requestPath, nil)
		rec := httptest.NewRecorder()

		RedirectLegacyDashboard(rec, req)

		if rec.Code != http.StatusTemporaryRedirect {
			t.Fatalf("%s: expected 307, got %d", requestPath, rec.Code)
		}

		want := "/app/"
		if requestPath == "/dashboard/legacy?tab=telemetry" {
			want += "?tab=telemetry"
		}
		if got := rec.Header().Get("Location"); got != want {
			t.Fatalf("%s: unexpected redirect location %q, want %q", requestPath, got, want)
		}
	}
}

func TestIndexUsesRevalidationSafeCachePolicy(t *testing.T) {
	handler := NewHandler(fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<html>spa</html>")},
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app/analysis", nil))

	if got := rec.Header().Get("Cache-Control"); got != "no-cache, no-store, must-revalidate" {
		t.Fatalf("unexpected index cache policy %q", got)
	}
}

func TestLegacyBackgroundRedirectKeepsVersionQuery(t *testing.T) {
	rec := httptest.NewRecorder()
	RedirectLegacyBackground(rec, httptest.NewRequest(http.MethodGet, "/app-background.avif?v=1", nil))

	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("expected 308, got %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/app/app-background.avif?v=1" {
		t.Fatalf("unexpected redirect location %q", got)
	}
}

func TestRobotsDisallowsOperatorUIIndexing(t *testing.T) {
	rec := httptest.NewRecorder()
	Robots(rec, httptest.NewRequest(http.MethodGet, "/robots.txt", nil))

	if rec.Code != http.StatusOK || rec.Body.String() != "User-agent: *\nDisallow: /\n" {
		t.Fatalf("unexpected robots response: status=%d body=%q", rec.Code, rec.Body.String())
	}
}
