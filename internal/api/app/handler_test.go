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
