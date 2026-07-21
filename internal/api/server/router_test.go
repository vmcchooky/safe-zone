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
