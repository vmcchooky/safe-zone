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
	})

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
