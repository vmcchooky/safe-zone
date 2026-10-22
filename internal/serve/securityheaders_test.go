package serve_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"safe-zone/internal/serve"
)

func TestSecurityHeaders(t *testing.T) {
	handler := serve.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Security-Policy"); got != "default-src 'self'; base-uri 'self'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; style-src 'self' 'unsafe-inline'" {
		t.Fatalf("unexpected CSP header: %q", got)
	}
	if got := rec.Header().Values("Content-Security-Policy"); len(got) != 1 {
		t.Fatalf("expected one CSP header, got %d values: %v", len(got), got)
	}

	// The style exception must stay scoped to styles. A style injection
	// cannot execute code, but an inline script can, so script-src keeps
	// 'self' without 'unsafe-inline' and 'unsafe-eval'.
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self' 'wasm-unsafe-eval'") {
		t.Fatalf("script-src must stay restricted: %q", csp)
	}
	if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Fatalf("script-src must not allow inline scripts: %q", csp)
	}
	if strings.Contains(csp, "unsafe-eval") && !strings.Contains(csp, "wasm-unsafe-eval") {
		t.Fatalf("only the wasm evaluator may be allowed: %q", csp)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("unexpected Referrer-Policy: %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("unexpected X-Content-Type-Options: %q", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("unexpected X-Frame-Options: %q", got)
	}
	if got := rec.Header().Get("Permissions-Policy"); got != "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()" {
		t.Fatalf("unexpected Permissions-Policy: %q", got)
	}
}
