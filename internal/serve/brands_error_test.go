package serve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"safe-zone/internal/analysis"
	"safe-zone/internal/store"
)

// stubBrandManager returns a canned outcome for every operation, so the test
// exercises the handler's mapping rather than a real database.
type stubBrandManager struct {
	err error
}

func (s stubBrandManager) ListBrands(context.Context) ([]analysis.Brand, error) {
	return nil, s.err
}

func (s stubBrandManager) GetBrand(context.Context, int64) (analysis.Brand, error) {
	return analysis.Brand{}, s.err
}

func (s stubBrandManager) CreateBrand(context.Context, analysis.Brand) (analysis.Brand, error) {
	return analysis.Brand{}, s.err
}

func (s stubBrandManager) UpdateBrand(context.Context, int64, analysis.Brand) (analysis.Brand, error) {
	return analysis.Brand{}, s.err
}

func (s stubBrandManager) DeleteBrand(context.Context, int64) error {
	return s.err
}

func doBrandRequest(t *testing.T, manager BrandManager, method, target string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, target, strings.NewReader(`{"name":"x","official_domain":"x.test"}`))
	BrandHandler(manager)(rec, req)

	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return rec.Code, string(body)
}

// Every brand route answered a disabled store with its own status: 404 on GET
// and DELETE, 400 on POST and PUT. That told the caller its brand did not exist
// when the database had never been consulted at all, and it leaked the store's
// internal "sqlite store disabled" text into the response body.
func TestBrandHandlerReportsADisabledStoreAs503(t *testing.T) {
	manager := stubBrandManager{err: store.ErrDisabled}

	for _, tc := range []struct {
		name   string
		method string
		target string
	}{
		{name: "list", method: http.MethodGet, target: "/v1/brands"},
		{name: "get one", method: http.MethodGet, target: "/v1/brands?id=1"},
		{name: "create", method: http.MethodPost, target: "/v1/brands"},
		{name: "update", method: http.MethodPut, target: "/v1/brands?id=1"},
		{name: "delete", method: http.MethodDelete, target: "/v1/brands?id=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := doBrandRequest(t, manager, tc.method, tc.target)
			if status != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503", status)
			}
			if strings.Contains(body, "sqlite store disabled") {
				t.Fatalf("response leaked the internal store message: %s", body)
			}
			if strings.Contains(body, "not configured") {
				t.Fatalf("a disabled store must not be reported as unconfigured: %s", body)
			}
		})
	}
}

func TestBrandHandlerSeparatesMissingFromInvalidFromBroken(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		wantStatus int
		wantInBody string
	}{
		{name: "missing row is a 404", err: store.ErrBrandNotFound, wantStatus: http.StatusNotFound, wantInBody: "brand not found"},
		{
			// Wrapped, the way validateBrand returns it. The reason is echoed
			// back because it describes the caller's own input; matching on the
			// sentinel rather than on the text is what keeps that safe.
			name:       "invalid input is a 400 and keeps the reason",
			err:        fmt.Errorf("%w: brand name is required", store.ErrInvalidBrand),
			wantStatus: http.StatusBadRequest,
			wantInBody: "brand name is required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := doBrandRequest(t, stubBrandManager{err: tc.err}, http.MethodPost, "/v1/brands")
			if status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", status, tc.wantStatus)
			}
			if !strings.Contains(body, tc.wantInBody) {
				t.Fatalf("body = %s, want it to mention %q", body, tc.wantInBody)
			}
		})
	}
}

// An unexpected failure is a 500 with a generic body. The detail belongs in the
// log, where it can be correlated with the request, not in the response.
func TestBrandHandlerKeepsUnexpectedFailuresOutOfTheBody(t *testing.T) {
	status, body := doBrandRequest(t,
		stubBrandManager{err: errors.New(`create brand "acme": open /var/lib/safe-zone/brands.db: disk I/O error`)},
		http.MethodPost, "/v1/brands")

	if status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", status)
	}
	for _, leak := range []string{"brands.db", "disk I/O error"} {
		if strings.Contains(body, leak) {
			t.Fatalf("response leaked %q: %s", leak, body)
		}
	}
}

func TestBrandHandlerStillValidatesTheRequestItself(t *testing.T) {
	// A bad id is a client mistake and must stay a 400 even though the store
	// would have been reachable.
	status, _ := doBrandRequest(t, stubBrandManager{err: nil}, http.MethodDelete, "/v1/brands?id=0")
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a non-positive id", status)
	}

	status, _ = doBrandRequest(t, stubBrandManager{err: nil}, http.MethodPut, "/v1/brands")
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a missing id", status)
	}
}

// The response must stay valid JSON, since these are consumed as such.
func TestBrandHandlerErrorBodiesAreJSON(t *testing.T) {
	status, body := doBrandRequest(t, stubBrandManager{err: store.ErrDisabled}, http.MethodGet, "/v1/brands")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", status)
	}
	var payload map[string]string
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("body is not a JSON object: %v (%s)", err, body)
	}
	if payload["error"] == "" {
		t.Fatalf("no error field in %s", body)
	}
}
