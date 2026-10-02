package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/risk"
	"safe-zone/internal/store"
)

// A handler that echoed a store error into the response body told the caller
// things about the server it had no business knowing: a file path, a SQL
// fragment, or the store's own "sqlite store disabled". The guest-access routes
// did that on every path.
//
// GuestAccessHandler is the useful case to pin because, unlike GroupsHandler and
// AgentProposalsHandler, it has no Enabled() guard of its own: it reaches
// loadGuestAccessConfig with a closed store and gets a real error back. Closing
// the store and asserting 503 therefore exercises the changed lines rather than a
// guard above them.
func TestGuestAccessRoutesScrubStoreErrors(t *testing.T) {
	ts := newHandlerTestServer(t)
	defer ts.Server.Close()

	if err := ts.Store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	for _, tc := range []struct {
		name   string
		method string
		body   string
	}{
		{name: "read", method: http.MethodGet},
		{name: "create", method: http.MethodPost, body: `{"password":"correct horse battery staple","enabled":true}`},
		{name: "update", method: http.MethodPut, body: `{"enabled":false}`},
		{name: "delete", method: http.MethodDelete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, ts.Server.URL+"/v1/settings/guest-access", strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			ts.addAdminBearer(req)

			resp, err := ts.Client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body := readBody(t, resp)

			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503 (body %q)", resp.StatusCode, body)
			}
			assertNoInternalLeak(t, body)
		})
	}
}

// The root cause, not the symptom. guestAccessStore used to fabricate
// "database not configured" with fmt.Errorf, so errors.Is never matched it and
// every disabled-store response came back as a 500 carrying that text. Routing the
// handler through WriteStoreError does not help unless the error has identity, so
// this pins the identity rather than the text.
func TestGuestAccessStoreUsesTheSentinelSoTheMappingWorks(t *testing.T) {
	ts := newHandlerTestServer(t)
	defer ts.Server.Close()
	if err := ts.Store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	_, err := ts.Handler.loadGuestAccessConfig(context.Background())
	if err == nil {
		t.Fatal("expected an error from a closed store")
	}
	if !errors.Is(err, store.ErrDisabled) {
		t.Fatalf("err = %v, want it to wrap store.ErrDisabled so the handler can map it to 503", err)
	}
}

// The risk service had the same defect in four places: "store not configured"
// built with fmt.Errorf, which is text and not identity. UpsertOverride is the one
// an HTTP handler maps, so it is the one pinned here.
func TestUpsertOverrideUsesTheSentinelWhenThereIsNoStore(t *testing.T) {
	svc := risk.NewService(risk.Options{})
	err := svc.UpsertOverride(context.Background(), "example.com", "block", "test")
	if err == nil {
		t.Fatal("expected an error from a service with no store")
	}
	if !errors.Is(err, store.ErrDisabled) {
		t.Fatalf("err = %v, want store.ErrDisabled", err)
	}
}

// A store failure must not be reported as a bad request. Listing proposals was a
// 400 with the store's own message in the body, which told the operator their
// status filter was wrong when the query had failed before the filter mattered.
//
// AgentProposalsHandler's Enabled() guard means a closed store never reaches the
// changed line, so the mapping is asserted directly here.
func TestDisabledStoreMapsTo503Not400(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/agent/proposals", nil)
	httputil.WriteStoreError(rec, req, store.ErrDisabled, "failed to list proposals")

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 for a disabled store, not 400", rec.Code)
	}
	assertNoInternalLeak(t, rec.Body.String())
}

// The internal-error helper covers failures that are not store failures and whose
// status is endpoint-specific. It must scrub, and it must not override the
// caller's status, or it would flatten a 502 into a 500.
func TestWriteInternalErrorScrubsButKeepsTheGivenStatus(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/analysis/osint", nil)
		detail := errors.New("dial tcp 10.0.0.5:53: i/o timeout querying resolver.internal")

		httputil.WriteInternalError(rec, req, status, detail, "OSINT evidence lookup failed")

		if rec.Code != status {
			t.Fatalf("status = %d, want the caller's %d", rec.Code, status)
		}
		body := rec.Body.String()
		assertNoInternalLeak(t, body)
		if !strings.Contains(body, "OSINT evidence lookup failed") {
			t.Fatalf("body = %s, want the public message", body)
		}
	}
}

// A nil error must still produce a response. The callers only reach this with a
// non-nil error, but the helper is exported and a silent empty 200 would be worse
// than the leak it prevents.
func TestWriteInternalErrorHandlesANilError(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/version", nil)
	httputil.WriteInternalError(rec, req, http.StatusInternalServerError, nil, "something went wrong")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "something went wrong") {
		t.Fatalf("body = %s, want the public message", rec.Body.String())
	}
}

// Eleven call sites still interpolate err.Error(), and every one of them is a 400
// or 403 describing the caller's own request. Echoing the reason there is the
// useful behaviour, and "scrub all of them" would be the wrong fix: it would cost
// operators the validation message they need in order to fix their request.
//
// This pins that intent so the next pass does not over-correct.
func TestValidationErrorsAreStillEchoedToTheCaller(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/settings", nil)
	const reason = `adblock_match_mode must be "suffix" or "exact", got "sideways"`
	httputil.WriteError(rec, http.StatusBadRequest, reason)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "sideways") {
		t.Fatalf("body = %s, want the validation reason echoed", rec.Body.String())
	}
	_ = req
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}

// assertNoInternalLeak checks the response for the strings that actually appeared
// in these bugs, rather than a generic "looks like an error" heuristic.
func assertNoInternalLeak(t *testing.T, body string) {
	t.Helper()
	for _, leak := range []string{
		"sqlite store disabled",
		"database not configured",
		"store not configured",
		"safe-zone.db",
		"sql:",
		"no such table",
		"10.0.0.5",
	} {
		if strings.Contains(body, leak) {
			t.Fatalf("response leaked %q: %s", leak, body)
		}
	}
}
