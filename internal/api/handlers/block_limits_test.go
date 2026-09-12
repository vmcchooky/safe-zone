package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func postBlockReport(t *testing.T, ts *handlerTestServer, form url.Values) int {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/block/report", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ts.Handler.BlockReportHandler(recorder, request)
	return recorder.Code
}

// P-2: free-text report fields are bounded before reaching the store.
func TestBlockReportRejectsOversizedFields(t *testing.T) {
	ts := newHandlerTestServer(t)
	base := url.Values{
		"domain":  {"maybe-blocked.example"},
		"contact": {"ops@example.com"},
		"note":    {"Legitimate business page."},
	}

	oversized := map[string]url.Values{
		"contact": {"domain": {"maybe-blocked.example"}, "contact": {strings.Repeat("c", 257)}},
		"note":    {"domain": {"maybe-blocked.example"}, "note": {strings.Repeat("n", 2001)}},
		"path":    {"domain": {"maybe-blocked.example"}, "requested_path": {"/" + strings.Repeat("p", 2048)}},
	}
	for name, form := range oversized {
		if code := postBlockReport(t, ts, form); code != http.StatusBadRequest {
			t.Fatalf("expected 400 for oversized %s, got %d", name, code)
		}
	}
	if code := postBlockReport(t, ts, base); code != http.StatusSeeOther {
		t.Fatalf("expected valid report to redirect, got %d", code)
	}
}
