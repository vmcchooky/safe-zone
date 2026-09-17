package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// PR-02/H4: oversized inputs must be rejected at the HTTP boundary (400)
// before any analysis work, per OWASP min/max-length validation.
func TestAnalyzeHandlerRejectsOversizedDomain(t *testing.T) {
	ts := newHandlerTestServer(t)

	huge := strings.Repeat("a", 5000)
	resp, err := ts.Client.Get(ts.Server.URL + "/v1/analyze?domain=" + huge)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 400 {
		t.Fatalf("oversized GET domain status = %d; want 400", resp.StatusCode)
	}

	// Boundary: 4096 decoded chars pass admission (NormalizeDomain still
	// enforces RFC 1035 253/63 downstream and returns INVALID with 200).
	edge := strings.Repeat("b", 4096)
	resp2, err := ts.Client.Get(ts.Server.URL + "/v1/analyze?domain=" + edge)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != 200 {
		t.Fatalf("boundary GET domain status = %d; want 200", resp2.StatusCode)
	}
}

func TestAnalyzeHandlerRejectsOversizedURLContext(t *testing.T) {
	ts := newHandlerTestServer(t)

	chain := make([]string, 17)
	for i := range chain {
		chain[i] = "https://example.test/r"
	}
	if msg := admitURLContext("https://example.test/", chain); msg == "" {
		t.Fatal("17-entry redirect chain must be rejected")
	}
	if msg := admitURLContext("https://example.test/", chain[:16]); msg != "" {
		t.Fatalf("16-entry chain must pass handler admission, got %q", msg)
	}
	if msg := admitURLContext(strings.Repeat("u", 8193), nil); msg == "" {
		t.Fatal("oversized requested_url must be rejected")
	}
	if msg := admitURLContext(strings.Repeat("u", 8192), nil); msg != "" {
		t.Fatalf("boundary requested_url must pass handler admission, got %q", msg)
	}

	// End to end: oversized chain over POST is a 400, not analysis work.
	body := `{"domain":"example.test","requested_url":"https://example.test/","redirect_chain":[` +
		strings.Repeat(`"https://example.test/r",`, 17) + `"https://example.test/last"]}`
	resp, err := ts.Client.Post(ts.Server.URL+"/v1/analyze", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 400 {
		t.Fatalf("oversized POST chain status = %d; want 400", resp.StatusCode)
	}
}

func TestRawDataHandlerRejectsOversizedDomain(t *testing.T) {
	ts := newHandlerTestServer(t)

	// /v1/analyze/raw is not mounted on the test mux; call the handler
	// directly. Admission must reject before InspectRawData performs any
	// live NS/TLS/WHOIS lookups.
	req := httptest.NewRequest(http.MethodGet, "/v1/analyze/raw?domain="+strings.Repeat("c", 5000), nil)
	recorder := httptest.NewRecorder()
	ts.Handler.RawDataHandler(recorder, req)
	if recorder.Code != 400 {
		t.Fatalf("oversized raw domain status = %d; want 400", recorder.Code)
	}
}
