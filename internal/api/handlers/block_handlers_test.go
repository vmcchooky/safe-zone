package handlers

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBlockPageHandlerRendersBlockedContext(t *testing.T) {
	ts := newHandlerTestServer(t)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/block?category=phishing&reason=Matched+Safe+Zone+policy", nil)
	request.Header.Set("X-Blocked-Domain", "login.example.com")
	request.Header.Set("X-Original-Path", "/signin")

	ts.Handler.BlockPageHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	body := recorder.Body.String()
	for _, fragment := range []string{"login.example.com", "/signin", "Matched Safe Zone policy", "Submit review request"} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("expected block page to contain %q, got: %s", fragment, body)
		}
	}
}

func TestBlockReportHandlerStoresFalsePositiveReport(t *testing.T) {
	ts := newHandlerTestServer(t)

	form := url.Values{
		"domain":         {"maybe-blocked.example"},
		"requested_path": {"/login"},
		"contact":        {"ops@example.com"},
		"note":           {"Business login page. Please review."},
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/block/report", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ts.Handler.BlockReportHandler(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", recorder.Code)
	}
	if location := recorder.Header().Get("Location"); !strings.Contains(location, "/block?reported=1") {
		t.Fatalf("expected redirect back to block page, got %q", location)
	}

	events, err := ts.Store.QueryAgentEvents(context.Background(), time.Now().Add(-1*time.Hour), []string{"false_positive_report"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 stored report event, got %d", len(events))
	}
	if events[0].Domain != "maybe-blocked.example" {
		t.Fatalf("expected stored report domain, got %q", events[0].Domain)
	}
	if !strings.Contains(events[0].Details, "Business login page") {
		t.Fatalf("expected report note in details, got %q", events[0].Details)
	}

	req, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/reports?status=pending", nil)
	if err != nil {
		t.Fatal(err)
	}
	ts.addAdminBearer(req)

	resp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected reports endpoint 200, got %d: %s", resp.StatusCode, body)
	}
}
