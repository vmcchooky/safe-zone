package handlers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestReviewFalsePositiveHandlerCreatesAllowOverride(t *testing.T) {
	ts := newHandlerTestServer(t)
	if _, err := ts.Store.CreateBlockReport(context.Background(), "legit-portal.example", "", "Valid business portal"); err != nil {
		t.Fatalf("create block report: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/overrides/review-false-positive", strings.NewReader(`{"domain":"Legit-Portal.Example","reason":"verified with site owner and internal users","source":"dashboard_analysis","previous_action":"block"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	ts.addAdminBearer(req)

	resp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	override, err := ts.Store.GetOverride(context.Background(), "legit-portal.example")
	if err != nil {
		t.Fatal(err)
	}
	if override == nil {
		t.Fatal("expected override to be created")
	}
	if override.Action != "allow" {
		t.Fatalf("expected allow override, got %q", override.Action)
	}
	if !strings.Contains(override.Reason, "false-positive review (dashboard_analysis): verified with site owner and internal users") {
		t.Fatalf("unexpected review reason %q", override.Reason)
	}

	events, err := ts.Store.QueryAgentEvents(context.Background(), time.Now().Add(-1*time.Hour), []string{"operator_false_positive_review"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 operator review event, got %d", len(events))
	}
	if events[0].Domain != "legit-portal.example" {
		t.Fatalf("expected normalized domain in event, got %q", events[0].Domain)
	}

	reports, err := ts.Store.ListBlockReports(context.Background(), "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || reports[0].Status != "resolved" {
		t.Fatalf("expected report to be resolved after allow review, got %+v", reports)
	}
}
