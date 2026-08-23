package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/auth"
)

func TestListReportsHandlerReturnsFilteredTotalForPagination(t *testing.T) {
	ts := newHandlerTestServer(t)
	for _, domain := range []string{"one.example", "two.example", "three.example"} {
		if _, err := ts.Store.CreateBlockReport(context.Background(), domain, "", "Needs review"); err != nil {
			t.Fatalf("create report: %v", err)
		}
	}

	req, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/reports?status=pending&limit=1&offset=1", nil)
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
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var payload struct {
		Reports []struct {
			Domain string `json:"domain"`
		} `json:"reports"`
		Total  int `json:"total"`
		Counts struct {
			Pending int `json:"pending"`
		} `json:"counts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Total != 3 {
		t.Fatalf("expected total 3, got %d", payload.Total)
	}
	if payload.Counts.Pending != 3 {
		t.Fatalf("expected pending count 3, got %d", payload.Counts.Pending)
	}
	if len(payload.Reports) != 1 || payload.Reports[0].Domain != "two.example" {
		t.Fatalf("expected second page to contain two.example, got %+v", payload.Reports)
	}
}

func TestReportsQueueIsAdminOnly(t *testing.T) {
	ts := newHandlerTestServer(t)
	hash, err := auth.HashPassword("guestpass12")
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.Handler.saveGuestAccessConfig(context.Background(), guestAccessConfig{
		Enabled:      true,
		PasswordHash: hash,
	}); err != nil {
		t.Fatal(err)
	}
	token, err := auth.GenerateSessionCookieValueForRole("guest", auth.RoleGuest, time.Hour, ts.Handler.Config.SessionSecret)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/reports", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: token})
	resp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected guest report queue access to be forbidden, got %d: %s", resp.StatusCode, body)
	}
}

func TestUpdateReportStatusRecordsDecisionProvenance(t *testing.T) {
	ts := newHandlerTestServer(t)
	id, err := ts.Store.CreateBlockReport(context.Background(), "needs-review.example", "reporter@example.com", "Unexpected block")
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		ts.Server.URL+"/v1/reports/status",
		strings.NewReader(`{"id":`+strconv.FormatInt(id, 10)+`,"status":"rejected","reason":"evidence confirms the original block"}`),
	)
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

	reports, err := ts.Store.ListBlockReports(context.Background(), "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 {
		t.Fatalf("expected one report, got %d", len(reports))
	}
	report := reports[0]
	if report.Status != "rejected" || report.ResolutionAction != "reject" {
		t.Fatalf("unexpected report decision: %+v", report)
	}
	if report.ReviewReason != "evidence confirms the original block" || report.ReviewedBy != auth.RoleAdmin || report.ReviewedAt == "" {
		t.Fatalf("missing decision provenance: %+v", report)
	}

	events, err := ts.Store.QueryAgentEvents(context.Background(), time.Now().Add(-time.Hour), []string{"operator_report_review"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Domain != "needs-review.example" {
		t.Fatalf("expected one review audit event, got %+v", events)
	}
}

func TestUpdateReportStatusValidatesDecision(t *testing.T) {
	ts := newHandlerTestServer(t)
	tests := []struct {
		name string
		body string
		want int
	}{
		{name: "unsupported status", body: `{"id":1,"status":"archived","reason":"operator decision"}`, want: http.StatusBadRequest},
		{name: "short reason", body: `{"id":1,"status":"resolved","reason":"short"}`, want: http.StatusBadRequest},
		{name: "missing report", body: `{"id":999,"status":"resolved","reason":"verified through support ticket"}`, want: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/reports/status", strings.NewReader(tt.body))
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
			if resp.StatusCode != tt.want {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected %d, got %d: %s", tt.want, resp.StatusCode, body)
			}
		})
	}
}
