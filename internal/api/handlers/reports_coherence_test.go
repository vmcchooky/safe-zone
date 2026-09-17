package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"safe-zone/internal/risk"
)

// Coherence: resolving a report as a false positive must unblock the
// domain in the same step (allow override + resolve + audit), never leave
// a "resolved" record on top of an enforced block.
func TestUpdateReportStatusResolvedUnblocks(t *testing.T) {
	ts := newHandlerTestServer(t)
	domain := "googel-verify-login-account-secure.example"

	before := ts.Handler.Risk.Policy(context.Background(), domain, risk.ClientInfo{})
	if before.Policy != "block" {
		t.Fatalf("fixture must start blocked, got %s (%v)", before.Policy, before.Result.Reasons)
	}

	id, err := ts.Store.CreateBlockReport(context.Background(), domain, "", "Legit service, please unblock")
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		ts.Server.URL+"/v1/reports/status",
		strings.NewReader(fmt.Sprintf(`{"id":%d,"status":"resolved","reason":"verified legitimate service"}`, id)),
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
	var payload struct {
		ResolutionAction string `json:"resolution_action"`
		ResolvedReports  int64  `json:"resolved_reports"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.ResolutionAction != "allow" || payload.ResolvedReports != 1 {
		t.Fatalf("unexpected resolve payload: %+v", payload)
	}

	after := ts.Handler.Risk.Policy(context.Background(), domain, risk.ClientInfo{})
	if after.Policy != "allow" {
		t.Fatalf("resolved report must unblock, policy = %s (%v)", after.Policy, after.Result.Reasons)
	}
	reports, err := ts.Store.ListBlockReports(context.Background(), "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || reports[0].Status != "resolved" || reports[0].ResolutionAction != "allow" {
		t.Fatalf("unexpected report state: %+v", reports)
	}
}

// Rejected keeps the block enforced and writes no override.
func TestUpdateReportStatusRejectedKeepsBlock(t *testing.T) {
	ts := newHandlerTestServer(t)
	domain := "googel-verify-login-account-secure.example"

	id, err := ts.Store.CreateBlockReport(context.Background(), domain, "", "Actually still suspicious")
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		ts.Server.URL+"/v1/reports/status",
		strings.NewReader(fmt.Sprintf(`{"id":%d,"status":"rejected","reason":"evidence confirms the original block"}`, id)),
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

	after := ts.Handler.Risk.Policy(context.Background(), domain, risk.ClientInfo{})
	if after.Policy != "block" {
		t.Fatalf("rejected report must keep block, policy = %s", after.Policy)
	}
}
