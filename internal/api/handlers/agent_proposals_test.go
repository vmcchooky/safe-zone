package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"safe-zone/internal/store"
)

func seedProposal(t *testing.T, ts *handlerTestServer, domain string) int64 {
	t.Helper()
	created, err := ts.Store.CreateAgentProposal(context.Background(), store.AgentProposal{
		Domain: domain, Action: "block", Score: 85, Confidence: 0.95,
		Reasons: []string{"tls: self-signed certificate"},
	})
	if err != nil {
		t.Fatalf("seed proposal: %v", err)
	}
	return created.ID
}

func doProposalAdmin(t *testing.T, ts *handlerTestServer, method, target, body string) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.Server.URL+target, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	ts.addAdminBearer(req)
	resp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func TestAgentProposalsListAndApprove(t *testing.T) {
	ts := newHandlerTestServer(t)
	id := seedProposal(t, ts, "proposal-candidate.test")

	code, data := doProposalAdmin(t, ts, http.MethodGet, "/v1/agent/proposals?status=pending", "")
	if code != http.StatusOK {
		t.Fatalf("expected 200 list, got %d: %s", code, data)
	}
	var listed struct {
		Items []store.AgentProposal `json:"items"`
	}
	if err := json.Unmarshal(data, &listed); err != nil || len(listed.Items) != 1 {
		t.Fatalf("expected 1 pending proposal, got %s (%v)", data, err)
	}
	if listed.Items[0].Actor != "agent:audit" || listed.Items[0].Scope != "exact" {
		t.Fatalf("proposal must carry actor/scope, got %+v", listed.Items[0])
	}

	code, data = doProposalAdmin(t, ts, http.MethodPost, "/v1/agent/proposals",
		`{"id":`+strconv.FormatInt(id, 10)+`,"decision":"approve","reason":"confirmed kit"}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 approve, got %d: %s", code, data)
	}
	override, err := ts.Store.GetOverride(context.Background(), "proposal-candidate.test")
	if err != nil || override == nil || override.Action != "block" {
		t.Fatalf("expected block override from approval, got %+v (%v)", override, err)
	}
	if !strings.Contains(override.Reason, "approved agent proposal") {
		t.Fatalf("override must cite its proposal provenance, got %q", override.Reason)
	}
	decided, err := ts.Store.GetAgentProposal(context.Background(), id)
	if err != nil || decided.Status != store.AgentProposalApproved {
		t.Fatalf("expected approved status, got %+v (%v)", decided, err)
	}

	// Re-review of a decided proposal must fail without side effects.
	code, _ = doProposalAdmin(t, ts, http.MethodPost, "/v1/agent/proposals",
		`{"id":`+strconv.FormatInt(id, 10)+`,"decision":"reject","reason":"second thought"}`)
	if code != http.StatusConflict {
		t.Fatalf("expected 409 re-review, got %d", code)
	}
}

func TestAgentProposalsReject(t *testing.T) {
	ts := newHandlerTestServer(t)
	id := seedProposal(t, ts, "reject-candidate.test")

	code, data := doProposalAdmin(t, ts, http.MethodPost, "/v1/agent/proposals",
		`{"id":`+strconv.FormatInt(id, 10)+`,"decision":"reject","reason":"false positive"}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 reject, got %d: %s", code, data)
	}
	if override, _ := ts.Store.GetOverride(context.Background(), "reject-candidate.test"); override != nil {
		t.Fatalf("rejected proposal must not create overrides, got %+v", override)
	}
}

func TestAgentProposalsInvalidInput(t *testing.T) {
	ts := newHandlerTestServer(t)
	for _, body := range []string{
		`{"id":0,"decision":"approve"}`,
		`{"id":1,"decision":"maybe"}`,
		`not-json`,
	} {
		if code, data := doProposalAdmin(t, ts, http.MethodPost, "/v1/agent/proposals", body); code != http.StatusBadRequest {
			t.Fatalf("expected 400 for %q, got %d: %s", body, code, data)
		}
	}
	if code, _ := doProposalAdmin(t, ts, http.MethodPost, "/v1/agent/proposals", `{"id":999999,"decision":"approve"}`); code != http.StatusConflict {
		t.Fatalf("expected 409 unknown id, got %d", code)
	}
}
