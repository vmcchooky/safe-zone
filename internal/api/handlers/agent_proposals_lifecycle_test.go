package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/store"
)

// HTTP-level lifecycle coverage for /v1/agent/proposals. The store layer
// pins the transition mechanics (see internal/store/proposals_test.go and
// proposals_race_test.go); these tests pin the HTTP contract the audit
// found unpinned: expiry through the endpoint, double-approve and
// reject-then-approve idempotency of side effects, the audit events the
// decisions record, and the authorization matrix.

// seedExpiredProposal creates a pending proposal whose TTL has already
// lapsed — the read-time expiry path, since no sweeper writes status='expired'.
func seedExpiredProposal(t *testing.T, ts *handlerTestServer, domain string) int64 {
	t.Helper()
	created, err := ts.Store.CreateAgentProposal(context.Background(), store.AgentProposal{
		Domain:     domain,
		Action:     "block",
		Score:      85,
		Confidence: 0.95,
		Reasons:    []string{"tls: self-signed certificate"},
		ExpiresAt:  time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatalf("seed expired proposal: %v", err)
	}
	return created.ID
}

func agentEvents(t *testing.T, ts *handlerTestServer, eventTypes ...string) []store.AgentEvent {
	t.Helper()
	events, err := ts.Store.QueryAgentEvents(context.Background(), time.Now().Add(-time.Hour), eventTypes, 100)
	if err != nil {
		t.Fatalf("query agent events: %v", err)
	}
	return events
}

func countEvents(events []store.AgentEvent, eventType string) int {
	count := 0
	for _, event := range events {
		if event.EventType == eventType {
			count++
		}
	}
	return count
}

func TestAgentProposalsExpiredDecisionIsRejectedWithoutSideEffects(t *testing.T) {
	ts := newHandlerTestServer(t)
	id := seedExpiredProposal(t, ts, "lapsed.test")

	code, data := doProposalAdmin(t, ts, http.MethodPost, "/v1/agent/proposals",
		`{"id":`+strconv.FormatInt(id, 10)+`,"decision":"approve","reason":"too late"}`)
	if code != http.StatusConflict {
		t.Fatalf("expired decision = %d, want 409: %s", code, data)
	}
	if !strings.Contains(string(data), "expired") {
		t.Fatalf("conflict body should name the expiry: %s", data)
	}

	// The refused decision must not enforce anything or record approval.
	if override, _ := ts.Store.GetOverride(context.Background(), "lapsed.test"); override != nil {
		t.Fatalf("expired approval created an override: %+v", override)
	}
	if got := countEvents(agentEvents(t, ts, "proposal_approved"), "proposal_approved"); got != 0 {
		t.Fatalf("expired approval recorded %d proposal_approved events, want 0", got)
	}
	if decided, err := ts.Store.GetAgentProposal(context.Background(), id); err != nil || decided.Status != store.AgentProposalPending {
		t.Fatalf("expired proposal row mutated: %+v (%v)", decided, err)
	}
}

func TestAgentProposalsDoubleApproveRecordsExactlyOneEvent(t *testing.T) {
	ts := newHandlerTestServer(t)
	id := seedProposal(t, ts, "twice.test")

	for i := 0; i < 2; i++ {
		code, _ := doProposalAdmin(t, ts, http.MethodPost, "/v1/agent/proposals",
			`{"id":`+strconv.FormatInt(id, 10)+`,"decision":"approve","reason":"confirmed kit"}`)
		if i == 0 && code != http.StatusOK {
			t.Fatalf("first approve = %d, want 200", code)
		}
		if i == 1 && code != http.StatusConflict {
			t.Fatalf("second approve = %d, want 409", code)
		}
	}

	events := agentEvents(t, ts, "proposal_approved")
	if got := countEvents(events, "proposal_approved"); got != 1 {
		t.Fatalf("proposal_approved recorded %d times, want exactly 1", got)
	}
	if override, _ := ts.Store.GetOverride(context.Background(), "twice.test"); override == nil {
		t.Fatal("the approval override is missing after the first approve")
	}
}

func TestAgentProposalsRejectThenApproveCreatesNoOverride(t *testing.T) {
	ts := newHandlerTestServer(t)
	id := seedProposal(t, ts, "rejected-first.test")

	code, _ := doProposalAdmin(t, ts, http.MethodPost, "/v1/agent/proposals",
		`{"id":`+strconv.FormatInt(id, 10)+`,"decision":"reject","reason":"looks benign"}`)
	if code != http.StatusOK {
		t.Fatalf("reject = %d, want 200", code)
	}
	code, _ = doProposalAdmin(t, ts, http.MethodPost, "/v1/agent/proposals",
		`{"id":`+strconv.FormatInt(id, 10)+`,"decision":"approve","reason":"changed my mind"}`)
	if code != http.StatusConflict {
		t.Fatalf("approve-after-reject = %d, want 409", code)
	}

	if override, _ := ts.Store.GetOverride(context.Background(), "rejected-first.test"); override != nil {
		t.Fatalf("refused approval still created an override: %+v", override)
	}
	events := agentEvents(t, ts, "proposal_approved", "proposal_rejected")
	if got := countEvents(events, "proposal_approved"); got != 0 {
		t.Fatalf("refused approval recorded %d proposal_approved events, want 0", got)
	}
	if got := countEvents(events, "proposal_rejected"); got != 1 {
		t.Fatalf("proposal_rejected recorded %d times, want exactly 1", got)
	}
}

func TestAgentProposalsDecisionsRecordAuditEvents(t *testing.T) {
	ts := newHandlerTestServer(t)
	approveID := seedProposal(t, ts, "audited-approve.test")
	rejectID := seedProposal(t, ts, "audited-reject.test")

	code, _ := doProposalAdmin(t, ts, http.MethodPost, "/v1/agent/proposals",
		`{"id":`+strconv.FormatInt(approveID, 10)+`,"decision":"approve","reason":"confirmed kit"}`)
	if code != http.StatusOK {
		t.Fatalf("approve = %d, want 200", code)
	}
	code, _ = doProposalAdmin(t, ts, http.MethodPost, "/v1/agent/proposals",
		`{"id":`+strconv.FormatInt(rejectID, 10)+`,"decision":"reject","reason":"looks benign"}`)
	if code != http.StatusOK {
		t.Fatalf("reject = %d, want 200", code)
	}

	events := agentEvents(t, ts, "proposal_approved", "proposal_rejected")
	if got := countEvents(events, "proposal_approved"); got != 1 {
		t.Fatalf("proposal_approved events = %d, want 1", got)
	}
	if got := countEvents(events, "proposal_rejected"); got != 1 {
		t.Fatalf("proposal_rejected events = %d, want 1", got)
	}
	for _, event := range events {
		var details map[string]any
		if err := json.Unmarshal([]byte(event.Details), &details); err != nil {
			t.Fatalf("event %s details are not JSON: %q", event.EventType, event.Details)
		}
		if _, ok := details["proposal_id"]; !ok {
			t.Fatalf("event %s details missing proposal_id: %q", event.EventType, event.Details)
		}
	}
}

func TestAgentProposalsAuthorizationMatrix(t *testing.T) {
	ts := newHandlerTestServer(t)
	id := seedProposal(t, ts, "authz.test")

	post := func(target, body string, withAuth bool) *httptest.ResponseRecorder {
		req, err := http.NewRequest(http.MethodPost, ts.Server.URL+target, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if withAuth {
			ts.addAdminBearer(req)
		}
		rec := httptest.NewRecorder()
		ts.Handler.RequireAdminForMutationFunc(ts.Handler.AgentProposalsHandler)(rec, req)
		return rec
	}

	// Unauthenticated: both methods fail closed.
	if rec := post("/v1/agent/proposals", `{"id":1,"decision":"approve","reason":"nope"}`, false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated POST = %d, want 401", rec.Code)
	}
	unauthGet, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/agent/proposals", nil)
	if err != nil {
		t.Fatal(err)
	}
	unauthRec := httptest.NewRecorder()
	ts.Handler.RequireAdminForMutationFunc(ts.Handler.AgentProposalsHandler)(unauthRec, unauthGet)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET = %d, want 401", unauthRec.Code)
	}

	// Read-only sessions may list but not decide. Guest access is enabled
	// through the settings endpoint and the session comes from the login
	// flow, mirroring the access lifecycle test.
	enableReq, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/settings/guest-access",
		strings.NewReader(`{"enabled":true,"password":"guest-pass-123"}`))
	if err != nil {
		t.Fatal(err)
	}
	enableReq.Header.Set("Content-Type", "application/json")
	ts.addAdminBearer(enableReq)
	enableRec := httptest.NewRecorder()
	ts.Handler.RequireAdminFunc(ts.Handler.GuestAccessHandler)(enableRec, enableReq)
	if enableRec.Code != http.StatusOK {
		t.Fatalf("enable guest access = %d, want 200: %s", enableRec.Code, enableRec.Body.String())
	}

	loginReq, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/auth/login",
		strings.NewReader(`{"username":"guest","password":"guest-pass-123"}`))
	if err != nil {
		t.Fatal(err)
	}
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	ts.Handler.AuthLoginHandler(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("guest login = %d, want 200: %s", loginRec.Code, loginRec.Body.String())
	}
	var guestCookie *http.Cookie
	for _, cookie := range loginRec.Result().Cookies() {
		if cookie.Name == "admin_session" {
			guestCookie = cookie
			break
		}
	}
	if guestCookie == nil {
		t.Fatal("guest login returned no session cookie")
	}

	guestGet, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/agent/proposals", nil)
	if err != nil {
		t.Fatal(err)
	}
	guestGet.AddCookie(guestCookie)
	guestRec := httptest.NewRecorder()
	ts.Handler.RequireAdminForMutationFunc(ts.Handler.AgentProposalsHandler)(guestRec, guestGet)
	if guestRec.Code != http.StatusOK {
		t.Fatalf("guest GET = %d, want 200 (reads are auth-only)", guestRec.Code)
	}

	guestPost, err := http.NewRequest(http.MethodPost, ts.Server.URL+"/v1/agent/proposals",
		strings.NewReader(`{"id":`+strconv.FormatInt(id, 10)+`,"decision":"approve","reason":"guest attempt"}`))
	if err != nil {
		t.Fatal(err)
	}
	guestPost.AddCookie(guestCookie)
	guestPost.Header.Set("Origin", ts.Server.URL)
	guestPostRec := httptest.NewRecorder()
	ts.Handler.RequireAdminForMutationFunc(ts.Handler.AgentProposalsHandler)(guestPostRec, guestPost)
	if guestPostRec.Code != http.StatusForbidden {
		t.Fatalf("guest POST = %d, want 403", guestPostRec.Code)
	}
	// The 403 must be the read-only role gate, not an earlier CSRF refusal:
	// the Origin above is same-origin, so reaching this body proves the role
	// check made the decision.
	if !strings.Contains(guestPostRec.Body.String(), "Khách không được quyền thay đổi") {
		t.Fatalf("guest POST 403 body is not the read-only gate: %s", guestPostRec.Body.String())
	}
	if override, _ := ts.Store.GetOverride(context.Background(), "authz.test"); override != nil {
		t.Fatalf("guest decision created an override: %+v", override)
	}

	// Unsupported methods are rejected by the handler itself.
	putReq, err := http.NewRequest(http.MethodPut, ts.Server.URL+"/v1/agent/proposals", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	ts.addAdminBearer(putReq)
	putRec := httptest.NewRecorder()
	ts.Handler.RequireAdminForMutationFunc(ts.Handler.AgentProposalsHandler)(putRec, putReq)
	if putRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT = %d, want 405", putRec.Code)
	}
}
