package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func doWhitelistRequest(t *testing.T, ts *handlerTestServer, method, path, body string, cookie *http.Cookie, bearer bool) *http.Response {
	t.Helper()

	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.Server.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		// Cookie-authenticated mutations require a same-origin CSRF source.
		req.Header.Set("Origin", ts.Server.URL)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if bearer {
		ts.addAdminBearer(req)
	}
	resp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func seedWhitelistSnapshot(t *testing.T, ts *handlerTestServer, domains []string) int64 {
	t.Helper()
	if err := ts.Store.UpdateWhitelist(context.Background(), domains); err != nil {
		t.Fatal(err)
	}
	id, err := ts.Store.SaveWhitelistSnapshot(context.Background(), "unit-test", domains)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestWhitelistSnapshotHandlersRejectTheWrongMethod(t *testing.T) {
	ts := newHandlerTestServer(t)

	snapshots := doWhitelistRequest(t, ts, http.MethodPost, "/v1/whitelist/snapshots", "", nil, true)
	defer func() { _ = snapshots.Body.Close() }()
	if snapshots.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST snapshots = %d, want 405", snapshots.StatusCode)
	}

	rollback := doWhitelistRequest(t, ts, http.MethodGet, "/v1/whitelist/rollback", "", nil, true)
	defer func() { _ = rollback.Body.Close() }()
	if rollback.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET rollback = %d, want 405", rollback.StatusCode)
	}
}

func TestWhitelistRollbackHandlerRequiresAdmin(t *testing.T) {
	ts := newHandlerTestServer(t)
	guest := enableGuestAccount(t, ts)

	resp := doWhitelistRequest(t, ts, http.MethodPost, "/v1/whitelist/rollback",
		`{"reason":"guest must not roll back"}`, guest, false)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("guest rollback = %d, want 403", resp.StatusCode)
	}
}

func TestWhitelistRollbackHandlerUnknownSnapshotIsNotFound(t *testing.T) {
	ts := newHandlerTestServer(t)
	admin := ts.adminSessionCookie(t)

	empty := doWhitelistRequest(t, ts, http.MethodPost, "/v1/whitelist/rollback",
		`{"reason":"restore a snapshot that does not exist"}`, admin, false)
	defer func() { _ = empty.Body.Close() }()
	if empty.StatusCode != http.StatusNotFound {
		t.Fatalf("rollback with no snapshots = %d, want 404", empty.StatusCode)
	}

	missing := doWhitelistRequest(t, ts, http.MethodPost, "/v1/whitelist/rollback?id=9999",
		`{"reason":"restore a snapshot that does not exist"}`, admin, false)
	defer func() { _ = missing.Body.Close() }()
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("rollback with unknown id = %d, want 404", missing.StatusCode)
	}
}

func TestWhitelistRollbackHandlerCorruptSnapshotIsServerError(t *testing.T) {
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")

	ts := newHandlerTestServer(t)
	snapshotID := seedWhitelistSnapshot(t, ts, []string{"before.example"})

	// Tamper with the stored blob after the digest was written. The handler
	// must refuse to apply it; a corrupt row is not a valid rollback.
	raw, err := sql.Open("sqlite", ts.DBPath+"?_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	if _, err := raw.Exec(`UPDATE whitelist_snapshots SET domains = 'tampered.example' WHERE id = ?`, snapshotID); err != nil {
		t.Fatal(err)
	}

	admin := ts.adminSessionCookie(t)
	resp := doWhitelistRequest(t, ts, http.MethodPost, "/v1/whitelist/rollback?id="+strconv.FormatInt(snapshotID, 10),
		`{"reason":"restore the verified snapshot"}`, admin, false)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("corrupt snapshot rollback = %d, want 500", resp.StatusCode)
	}
}

func TestWhitelistRollbackRequiresAReason(t *testing.T) {
	ts := newHandlerTestServer(t)
	admin := ts.adminSessionCookie(t)

	cases := []struct {
		name string
		body string
	}{
		{"missing body", ""},
		{"empty object", `{}`},
		{"too short", `{"reason":"short"}`},
		{"whitespace only", `{"reason":"        "}`},
		{"invalid json", `{"reason":`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := doWhitelistRequest(t, ts, http.MethodPost, "/v1/whitelist/rollback", tc.body, admin, false)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
		})
	}
}

func TestWhitelistSnapshotListingAndRollbackAudit(t *testing.T) {
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")

	ts := newHandlerTestServer(t)
	ctx := context.Background()
	admin := ts.adminSessionCookie(t)

	firstID := seedWhitelistSnapshot(t, ts, []string{"one.example"})
	if err := ts.Store.UpdateWhitelist(ctx, []string{"two.example"}); err != nil {
		t.Fatal(err)
	}
	secondID, err := ts.Store.SaveWhitelistSnapshot(ctx, "second-source", []string{"two.example"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.Store.UpdateWhitelist(ctx, []string{"three.example"}); err != nil {
		t.Fatal(err)
	}
	if err := ts.Handler.Risk.Whitelist().LoadFromDB(); err != nil {
		t.Fatal(err)
	}

	var listing struct {
		Snapshots []struct {
			ID         int64  `json:"id"`
			CreatedAt  string `json:"created_at"`
			Source     string `json:"source"`
			EntryCount int    `json:"entry_count"`
			SHA256     string `json:"sha256"`
		} `json:"snapshots"`
		LastRollback *struct {
			AuditID       int64  `json:"audit_id"`
			CreatedAt     string `json:"created_at"`
			SnapshotID    int64  `json:"snapshot_id"`
			Entries       int    `json:"entries"`
			Actor         string `json:"actor"`
			Reason        string `json:"reason"`
			Revision      int64  `json:"revision"`
			CorrelationID string `json:"correlation_id"`
		} `json:"last_rollback"`
	}

	resp := doWhitelistRequest(t, ts, http.MethodGet, "/v1/whitelist/snapshots", "", admin, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list snapshots = %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&listing); err != nil {
		t.Fatalf("decode listing: %v", err)
	}
	_ = resp.Body.Close()

	if len(listing.Snapshots) != 2 {
		t.Fatalf("snapshot count = %d, want 2", len(listing.Snapshots))
	}
	if listing.Snapshots[0].ID != secondID || listing.Snapshots[1].ID != firstID {
		t.Fatalf("snapshots are not newest-first: %+v", listing.Snapshots)
	}
	if listing.Snapshots[0].Source != "second-source" || listing.Snapshots[0].EntryCount != 1 || listing.Snapshots[0].SHA256 == "" {
		t.Fatalf("snapshot metadata is incomplete: %+v", listing.Snapshots[0])
	}
	if listing.LastRollback != nil {
		t.Fatalf("last_rollback = %+v before any rollback, want nil", listing.LastRollback)
	}

	reason := "restore the curated allow list after a bad import"
	rollback := doWhitelistRequest(t, ts, http.MethodPost, "/v1/whitelist/rollback?id="+strconv.FormatInt(firstID, 10),
		`{"reason":"`+reason+`"}`, admin, false)
	if rollback.StatusCode != http.StatusOK {
		t.Fatalf("rollback = %d, body = %s", rollback.StatusCode, readResponseBody(t, rollback))
	}
	var rollbackBody struct {
		Revision      int64 `json:"revision"`
		Published     bool  `json:"published"`
		AuditRecorded bool  `json:"audit_recorded"`
	}
	if err := json.NewDecoder(rollback.Body).Decode(&rollbackBody); err != nil {
		t.Fatalf("decode rollback: %v", err)
	}
	_ = rollback.Body.Close()
	if rollbackBody.Revision != 4 {
		t.Fatalf("rollback revision = %d, want 4", rollbackBody.Revision)
	}
	if rollbackBody.Published {
		t.Fatal("published = true without Redis, want false")
	}
	if !rollbackBody.AuditRecorded {
		t.Fatal("audit_recorded = false, want the rollback in agent_audit_log")
	}

	resp = doWhitelistRequest(t, ts, http.MethodGet, "/v1/whitelist/snapshots", "", admin, false)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list snapshots after rollback = %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&listing); err != nil {
		t.Fatalf("decode listing after rollback: %v", err)
	}
	if listing.LastRollback == nil {
		t.Fatal("last_rollback is nil after a rollback")
	}
	if listing.LastRollback.SnapshotID != firstID {
		t.Fatalf("last_rollback.snapshot_id = %d, want %d", listing.LastRollback.SnapshotID, firstID)
	}
	if listing.LastRollback.Actor != "admin" {
		t.Fatalf("last_rollback.actor = %q, want admin", listing.LastRollback.Actor)
	}
	if listing.LastRollback.Reason != reason {
		t.Fatalf("last_rollback.reason = %q, want %q", listing.LastRollback.Reason, reason)
	}
	if listing.LastRollback.Revision != 4 {
		t.Fatalf("last_rollback.revision = %d, want 4", listing.LastRollback.Revision)
	}
	if listing.LastRollback.CorrelationID == "" {
		t.Fatal("last_rollback.correlation_id is empty")
	}
	if listing.LastRollback.AuditID <= 0 || listing.LastRollback.CreatedAt == "" {
		t.Fatalf("last_rollback is missing its audit identity: %+v", listing.LastRollback)
	}

	// The audit row is the durable record, not only the JSON view built from
	// it. Query it directly and assert the required fields.
	events, err := ts.Store.QueryAgentEvents(ctx, time.Now().Add(-time.Minute), []string{"rollback"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("rollback audit events = %d, want 1", len(events))
	}
	if events[0].TaskName != "whitelist" {
		t.Fatalf("audit task_name = %q, want whitelist", events[0].TaskName)
	}
	var details whitelistRollbackDetails
	if err := json.Unmarshal([]byte(events[0].Details), &details); err != nil {
		t.Fatalf("decode audit details: %v", err)
	}
	if details.SnapshotID != firstID || details.Actor != "admin" || details.Reason != reason || details.Entries != 1 {
		t.Fatalf("audit details = %+v", details)
	}

	if !ts.Handler.Risk.Whitelist().ContainsExactIndex("one.example") {
		t.Fatal("the rollback did not restore the snapshot into the in-process index")
	}
}

func readResponseBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
