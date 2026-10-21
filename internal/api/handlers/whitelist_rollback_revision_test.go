package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// A rollback changes the durable allow list, so the response has to name the
// revision it produced and whether the other process was notified. With Redis
// disabled the answer is published=false, not a failed request: the poll
// reconciler still applies the revision.
func TestWhitelistRollbackReportsRevisionAndPublishResult(t *testing.T) {
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")

	ts := newHandlerTestServer(t)
	ctx := context.Background()

	if err := ts.Store.UpdateWhitelist(ctx, []string{"before.example"}); err != nil {
		t.Fatal(err)
	}
	snapshotID, err := ts.Store.SaveWhitelistSnapshot(ctx, "test", []string{"before.example"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.Store.UpdateWhitelist(ctx, []string{"after.example"}); err != nil {
		t.Fatal(err)
	}
	if err := ts.Handler.Risk.Whitelist().LoadFromDB(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/whitelist/rollback?id="+strconv.FormatInt(snapshotID, 10), nil)
	rec := httptest.NewRecorder()
	ts.Handler.WhitelistRollbackHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Status    string `json:"status"`
		Snapshot  int64  `json:"snapshot"`
		Entries   int    `json:"entries"`
		Revision  int64  `json:"revision"`
		Published bool   `json:"published"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v (body %s)", err, rec.Body.String())
	}
	if body.Status != "ok" {
		t.Fatalf("status field = %q, want ok", body.Status)
	}
	if body.Snapshot != snapshotID {
		t.Fatalf("snapshot = %d, want %d", body.Snapshot, snapshotID)
	}
	if body.Entries != 1 {
		t.Fatalf("entries = %d, want 1", body.Entries)
	}
	if body.Revision != 3 {
		t.Fatalf("revision = %d, want 3 (two imports and the rollback)", body.Revision)
	}
	if body.Published {
		t.Fatal("published = true without Redis, want false")
	}

	if got := ts.Handler.Risk.Whitelist().Revision(); got != 3 {
		t.Fatalf("in-process revision = %d, want 3", got)
	}
	if !ts.Handler.Risk.Whitelist().ContainsExactIndex("before.example") {
		t.Fatal("the rollback did not restore the snapshot into the in-process index")
	}
	if ts.Handler.Risk.Whitelist().ContainsExactIndex("after.example") {
		t.Fatal("the index still contains the replaced domain after the rollback")
	}
}
