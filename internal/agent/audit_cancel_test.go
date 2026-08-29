package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// The audit cursor must survive a cancelled task context: a mid-page
// cancellation commits the processed prefix through a detached bounded
// context, so a restart resumes instead of repeating the page.
func TestAuditCursorPersistsDespiteCanceledContext(t *testing.T) {
	db := newTestStore(t)
	task := NewAuditTask(db, nil, nil, AuditConfig{MinOccurrences: 1, MaxPerCycle: 10})

	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	state := auditCursorState{Version: auditCursorVersion, WindowEnd: time.Now().UTC().Format(time.RFC3339Nano), LastDomain: "bb-prefix.test"}
	task.storeCursor(canceled, state)

	raw, err := db.GetSystemConfig(context.Background(), auditCursorConfigKey)
	if err != nil || raw == "" {
		t.Fatalf("cursor must persist despite canceled context (err=%v)", err)
	}
	var persisted auditCursorState
	if err := json.Unmarshal([]byte(raw), &persisted); err != nil {
		t.Fatalf("decode persisted cursor: %v", err)
	}
	if persisted.LastDomain != "bb-prefix.test" {
		t.Fatalf("expected persisted prefix cursor, got %+v", persisted)
	}

	// A reconstructed task (restart) must load the prefix and resume after it.
	restarted := NewAuditTask(db, nil, nil, AuditConfig{MinOccurrences: 1, MaxPerCycle: 10})
	if got := restarted.snapshotCursor(); got.LastDomain != "bb-prefix.test" {
		t.Fatalf("expected restart to load the persisted prefix, got %+v", got)
	}
}

// A mid-page cancellation persists the processed prefix (durable, visible to
// a reconstructed task) and the already-audited domains are not processed a
// second time. The test seam fires after the first domain is audited, so the
// cancellation deterministically lands mid-page.
func TestAuditMidPageCancellationPersistsPrefixWithoutReprocessing(t *testing.T) {
	db := newTestStore(t)

	domains := []string{"aa-cancel-prefix.test", "bb-cancel-mid.test", "cc-cancel-tail.test"}
	for _, domain := range domains {
		seedSuspiciousDomains(t, db, domain, 3)
	}

	task := NewAuditTask(db, nil, nil, AuditConfig{
		MinOccurrences: 1,
		MaxPerCycle:    3,
		EnrichTimeout:  100 * time.Millisecond,
	})

	runCtx, cancel := context.WithCancel(context.Background())
	testHookAfterDomain = func() { cancel() }
	defer func() { testHookAfterDomain = nil }()

	runErr := task.Run(runCtx)
	if runErr == nil {
		t.Fatal("expected the cancelled audit cycle to report an error")
	}

	cursor := task.snapshotCursor()
	if cursor.LastDomain != "aa-cancel-prefix.test" {
		t.Fatalf("expected durable prefix cursor at the first domain, got %+v", cursor)
	}
	raw, err := db.GetSystemConfig(context.Background(), auditCursorConfigKey)
	if err != nil || raw == "" {
		t.Fatalf("prefix cursor must be durable after cancellation (err=%v)", err)
	}
	var persisted auditCursorState
	if err := json.Unmarshal([]byte(raw), &persisted); err != nil || persisted.LastDomain != "aa-cancel-prefix.test" {
		t.Fatalf("expected persisted prefix cursor, got raw=%q (err=%v)", raw, err)
	}

	// Restart semantics: a fresh task resumes from the persisted prefix and
	// finishes the window without re-auditing the processed prefix.
	restarted := NewAuditTask(db, nil, nil, AuditConfig{
		MinOccurrences: 1,
		MaxPerCycle:    3,
		EnrichTimeout:  100 * time.Millisecond,
	})
	if err := restarted.Run(context.Background()); err != nil {
		t.Fatalf("restarted audit run: %v", err)
	}

	counts := map[string]int{}
	events, err := db.QueryAgentEvents(context.Background(), time.Now().Add(-time.Hour), []string{"reviewed", "auto_block"}, 100)
	if err != nil {
		t.Fatalf("query audit events: %v", err)
	}
	for _, e := range events {
		counts[e.Domain]++
	}
	for _, domain := range domains {
		if counts[domain] == 0 {
			t.Fatalf("domain %s was never audited", domain)
		}
	}
	if counts["aa-cancel-prefix.test"] != 1 {
		t.Fatalf("processed prefix must not be re-audited after restart, got %d events", counts["aa-cancel-prefix.test"])
	}
}
