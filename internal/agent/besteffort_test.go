package agent

import (
	"context"
	"testing"

	"safe-zone/internal/store"
)

// recordAgentEventBestEffort must stay silent-by-design on success and on a
// disabled store, but surface real persistence failures through the warning
// log instead of the old `_ =` swallow.
func TestRecordAgentEventBestEffortDisabledStore(t *testing.T) {
	recordAgentEventBestEffort(context.Background(), nil, "audit", "test_event", "subject", "{}")
	// A nil store must not panic and must not log an error path.
}

func TestRecordAgentEventBestEffortPropagatesNothing(t *testing.T) {
	// A real store handle must not panic on the happy path.
	db, err := store.New("", 30)
	if err != nil {
		t.Skipf("in-memory store unavailable: %v", err)
	}
	defer func() { _ = db.Close() }()
	recordAgentEventBestEffort(context.Background(), db, "audit", "test_event", "subject", "{}")
}
