package agent

import (
	"context"
	"errors"

	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
	"safe-zone/internal/store"
)

// recordAgentEventBestEffort wraps RecordAgentEvent for durable event history
// that must never fail the surrounding task. Failures were previously swallowed
// with `_ =`, which made a broken event table invisible: the task kept running
// while its audit trail silently stopped. Logging the error makes the gap
// observable without promoting the write to a hard failure.
func recordAgentEventBestEffort(ctx context.Context, st *store.DB, taskType, event, subject, details string) {
	if st == nil {
		return
	}
	if err := st.RecordAgentEvent(ctx, taskType, event, subject, details); err != nil && !errors.Is(err, store.ErrDisabled) {
		logjson.Warn("agent event persistence failed; event dropped", correlation.Fields(ctx, map[string]any{
			"service":   "agent",
			"task_type": taskType,
			"event":     event,
			"subject":   subject,
			"error":     err.Error(),
		}))
	}
}
