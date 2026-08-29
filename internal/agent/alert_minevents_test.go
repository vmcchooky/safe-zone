package agent

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// MinEvents gates on the whole pending backlog: a threshold above the page
// size must not starve alerts forever.
func TestAlertMinEventsAbovePageSizeTriggersOnFullBacklog(t *testing.T) {
	db := newTestStore(t)
	capture := &webhookCapture{}
	server := newWebhookServer(t, capture, nil)
	defer server.Close()

	task := NewAlertTask(db, AlertConfig{WebhookURL: server.URL, MinEvents: 200})
	task.http = server.Client()
	rewindAlertCursor(t, task, time.Now().Add(-time.Hour))

	// Backlog of 199 stays under the threshold: nothing is sent and the
	// cursor stays put so the events remain pending.
	for i := 0; i < 199; i++ {
		_ = db.RecordAgentEvent(context.Background(), "audit", "auto_block", fmt.Sprintf("threshold-%03d.test", i), `{}`)
	}
	time.Sleep(50 * time.Millisecond)

	if err := task.Run(context.Background()); err != nil {
		t.Fatalf("alert run below threshold: %v", err)
	}
	if got := len(capture.domains()); got != 0 {
		t.Fatalf("expected no delivery below MinEvents, got %d", got)
	}
	if task.snapshotCursor().ID != 0 {
		t.Fatal("cursor must stay put while below MinEvents")
	}

	// Crossing the threshold delivers the entire backlog across pages.
	for i := 0; i < 2; i++ {
		_ = db.RecordAgentEvent(context.Background(), "audit", "auto_block", fmt.Sprintf("threshold-cross-%d.test", i), `{}`)
	}
	time.Sleep(50 * time.Millisecond)

	if err := task.Run(context.Background()); err != nil {
		t.Fatalf("alert run at threshold: %v", err)
	}
	if got := len(capture.domains()); got != 201 {
		t.Fatalf("expected the whole pending backlog delivered across pages, got %d", got)
	}

	// Restart semantics: the persisted cursor sits past every delivered
	// event, so a reconstructed task neither replays nor loses the remainder.
	restarted := NewAlertTask(db, AlertConfig{WebhookURL: server.URL, MinEvents: 200})
	restarted.http = server.Client()
	if err := restarted.Run(context.Background()); err != nil {
		t.Fatalf("restarted run: %v", err)
	}
	if got := len(capture.domains()); got != 201 {
		t.Fatalf("restart must not replay the delivered backlog, got %d deliveries", got)
	}
}
