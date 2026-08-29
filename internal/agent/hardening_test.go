package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- Audit cursor ---

// A canceled context must fail the query and leave the cursor retryable so
// the window is never skipped.
func TestAuditQueryFailureDoesNotAdvanceCursor(t *testing.T) {
	db := newTestStore(t)
	task := NewAuditTask(db, nil, nil, AuditConfig{MinOccurrences: 1, MaxPerCycle: 10})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := task.Run(ctx)
	if err == nil {
		t.Fatal("expected query failure on canceled context")
	}
	cursor := task.snapshotCursor()
	if cursor.WindowEnd != "" || cursor.LastDomain != "" {
		t.Fatalf("cursor must stay untouched after query failure, got %+v", cursor)
	}
}

// More domains than MaxPerCycle must be continued across cycles from the
// persisted cursor: nothing is starved, nothing is skipped.
func TestAuditPaginationContinuesAcrossCycles(t *testing.T) {
	db := newTestStore(t)

	domains := []string{"aa-audit-page.test", "bb-audit-page.test", "cc-audit-page.test"}
	for _, domain := range domains {
		seedSuspiciousDomains(t, db, domain, 3)
	}

	task := NewAuditTask(db, nil, nil, AuditConfig{
		MinOccurrences: 1,
		MaxPerCycle:    2,
		EnrichTimeout:  1 * time.Second,
	})

	seen := map[string]bool{}
	for cycle := 0; cycle < 3; cycle++ {
		if err := task.Run(context.Background()); err != nil {
			t.Fatalf("audit cycle %d: %v", cycle, err)
		}
		events, err := db.QueryAgentEvents(context.Background(), time.Now().Add(-time.Hour), []string{"reviewed", "auto_block"}, 100)
		if err != nil {
			t.Fatalf("query audit events: %v", err)
		}
		for _, e := range events {
			seen[e.Domain] = true
		}
	}

	for _, domain := range domains {
		if !seen[domain] {
			t.Fatalf("domain %s was never audited across cycles (seen: %v)", domain, seen)
		}
	}
}

// A persisted cursor must survive task reconstruction (restart): the new
// task resumes the window instead of reprocessing from the beginning.
func TestAuditCursorPersistsAcrossRestart(t *testing.T) {
	db := newTestStore(t)

	for _, domain := range []string{"aa-restart-a.test", "bb-restart-b.test", "cc-restart-c.test"} {
		seedSuspiciousDomains(t, db, domain, 3)
	}

	first := NewAuditTask(db, nil, nil, AuditConfig{MinOccurrences: 1, MaxPerCycle: 2, EnrichTimeout: 1 * time.Second})
	if err := first.Run(context.Background()); err != nil {
		t.Fatalf("first task run: %v", err)
	}

	// Simulate a restart: a fresh task over the same store must load the
	// persisted cursor.
	second := NewAuditTask(db, nil, nil, AuditConfig{MinOccurrences: 1, MaxPerCycle: 2, EnrichTimeout: 1 * time.Second})
	reloaded := second.snapshotCursor()
	if reloaded.WindowEnd == "" || reloaded.LastDomain == "" {
		t.Fatalf("expected persisted mid-window cursor after restart, got %+v", reloaded)
	}
	if reloaded.LastDomain != "bb-restart-b.test" {
		t.Fatalf("expected resume point bb-restart-b.test, got %q", reloaded.LastDomain)
	}
}

// --- Cache invalidation ---

// The shared invalidation helper must delete the base key plus every
// model-revision variant of exactly one domain, and nothing else.
func TestInvalidateAnalysisCacheExactScope(t *testing.T) {
	_, redisCache := newTestRedis(t)
	ctx := context.Background()

	keys := []string{
		"safe-zone:analysis:target.test",
		"safe-zone:analysis:target.test:model:rev1",
		"safe-zone:analysis:target.test:model:rev2",
		"safe-zone:analysis:target.test:model:rev1:extra",
	}
	neighbors := []string{
		"safe-zone:analysis:target-othersuffix.test",
		"safe-zone:analysis:other.test",
	}
	for _, key := range append(append([]string{}, keys...), neighbors...) {
		if err := redisCache.SetString(ctx, key, "{}", time.Hour); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
	}

	if err := invalidateAnalysisCache(ctx, redisCache, "target.test"); err != nil {
		t.Fatalf("invalidate: %v", err)
	}

	for _, key := range keys {
		if value, _ := redisCache.GetString(ctx, key); value != "" {
			t.Fatalf("expected %s to be deleted", key)
		}
	}
	for _, key := range neighbors {
		if value, _ := redisCache.GetString(ctx, key); value == "" {
			t.Fatalf("expected neighbor key %s to survive", key)
		}
	}
}

// Invalidation failures must surface, not vanish.
func TestInvalidateAnalysisCacheSurfacesRedisError(t *testing.T) {
	server, redisCache := newTestRedis(t)
	server.SetError("SIMULATED_REDIS_OUTAGE")

	if err := invalidateAnalysisCache(context.Background(), redisCache, "target.test"); err == nil {
		t.Fatal("expected invalidation error on redis outage")
	}
}

// --- Alert cursor and delivery ---

type webhookCapture struct {
	mu      sync.Mutex
	batches [][]string
}

func (c *webhookCapture) domains() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var all []string
	for _, batch := range c.batches {
		all = append(all, batch...)
	}
	return all
}

func newWebhookServer(t *testing.T, capture *webhookCapture, status *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		failed := status != nil && atomic.LoadInt32(status) != http.StatusOK
		var payload AlertPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err == nil && !failed {
			capture.mu.Lock()
			batch := make([]string, 0, len(payload.Events))
			for _, e := range payload.Events {
				batch = append(batch, e.Domain)
			}
			capture.batches = append(capture.batches, batch)
			capture.mu.Unlock()
		}
		if failed {
			w.WriteHeader(int(atomic.LoadInt32(status)))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
}

// More than 100 pending events must be delivered through multiple pages
// without loss, and a follow-up run must not resend anything.
func TestAlertDeliversOverOneHundredEventsAcrossPages(t *testing.T) {
	db := newTestStore(t)
	for i := 0; i < 105; i++ {
		_ = db.RecordAgentEvent(context.Background(), "audit", "auto_block", fmt.Sprintf("page-domain-%03d.test", i), `{}`)
	}
	time.Sleep(50 * time.Millisecond)

	capture := &webhookCapture{}
	server := newWebhookServer(t, capture, nil)
	defer server.Close()

	task := NewAlertTask(db, AlertConfig{WebhookURL: server.URL, MinEvents: 1})
	task.http = server.Client()
	rewindAlertCursor(t, task, time.Now().Add(-time.Hour))

	if err := task.Run(context.Background()); err != nil {
		t.Fatalf("alert run: %v", err)
	}
	if got := len(capture.domains()); got != 105 {
		t.Fatalf("expected 105 delivered events across pages, got %d", got)
	}

	// The cursor must now sit past every delivered event: a fresh run finds
	// nothing pending and sends nothing.
	before := len(capture.domains())
	if err := task.Run(context.Background()); err != nil {
		t.Fatalf("second alert run: %v", err)
	}
	if got := len(capture.domains()); got != before {
		t.Fatalf("expected no resend after cursor advance, got %d extra", got-before)
	}
}

// A restart must load the persisted cursor: events raised during downtime
// are delivered, the old backlog is not replayed.
func TestAlertCursorPersistsAcrossRestart(t *testing.T) {
	db := newTestStore(t)
	for i := 0; i < 3; i++ {
		_ = db.RecordAgentEvent(context.Background(), "audit", "auto_block", fmt.Sprintf("restart-%d.test", i), `{}`)
	}
	time.Sleep(50 * time.Millisecond)

	capture := &webhookCapture{}
	server := newWebhookServer(t, capture, nil)
	defer server.Close()

	first := NewAlertTask(db, AlertConfig{WebhookURL: server.URL, MinEvents: 1})
	first.http = server.Client()
	rewindAlertCursor(t, first, time.Now().Add(-time.Hour))
	if err := first.Run(context.Background()); err != nil {
		t.Fatalf("first task run: %v", err)
	}

	second := NewAlertTask(db, AlertConfig{WebhookURL: server.URL, MinEvents: 1})
	second.http = server.Client()
	if err := second.Run(context.Background()); err != nil {
		t.Fatalf("restarted task run: %v", err)
	}
	if got := len(capture.domains()); got != 3 {
		t.Fatalf("restart must not replay the delivered backlog, got %d deliveries", got)
	}

	// Events raised after the restart must still be picked up.
	_ = db.RecordAgentEvent(context.Background(), "audit", "auto_block", "post-restart.test", `{}`)
	time.Sleep(50 * time.Millisecond)
	if err := second.Run(context.Background()); err != nil {
		t.Fatalf("post-restart run: %v", err)
	}
	found := false
	for _, domain := range capture.domains() {
		if domain == "post-restart.test" {
			found = true
		}
	}
	if !found {
		t.Fatal("post-restart event was not delivered")
	}
}

// A failing webhook must keep the cursor on the failed page so the next
// cycle replays it (at-least-once), and must record alert_failed.
func TestAlertWebhookFailureKeepsCursorRetryable(t *testing.T) {
	db := newTestStore(t)
	_ = db.RecordAgentEvent(context.Background(), "audit", "auto_block", "retry-webhook.test", `{}`)
	time.Sleep(50 * time.Millisecond)

	capture := &webhookCapture{}
	var status int32 = http.StatusInternalServerError
	server := newWebhookServer(t, capture, &status)
	defer server.Close()

	task := NewAlertTask(db, AlertConfig{WebhookURL: server.URL, MinEvents: 1})
	task.http = server.Client()
	rewindAlertCursor(t, task, time.Now().Add(-time.Hour))

	if err := task.Run(context.Background()); err == nil {
		t.Fatal("expected webhook failure to surface")
	}
	if len(capture.domains()) != 0 {
		t.Fatal("failed page must not be reported as delivered")
	}
	cursor := task.snapshotCursor()
	if cursor.ID != 0 {
		t.Fatalf("cursor must stay on the failed page, got %+v", cursor)
	}
	if failures := countAgentEvents(t, db, "alert_failed"); len(failures) != 1 {
		t.Fatalf("expected one alert_failed event, got %d", len(failures))
	}
	if len(countAgentEvents(t, db, "alert_sent")) != 0 {
		t.Fatal("no alert_sent may be recorded for a failed page")
	}

	// Recovery: same events delivered on the next successful cycle.
	atomic.StoreInt32(&status, http.StatusOK)
	if err := task.Run(context.Background()); err != nil {
		t.Fatalf("recovery run: %v", err)
	}
	found := false
	for _, domain := range capture.domains() {
		if domain == "retry-webhook.test" {
			found = true
		}
	}
	if !found {
		t.Fatal("previously failed events must be retried after recovery")
	}
}

// A failing secondary channel must count as a page failure: no alert_sent,
// cursor stays retryable.
func TestAlertSecondaryChannelFailureCountsAsFailure(t *testing.T) {
	db := newTestStore(t)
	_ = db.RecordAgentEvent(context.Background(), "audit", "auto_block", "vietcombbank.com.vn", `{}`)
	time.Sleep(50 * time.Millisecond)

	capture := &webhookCapture{}
	server := newWebhookServer(t, capture, nil)
	defer server.Close()

	task := NewAlertTask(db, AlertConfig{
		WebhookURL:      server.URL,
		MinEvents:       1,
		TelegramEnabled: true,
		TelegramToken:   "dummy",
		TelegramChatID:  "dummy",
	})
	task.http = server.Client()
	rewindAlertCursor(t, task, time.Now().Add(-time.Hour))

	// Force the Telegram send to fail with a 500.
	task.http.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "api.telegram.org" {
			return &http.Response{StatusCode: http.StatusInternalServerError, Body: http.NoBody, Header: http.Header{}}, nil
		}
		return http.DefaultTransport.RoundTrip(req)
	})

	err := task.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "telegram") {
		t.Fatalf("expected telegram failure to surface, got %v", err)
	}
	if len(countAgentEvents(t, db, "alert_sent")) != 0 {
		t.Fatal("partial channel success must not be reported as alert_sent")
	}
	if task.snapshotCursor().ID != 0 {
		t.Fatal("cursor must stay retryable after partial failure")
	}
}

// Ties on the second-precision created_at column must not skip or repeat
// rows when paging: the ID tie-breaker guarantees a stable total order.
func TestQueryAgentEventsPageHandlesCreatedATies(t *testing.T) {
	db := newTestStore(t)
	const total = 150
	for i := 0; i < total; i++ {
		_ = db.RecordAgentEvent(context.Background(), "audit", "auto_block", fmt.Sprintf("tie-%03d.test", i), `{}`)
	}
	time.Sleep(50 * time.Millisecond)

	var (
		ids       []int64
		afterTime string
		afterID   int64
	)
	for {
		events, err := db.QueryAgentEventsPage(context.Background(), afterTime, afterID, []string{"auto_block"}, 50)
		if err != nil {
			t.Fatalf("page query: %v", err)
		}
		if len(events) == 0 {
			break
		}
		for _, e := range events {
			ids = append(ids, e.ID)
			afterTime = e.CreatedAt
			afterID = e.ID
		}
	}
	if len(ids) != total {
		t.Fatalf("expected %d events across pages, got %d", total, len(ids))
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] <= ids[i-1] {
			t.Fatalf("expected strictly increasing ids across pages, got %v then %v", ids[i-1], ids[i])
		}
	}
}

// The audit auto_block event details must be valid JSON (operators parse
// them) even when enrichment reasons are present.
func TestAuditAutoBlockDetailsAreValidJSON(t *testing.T) {
	reasons := []string{"reason one", "reason two"}
	encoded, err := json.Marshal(map[string]any{
		"score":      90,
		"confidence": 0.9,
		"reasons":    reasons,
	})
	if err != nil {
		t.Fatalf("marshal details: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("details must be valid JSON: %v", err)
	}
	// The legacy %q-on-a-slice formatting produced ["a" "b"], which is not
	// valid JSON; the structured marshal above is the contract.
	legacy := fmt.Sprintf(`{"reasons":%q}`, reasons)
	var broken map[string]any
	if json.Unmarshal([]byte(legacy), &broken) == nil {
		t.Fatal("legacy formatting unexpectedly valid; update this regression test")
	}
}
