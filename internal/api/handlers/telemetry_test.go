package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"safe-zone/internal/store"
)

func TestTelemetryRecentHandlerCapsLimit(t *testing.T) {
	ts := newHandlerTestServer(t)

	now := time.Now().UTC()
	for i := 0; i < 110; i++ {
		ts.Store.RecordAnalysis(store.TelemetryEntry{
			Domain:     "domain-" + time.Unix(0, int64(i)).UTC().Format("150405.000000000") + ".test",
			Verdict:    "SAFE",
			Score:      5,
			Confidence: 0.9,
			Reasons:    []string{"test"},
			Source:     "lexical",
			AnalyzedAt: now.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano),
		})
	}

	waitForTelemetryEntries(t, ts.Store, 110)

	req, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/telemetry/recent?limit=200", nil)
	if err != nil {
		t.Fatal(err)
	}
	ts.addAdminBearer(req)

	resp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var payload struct {
		Items []store.TelemetryEntry `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Items) != 100 {
		t.Fatalf("expected limit to be capped at 100, got %d items", len(payload.Items))
	}
}

func waitForTelemetryEntries(t *testing.T, db *store.DB, want int) {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for {
		entries, err := db.QueryRecent(context.Background(), want, 0)
		if err == nil && len(entries) >= want {
			return
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("telemetry entries not flushed in time: %v", err)
			}
			t.Fatalf("telemetry entries not flushed in time: got %d want at least %d", len(entries), want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
