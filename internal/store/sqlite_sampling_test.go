package store

import (
	"context"
	"strconv"
	"testing"
	"time"
)

func TestTelemetryWriteSampling(t *testing.T) {
	db := newTestDB(t)

	// 100%: every entry is persisted (default behavior).
	db.writePercent = 100
	for i := 0; i < 40; i++ {
		db.RecordAnalysis(TelemetryEntry{
			Domain:     "full-" + strconv.Itoa(i) + ".test",
			Verdict:    "SAFE",
			AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
		})
	}
	time.Sleep(200 * time.Millisecond)
	entries, err := db.QueryRecent(context.Background(), 1000, 0)
	if err != nil {
		t.Fatalf("query recent: %v", err)
	}
	if len(entries) != 40 {
		t.Fatalf("writePercent=100: got %d entries, want 40", len(entries))
	}

	// 0%: telemetry writes are fully disabled; no new rows appear.
	db.writePercent = 0
	for i := 0; i < 40; i++ {
		db.RecordAnalysis(TelemetryEntry{
			Domain:     "none-" + strconv.Itoa(i) + ".test",
			Verdict:    "SAFE",
			AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
		})
	}
	time.Sleep(200 * time.Millisecond)
	after, err := db.QueryRecent(context.Background(), 1000, 0)
	if err != nil {
		t.Fatalf("query recent after sampling: %v", err)
	}
	if len(after) != 40 {
		t.Fatalf("writePercent=0: got %d entries, want unchanged 40", len(after))
	}

	// ~10%: roughly one in ten entries lands within a small tolerance.
	db.writePercent = 10
	before := len(after)
	for i := 0; i < 2000; i++ {
		db.RecordAnalysis(TelemetryEntry{
			Domain:     "sample-" + strconv.Itoa(i) + ".test",
			Verdict:    "SAFE",
			AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
		})
	}
	time.Sleep(400 * time.Millisecond)
	afterSample, err := db.QueryRecent(context.Background(), 5000, 0)
	if err != nil {
		t.Fatalf("query recent sampled: %v", err)
	}
	written := len(afterSample) - before
	if written < 100 || written > 300 {
		t.Fatalf("writePercent=10: sampled %d entries, want ~200 (tolerance 100-300)", written)
	}
}
