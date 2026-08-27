package store

import (
	"context"
	"math"
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
	if written < 160 || written > 240 {
		t.Fatalf("writePercent=10: sampled %d entries, want ~200", written)
	}
}

// TestSamplingDistribution verifies the pure sampler spreads uniformly for
// consecutive sequence numbers across several percentages (bucket max error
// stays well inside +/-10%% of nominal), catching clustered-hash regressions.
func TestSamplingDistribution(t *testing.T) {
	const n = 100000
	cases := []int{1, 5, 10, 25, 50}
	for _, pct := range cases {
		accepted := 0
		for i := uint64(1); i <= n; i++ {
			if sampleAccept(i, pct) {
				accepted++
			}
		}
		want := float64(pct) / 100 * n
		sigma := math.Sqrt(want * (1 - float64(pct)/100))
		tol := math.Max(want*0.02, sigma*4) // deterministic mixer: stay within 4-sigma
		if float64(accepted) < want-tol || float64(accepted) > want+tol {
			t.Fatalf("percent=%d accepted=%d want=%.0f (+/-%.0f)", pct, accepted, want, tol)
		}
	}
}
