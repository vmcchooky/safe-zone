package risk

import (
	"encoding/json"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"safe-zone/internal/config"
)

// A reference bucket with a zero count is legal — url_baseline.go rejects only
// negative counts — but using it unsmoothed made log(liveShare/0) evaluate to
// +Inf, so the PSI became +Inf for every live sample set rather than only
// under drift. +Inf is not representable in JSON, so the whole /v1/status
// payload failed to encode.
func TestDriftPSISStaysFiniteWithAnEmptyReferenceBucket(t *testing.T) {
	distribution := make([]float64, len(mlProbabilityBuckets))
	distribution[0] = 1.0 // every other reference bucket stays at zero

	s := newDriftTestService(t, distribution, 100)
	s.ml.urlMLTelemetry.probabilityBuckets[0].Add(10)

	status := s.urlMLDriftStatus()
	psi := status.PopulationStabilityIndex
	if math.IsNaN(psi) || math.IsInf(psi, 0) {
		t.Fatalf("psi = %v, want a finite value", psi)
	}
	if _, err := json.Marshal(status); err != nil {
		t.Fatalf("drift status must be JSON-encodable: %v", err)
	}
}

// Identical live and reference distributions must score zero. The 0.1/0.25
// thresholds only mean anything if "nothing changed" lands at 0.
//
// The reference is a normalized distribution while the live side is raw bucket
// counts, so smoothing the reference with the same absolute constant distorts
// it: +0.5 across ten buckets is a rounding error against ~1000 live samples
// but several times the reference's whole mass. An intermediate fix that
// smoothed the reference without rescaling it scored 1.3 for identical
// distributions, and a "large shift" scored 0.05 — the comparison was
// inverted, and the alert state meant nothing.
func TestDriftPSIScoresZeroForIdenticalDistributions(t *testing.T) {
	raw := []int64{520, 210, 120, 80, 45, 25, 14, 8, 5, 3}
	var total int64
	distribution := make([]float64, len(mlProbabilityBuckets))
	for index, count := range raw {
		distribution[index] = float64(count)
		total += count
	}
	for index := range distribution {
		distribution[index] /= float64(total)
	}

	s := newDriftTestService(t, distribution, int(total))
	for index, count := range raw {
		s.ml.urlMLTelemetry.probabilityBuckets[index].Add(count)
	}

	status := s.urlMLDriftStatus()
	if got := status.PopulationStabilityIndex; got != 0 {
		t.Fatalf("psi = %v for an identical distribution, want 0", got)
	}
	if status.State != "stable" {
		t.Fatalf("state = %q, want stable", status.State)
	}
}

// Sampling noise must stay under the watch threshold, and a real shift must
// clear the alert threshold. Without this the thresholds are uncalibrated
// constants that nothing verifies.
func TestDriftPSISeparatesNoiseFromRealShift(t *testing.T) {
	raw := []int64{520, 210, 120, 80, 45, 25, 14, 8, 5, 3}
	var total int64
	distribution := make([]float64, len(mlProbabilityBuckets))
	for index, count := range raw {
		distribution[index] = float64(count)
		total += count
	}
	for index := range distribution {
		distribution[index] /= float64(total)
	}

	// A modest rounding of the same shape: noise, not drift.
	noisy := []int64{500, 200, 130, 80, 50, 20, 10, 5, 3, 2}
	noisyTotal := int64(0)
	for _, count := range noisy {
		noisyTotal += count
	}
	noiseService := newDriftTestService(t, distribution, int(total))
	for index, count := range noisy {
		noiseService.ml.urlMLTelemetry.probabilityBuckets[index].Add(count)
	}
	noise := noiseService.urlMLDriftStatus()
	if noise.PopulationStabilityIndex >= noise.WatchThreshold {
		t.Fatalf("sampling noise scored %v, which is at or above the watch threshold %v",
			noise.PopulationStabilityIndex, noise.WatchThreshold)
	}
	if noise.State != "stable" {
		t.Fatalf("sampling noise state = %q, want stable", noise.State)
	}
	_ = noisyTotal

	// A genuinely different distribution must alert.
	shiftService := newDriftTestService(t, distribution, int(total))
	shiftService.ml.urlMLTelemetry.probabilityBuckets[0].Add(100)
	shiftService.ml.urlMLTelemetry.probabilityBuckets[9].Add(900)
	shift := shiftService.urlMLDriftStatus()
	if shift.PopulationStabilityIndex <= shift.AlertThreshold {
		t.Fatalf("a real shift scored %v, want above the alert threshold %v",
			shift.PopulationStabilityIndex, shift.AlertThreshold)
	}
	if shift.State != "alert" {
		t.Fatalf("a real shift reported state %q, want alert", shift.State)
	}
}

// A reference with no recorded row count cannot be placed on the same scale as
// the live counts, so it must yield no PSI rather than a fabricated one.
func TestDriftPSIIsSkippedWithoutAReferenceRowCount(t *testing.T) {
	distribution := make([]float64, len(mlProbabilityBuckets))
	distribution[0] = 1.0

	s := newDriftTestService(t, distribution, 0)
	s.ml.urlMLTelemetry.probabilityBuckets[0].Add(10)

	status := s.urlMLDriftStatus()
	if status.PopulationStabilityIndex != 0 {
		t.Fatalf("psi = %v without a reference row count, want 0", status.PopulationStabilityIndex)
	}
	if status.State != "insufficient_data" && status.State != "unavailable" && status.State != "stable" {
		t.Fatalf("unexpected state %q", status.State)
	}
}

func newDriftTestService(t *testing.T, distribution []float64, referenceRows int) *Service {
	t.Helper()
	bucketNames := make([]string, len(mlProbabilityBuckets))
	copy(bucketNames, mlProbabilityBuckets[:])
	return &Service{
		ml: &MLEngine{
			urlMLOpsBaseline: &URLOperationalBaseline{
				ReferenceKind:      "frozen_operational_shadow_traffic",
				ReferenceRows:      referenceRows,
				BucketNames:        bucketNames,
				Distribution:       distribution,
				MinimumLiveSamples: 1,
				WatchThreshold:     0.1,
				AlertThreshold:     0.25,
			},
		},
	}
}

// The whole reason the failure was invisible: a non-finite number anywhere in
// the status payload broke encoding. This asserts the end-to-end property for
// the status struct, not just the PSI field.
func TestURLMLStatusIsAlwaysJSONEncodable(t *testing.T) {
	s := NewService(Options{AnalysisConfig: config.DefaultAnalysisConfig()})
	t.Cleanup(func() { _ = s.Close() })

	// Drive the p95 into the overflow bucket, which used to yield -1.
	for range 10 {
		s.ml.urlMLTelemetry.observeLatency(200 * time.Millisecond)
	}
	if _, err := json.Marshal(s.URLMLStatus(t.Context())); err != nil {
		t.Fatalf("URLMLStatus must encode: %v", err)
	}
}

// latencyP95 used to ignore the overflow bucket entirely, so once more than
// 5% of samples exceeded the highest boundary the cumulative count could never
// reach the target and the function returned -1, which was then published
// verbatim as latency_p95_us.
func TestLatencyP95AccountsForTheOverflowBucket(t *testing.T) {
	var buckets [len(mlLatencyBuckets) + 1]atomic.Int64

	// 10 fast samples, 100 samples above the highest boundary (50 ms). The
	// 95th percentile falls inside the overflow region.
	for range 10 {
		observeLatencyMicros(buckets[:], 100)
	}
	for range 100 {
		observeLatencyMicros(buckets[:], 5_000_000)
	}

	got := latencyP95Micros(buckets[:], 110)
	if got < 0 {
		t.Fatalf("latency p95 = %d, want a non-negative measurement", got)
	}
	if got != mlLatencyBuckets[len(mlLatencyBuckets)-1] {
		t.Fatalf("latency p95 = %d, want the highest boundary %d as a lower bound", got, mlLatencyBuckets[len(mlLatencyBuckets)-1])
	}
}

func TestLatencyP95ReturnsZeroWithNoSamples(t *testing.T) {
	var buckets [len(mlLatencyBuckets) + 1]atomic.Int64
	if got := latencyP95Micros(buckets[:], 0); got != 0 {
		t.Fatalf("latency p95 with no samples = %d, want 0", got)
	}
}

func TestLatencyP95PicksTheRightBucket(t *testing.T) {
	var buckets [len(mlLatencyBuckets) + 1]atomic.Int64
	// 100 samples, 96 of them at 300us (the <=500 bucket, index 2).
	for range 96 {
		observeLatencyMicros(buckets[:], 300)
	}
	for range 4 {
		observeLatencyMicros(buckets[:], 9_000)
	}

	if got, want := latencyP95Micros(buckets[:], 100), int64(500); got != want {
		t.Fatalf("latency p95 = %d, want %d", got, want)
	}
}

// The two telemetry types each had their own byte-identical copy of this
// function. If they drift again, a caller comparing domain-ML and URL-ML
// latency percentiles would be comparing different definitions.
func TestBothTelemetryTypesShareLatencyAccounting(t *testing.T) {
	domain := &mlTelemetry{}
	url := &urlMLTelemetry{}
	for range 20 {
		domain.observeLatency(1200 * time.Microsecond)
		url.observeLatency(1200 * time.Microsecond)
	}
	if domain.latencyP95() != url.latencyP95() {
		t.Fatalf("domain p95 = %d, url p95 = %d, want equal", domain.latencyP95(), url.latencyP95())
	}
}

func TestProbabilityBucketIndexRejectsUnusableValues(t *testing.T) {
	for _, bad := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -0.1, 1.1} {
		if index := probabilityBucketIndex(bad); index >= 0 {
			t.Fatalf("probabilityBucketIndex(%v) = %d, want -1", bad, index)
		}
	}
	if index := probabilityBucketIndex(0.95); index != 9 {
		t.Fatalf("probabilityBucketIndex(0.95) = %d, want 9", index)
	}
	if index := probabilityBucketIndex(1.0); index != 9 {
		t.Fatalf("probabilityBucketIndex(1.0) = %d, want 9 (clamped)", index)
	}
}
