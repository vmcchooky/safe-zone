package risk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sync/atomic"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
)

const mlClassifierReason = "ml_classifier_high_risk"

var mlLatencyBuckets = [...]int64{100, 250, 500, 1000, 2000, 5000, 10000, 50000}
var mlProbabilityBuckets = [...]string{"lt_0_10", "0_10_0_19", "0_20_0_29", "0_30_0_39", "0_40_0_49", "0_50_0_59", "0_60_0_69", "0_70_0_79", "0_80_0_89", "gte_0_90"}

type mlTelemetry struct {
	predictionAttempts atomic.Int64
	shadowWouldBlock   atomic.Int64
	shadowWouldPass    atomic.Int64
	enforcePromotions  atomic.Int64
	abstains           atomic.Int64
	errors             atomic.Int64
	skips              atomic.Int64
	fallbacks          atomic.Int64
	latencyCount       atomic.Int64
	latencyTotalMicros atomic.Int64
	latencyBuckets     [len(mlLatencyBuckets) + 1]atomic.Int64
	probabilityBuckets [len(mlProbabilityBuckets)]atomic.Int64
	canarySelected     atomic.Int64
	canaryExcluded     atomic.Int64
	canaryWouldBlock   atomic.Int64
	canaryWouldPass    atomic.Int64
	canarySuppressed   atomic.Int64
}

type MLStatus struct {
	Mode                 analysis.MLMode  `json:"ml_mode"`
	Enabled              bool             `json:"ml_enabled"`
	ModelVersion         string           `json:"ml_model_version,omitempty"`
	Revision             string           `json:"ml_revision,omitempty"`
	PolicyRevision       string           `json:"ml_policy_revision,omitempty"`
	BlockThreshold       float64          `json:"ml_block_threshold,omitempty"`
	PredictionAttempts   int64            `json:"prediction_attempts"`
	ShadowWouldBlock     int64            `json:"shadow_would_block"`
	ShadowWouldPass      int64            `json:"shadow_would_pass"`
	EnforcePromotions    int64            `json:"enforce_promotions"`
	Abstains             int64            `json:"abstains"`
	Errors               int64            `json:"errors"`
	Skips                int64            `json:"skips"`
	LLMFallbacks         int64            `json:"llm_fallbacks_after_ml"`
	LatencyP95Micros     int64            `json:"latency_p95_us"`
	LatencyCount         int64            `json:"latency_count"`
	LatencyHistogram     map[string]int64 `json:"latency_histogram_us"`
	ProbabilityHistogram map[string]int64 `json:"probability_histogram"`
	State                string           `json:"ml_state"`
	Canary               MLCanaryStatus   `json:"canary"`
	URL                  URLMLStatus      `json:"url"`
}

func (t *mlTelemetry) observeLatency(duration time.Duration) {
	if t == nil {
		return
	}
	micros := duration.Microseconds()
	t.latencyCount.Add(1)
	t.latencyTotalMicros.Add(micros)
	observeLatencyMicros(t.latencyBuckets[:], micros)
}

// observeLatencyMicros files a latency sample into buckets. The slice must
// have len(mlLatencyBuckets)+1 entries: the trailing slot counts samples above
// the highest boundary, and a reader that ignores it cannot reach its target.
func observeLatencyMicros(buckets []atomic.Int64, micros int64) {
	for i, upper := range mlLatencyBuckets {
		if micros <= upper {
			buckets[i].Add(1)
			return
		}
	}
	buckets[len(mlLatencyBuckets)].Add(1)
}

// probabilityBucketIndex maps a probability to its histogram bucket, or -1
// when the value is not a usable probability.
func probabilityBucketIndex(probability float64) int {
	if math.IsNaN(probability) || math.IsInf(probability, 0) || probability < 0 || probability > 1 {
		return -1
	}
	index := int(probability * 10)
	if index >= len(mlProbabilityBuckets) {
		index = len(mlProbabilityBuckets) - 1
	}
	return index
}

func observeProbabilityMicros(buckets []atomic.Int64, probability float64) {
	if index := probabilityBucketIndex(probability); index >= 0 {
		buckets[index].Add(1)
	}
}

// latencyP95Micros reports the upper bound of the bucket holding the 95th
// percentile. buckets must have len(mlLatencyBuckets)+1 entries.
//
// When the cumulative count still falls short after the last defined boundary,
// the remainder sits in the overflow slot, so the reported value is that
// boundary and is a lower bound. It used to return -1 instead, which was then
// published verbatim as latency_p95_us: a consumer charting p95 could not
// distinguish the sentinel from a measurement, and the case is reached exactly
// when more than 5% of samples are slow.
func latencyP95Micros(buckets []atomic.Int64, total int64) int64 {
	if total <= 0 {
		return 0
	}
	target := (total*95 + 99) / 100
	var cumulative int64
	for i, upper := range mlLatencyBuckets {
		cumulative += buckets[i].Load()
		if cumulative >= target {
			return upper
		}
	}
	return mlLatencyBuckets[len(mlLatencyBuckets)-1]
}

func (t *mlTelemetry) latencyP95() int64 {
	if t == nil {
		return 0
	}
	return latencyP95Micros(t.latencyBuckets[:], t.latencyCount.Load())
}

func (e *MLEngine) MLStatus(ctx context.Context) MLStatus {
	if e == nil {
		return MLStatus{Mode: analysis.MLModeDisabled}
	}
	status := MLStatus{
		Mode:                 e.mlMode,
		Enabled:              e.mlClassifier != nil && e.mlClassifier.Enabled(),
		State:                mlState(e.mlMode, e.mlClassifier != nil && e.mlClassifier.Enabled()),
		PolicyRevision:       e.currentMLPolicyRevision(),
		PredictionAttempts:   e.mlTelemetry.predictionAttempts.Load(),
		ShadowWouldBlock:     e.mlTelemetry.shadowWouldBlock.Load(),
		ShadowWouldPass:      e.mlTelemetry.shadowWouldPass.Load(),
		EnforcePromotions:    e.mlTelemetry.enforcePromotions.Load(),
		Abstains:             e.mlTelemetry.abstains.Load(),
		Errors:               e.mlTelemetry.errors.Load(),
		Skips:                e.mlTelemetry.skips.Load(),
		LLMFallbacks:         e.mlTelemetry.fallbacks.Load(),
		LatencyP95Micros:     e.mlTelemetry.latencyP95(),
		LatencyCount:         e.mlTelemetry.latencyCount.Load(),
		LatencyHistogram:     make(map[string]int64, len(mlLatencyBuckets)+1),
		ProbabilityHistogram: make(map[string]int64, len(mlProbabilityBuckets)),
		Canary: MLCanaryStatus{
			Configured:          e.mlCanary.enabled(),
			Percent:             e.mlCanary.Percent,
			SelectedPredictions: e.mlTelemetry.canarySelected.Load(),
			ExcludedPredictions: e.mlTelemetry.canaryExcluded.Load(),
			SelectedWouldBlock:  e.mlTelemetry.canaryWouldBlock.Load(),
			SelectedWouldPass:   e.mlTelemetry.canaryWouldPass.Load(),
			EnforceSuppressed:   e.mlTelemetry.canarySuppressed.Load(),
		},
		URL: e.URLMLStatus(ctx),
	}
	if status.Canary.Configured {
		status.Canary.Algorithm = mlCanarySelectorAlgorithm
		status.Canary.SelectorRevision = e.mlCanary.revision()
	}
	if metadata, ok := e.mlClassifier.(analysis.ClassifierMetadata); ok {
		status.ModelVersion = metadata.ModelVersion()
		status.BlockThreshold = metadata.BlockThreshold()
	}
	if e.mlClassifier != nil {
		status.Revision = e.mlClassifier.Revision()
	}
	for i, upper := range mlLatencyBuckets {
		status.LatencyHistogram[fmt.Sprintf("le_%dus", upper)] = e.mlTelemetry.latencyBuckets[i].Load()
	}
	status.LatencyHistogram["gt_50000us"] = e.mlTelemetry.latencyBuckets[len(mlLatencyBuckets)].Load()
	for i, name := range mlProbabilityBuckets {
		status.ProbabilityHistogram[name] = e.mlTelemetry.probabilityBuckets[i].Load()
	}
	return status
}

func mlState(mode analysis.MLMode, enabled bool) string {
	if mode == analysis.MLModeDisabled {
		return "disabled"
	}
	if enabled {
		return "ready"
	}
	return "degraded"
}

func (e *MLEngine) currentMLPolicyRevision() string {
	if e == nil || e.mlClassifier == nil || !e.mlClassifier.Enabled() {
		return ""
	}
	material := fmt.Sprintf("model=%s\nmode=%s\ncanary=%s\n", e.mlClassifier.Revision(), e.mlMode, e.mlCanary.revision())
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

func (e *MLEngine) classifyML(ctx context.Context, current analysis.Result) (analysis.Result, bool) {
	if e == nil || e.mlMode == analysis.MLModeDisabled || e.mlClassifier == nil || !e.mlClassifier.Enabled() {
		if e != nil {
			e.mlTelemetry.skips.Add(1)
		}
		return current, false
	}
	if current.Verdict != analysis.VerdictSuspicious {
		e.mlTelemetry.skips.Add(1)
		return current, false
	}

	e.mlTelemetry.predictionAttempts.Add(1)
	started := time.Now()
	decision, err := classifyWithRecovery(e.mlClassifier, current.Domain)
	e.mlTelemetry.observeLatency(time.Since(started))
	if err != nil {
		e.mlTelemetry.errors.Add(1)
		return current, false
	}
	e.mlTelemetry.observeProbability(decision.Probability)
	canaryConfigured := e.mlCanary.enabled()
	canarySelected := canaryConfigured && e.mlCanary.Eligible(current.Domain)
	if canaryConfigured {
		if canarySelected {
			e.mlTelemetry.canarySelected.Add(1)
		} else {
			e.mlTelemetry.canaryExcluded.Add(1)
		}
	}
	switch decision.Action {
	case analysis.MLActionPromoteMalicious:
		if canarySelected {
			e.mlTelemetry.canaryWouldBlock.Add(1)
		}
		if e.mlMode == analysis.MLModeShadow {
			e.mlTelemetry.shadowWouldBlock.Add(1)
			return current, false
		}
		if !canarySelected {
			e.mlTelemetry.canarySuppressed.Add(1)
			return current, false
		}
		e.mlTelemetry.enforcePromotions.Add(1)
		current.Verdict = analysis.VerdictMalicious
		current.Confidence = decision.Probability
		current.Score = int(math.Round(decision.Probability * 100))
		if current.Score < 70 {
			current.Score = 70
		}
		if current.Score > 100 {
			current.Score = 100
		}
		if current.Category != "phishing" && current.Category != "malware" {
			current.Category = "malware"
		}
		current.Reasons = append(current.Reasons, mlClassifierReason)
		if decision.ModelVersion != "" {
			current.Reasons = append(current.Reasons, "ml_classifier_model_version:"+decision.ModelVersion)
		}
		return current, true
	case analysis.MLActionAbstain:
		if canarySelected {
			e.mlTelemetry.canaryWouldPass.Add(1)
		}
		if e.mlMode == analysis.MLModeShadow {
			e.mlTelemetry.shadowWouldPass.Add(1)
		}
		e.mlTelemetry.abstains.Add(1)
		return current, false
	default:
		e.mlTelemetry.errors.Add(1)
		return current, false
	}
}

func (t *mlTelemetry) observeProbability(probability float64) {
	if t == nil {
		return
	}
	observeProbabilityMicros(t.probabilityBuckets[:], probability)
}

func classifyWithRecovery(classifier analysis.DomainClassifier, domain string) (decision analysis.MLDecision, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("ML classifier panic: %v", recovered)
			logjson.Warn("ML classifier prediction failed", correlation.Fields(context.Background(), map[string]any{
				"service":     "risk",
				"error_class": "panic",
			}))
		}
	}()
	return classifier.Classify(domain)
}
