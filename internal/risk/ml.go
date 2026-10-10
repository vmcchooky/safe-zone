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

func (s *Service) MLStatus() MLStatus {
	if s == nil {
		return MLStatus{Mode: analysis.MLModeDisabled}
	}
	status := MLStatus{
		Mode:                 s.ml.mlMode,
		Enabled:              s.ml.mlClassifier != nil && s.ml.mlClassifier.Enabled(),
		State:                mlState(s.ml.mlMode, s.ml.mlClassifier != nil && s.ml.mlClassifier.Enabled()),
		PolicyRevision:       s.currentMLPolicyRevision(),
		PredictionAttempts:   s.ml.mlTelemetry.predictionAttempts.Load(),
		ShadowWouldBlock:     s.ml.mlTelemetry.shadowWouldBlock.Load(),
		ShadowWouldPass:      s.ml.mlTelemetry.shadowWouldPass.Load(),
		EnforcePromotions:    s.ml.mlTelemetry.enforcePromotions.Load(),
		Abstains:             s.ml.mlTelemetry.abstains.Load(),
		Errors:               s.ml.mlTelemetry.errors.Load(),
		Skips:                s.ml.mlTelemetry.skips.Load(),
		LLMFallbacks:         s.ml.mlTelemetry.fallbacks.Load(),
		LatencyP95Micros:     s.ml.mlTelemetry.latencyP95(),
		LatencyCount:         s.ml.mlTelemetry.latencyCount.Load(),
		LatencyHistogram:     make(map[string]int64, len(mlLatencyBuckets)+1),
		ProbabilityHistogram: make(map[string]int64, len(mlProbabilityBuckets)),
		Canary: MLCanaryStatus{
			Configured:          s.ml.mlCanary.enabled(),
			Percent:             s.ml.mlCanary.Percent,
			SelectedPredictions: s.ml.mlTelemetry.canarySelected.Load(),
			ExcludedPredictions: s.ml.mlTelemetry.canaryExcluded.Load(),
			SelectedWouldBlock:  s.ml.mlTelemetry.canaryWouldBlock.Load(),
			SelectedWouldPass:   s.ml.mlTelemetry.canaryWouldPass.Load(),
			EnforceSuppressed:   s.ml.mlTelemetry.canarySuppressed.Load(),
		},
		URL: s.URLMLStatus(s.lifecycleCtx),
	}
	if status.Canary.Configured {
		status.Canary.Algorithm = mlCanarySelectorAlgorithm
		status.Canary.SelectorRevision = s.ml.mlCanary.revision()
	}
	if metadata, ok := s.ml.mlClassifier.(analysis.ClassifierMetadata); ok {
		status.ModelVersion = metadata.ModelVersion()
		status.BlockThreshold = metadata.BlockThreshold()
	}
	if s.ml.mlClassifier != nil {
		status.Revision = s.ml.mlClassifier.Revision()
	}
	for i, upper := range mlLatencyBuckets {
		status.LatencyHistogram[fmt.Sprintf("le_%dus", upper)] = s.ml.mlTelemetry.latencyBuckets[i].Load()
	}
	status.LatencyHistogram["gt_50000us"] = s.ml.mlTelemetry.latencyBuckets[len(mlLatencyBuckets)].Load()
	for i, name := range mlProbabilityBuckets {
		status.ProbabilityHistogram[name] = s.ml.mlTelemetry.probabilityBuckets[i].Load()
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

func (s *Service) currentMLPolicyRevision() string {
	if s == nil || s.ml.mlClassifier == nil || !s.ml.mlClassifier.Enabled() {
		return ""
	}
	material := fmt.Sprintf("model=%s\nmode=%s\ncanary=%s\n", s.ml.mlClassifier.Revision(), s.ml.mlMode, s.ml.mlCanary.revision())
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

func (s *Service) classifyML(ctx context.Context, current analysis.Result) (analysis.Result, bool) {
	if s == nil || s.ml.mlMode == analysis.MLModeDisabled || s.ml.mlClassifier == nil || !s.ml.mlClassifier.Enabled() {
		if s != nil {
			s.ml.mlTelemetry.skips.Add(1)
		}
		return current, false
	}
	if current.Verdict != analysis.VerdictSuspicious {
		s.ml.mlTelemetry.skips.Add(1)
		return current, false
	}

	s.ml.mlTelemetry.predictionAttempts.Add(1)
	started := time.Now()
	decision, err := classifyWithRecovery(s.ml.mlClassifier, current.Domain)
	s.ml.mlTelemetry.observeLatency(time.Since(started))
	if err != nil {
		s.ml.mlTelemetry.errors.Add(1)
		return current, false
	}
	s.ml.mlTelemetry.observeProbability(decision.Probability)
	canaryConfigured := s.ml.mlCanary.enabled()
	canarySelected := canaryConfigured && s.ml.mlCanary.Eligible(current.Domain)
	if canaryConfigured {
		if canarySelected {
			s.ml.mlTelemetry.canarySelected.Add(1)
		} else {
			s.ml.mlTelemetry.canaryExcluded.Add(1)
		}
	}
	switch decision.Action {
	case analysis.MLActionPromoteMalicious:
		if canarySelected {
			s.ml.mlTelemetry.canaryWouldBlock.Add(1)
		}
		if s.ml.mlMode == analysis.MLModeShadow {
			s.ml.mlTelemetry.shadowWouldBlock.Add(1)
			return current, false
		}
		if !canarySelected {
			s.ml.mlTelemetry.canarySuppressed.Add(1)
			return current, false
		}
		s.ml.mlTelemetry.enforcePromotions.Add(1)
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
			s.ml.mlTelemetry.canaryWouldPass.Add(1)
		}
		if s.ml.mlMode == analysis.MLModeShadow {
			s.ml.mlTelemetry.shadowWouldPass.Add(1)
		}
		s.ml.mlTelemetry.abstains.Add(1)
		return current, false
	default:
		s.ml.mlTelemetry.errors.Add(1)
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
