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
	for i, upper := range mlLatencyBuckets {
		if micros <= upper {
			t.latencyBuckets[i].Add(1)
			return
		}
	}
	t.latencyBuckets[len(mlLatencyBuckets)].Add(1)
}

func (t *mlTelemetry) latencyP95() int64 {
	if t == nil {
		return 0
	}
	total := t.latencyCount.Load()
	if total == 0 {
		return 0
	}
	target := (total*95 + 99) / 100
	var cumulative int64
	for i, upper := range mlLatencyBuckets {
		cumulative += t.latencyBuckets[i].Load()
		if cumulative >= target {
			return upper
		}
	}
	return -1
}

func (s *Service) MLStatus() MLStatus {
	if s == nil {
		return MLStatus{Mode: analysis.MLModeDisabled}
	}
	status := MLStatus{
		Mode:                 s.mlMode,
		Enabled:              s.mlClassifier != nil && s.mlClassifier.Enabled(),
		State:                mlState(s.mlMode, s.mlClassifier != nil && s.mlClassifier.Enabled()),
		PolicyRevision:       s.currentMLPolicyRevision(),
		PredictionAttempts:   s.mlTelemetry.predictionAttempts.Load(),
		ShadowWouldBlock:     s.mlTelemetry.shadowWouldBlock.Load(),
		ShadowWouldPass:      s.mlTelemetry.shadowWouldPass.Load(),
		EnforcePromotions:    s.mlTelemetry.enforcePromotions.Load(),
		Abstains:             s.mlTelemetry.abstains.Load(),
		Errors:               s.mlTelemetry.errors.Load(),
		Skips:                s.mlTelemetry.skips.Load(),
		LLMFallbacks:         s.mlTelemetry.fallbacks.Load(),
		LatencyP95Micros:     s.mlTelemetry.latencyP95(),
		LatencyCount:         s.mlTelemetry.latencyCount.Load(),
		LatencyHistogram:     make(map[string]int64, len(mlLatencyBuckets)+1),
		ProbabilityHistogram: make(map[string]int64, len(mlProbabilityBuckets)),
		Canary: MLCanaryStatus{
			Configured:          s.mlCanary.enabled(),
			Percent:             s.mlCanary.Percent,
			SelectedPredictions: s.mlTelemetry.canarySelected.Load(),
			ExcludedPredictions: s.mlTelemetry.canaryExcluded.Load(),
			SelectedWouldBlock:  s.mlTelemetry.canaryWouldBlock.Load(),
			SelectedWouldPass:   s.mlTelemetry.canaryWouldPass.Load(),
			EnforceSuppressed:   s.mlTelemetry.canarySuppressed.Load(),
		},
		URL: s.URLMLStatus(),
	}
	if status.Canary.Configured {
		status.Canary.Algorithm = mlCanarySelectorAlgorithm
		status.Canary.SelectorRevision = s.mlCanary.revision()
	}
	if metadata, ok := s.mlClassifier.(analysis.ClassifierMetadata); ok {
		status.ModelVersion = metadata.ModelVersion()
		status.BlockThreshold = metadata.BlockThreshold()
	}
	if s.mlClassifier != nil {
		status.Revision = s.mlClassifier.Revision()
	}
	for i, upper := range mlLatencyBuckets {
		status.LatencyHistogram[fmt.Sprintf("le_%dus", upper)] = s.mlTelemetry.latencyBuckets[i].Load()
	}
	status.LatencyHistogram["gt_50000us"] = s.mlTelemetry.latencyBuckets[len(mlLatencyBuckets)].Load()
	for i, name := range mlProbabilityBuckets {
		status.ProbabilityHistogram[name] = s.mlTelemetry.probabilityBuckets[i].Load()
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
	if s == nil || s.mlClassifier == nil || !s.mlClassifier.Enabled() {
		return ""
	}
	material := fmt.Sprintf("model=%s\nmode=%s\ncanary=%s\n", s.mlClassifier.Revision(), s.mlMode, s.mlCanary.revision())
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

func (s *Service) classifyML(ctx context.Context, current analysis.Result) (analysis.Result, bool) {
	if s == nil || s.mlMode == analysis.MLModeDisabled || s.mlClassifier == nil || !s.mlClassifier.Enabled() {
		if s != nil {
			s.mlTelemetry.skips.Add(1)
		}
		return current, false
	}
	if current.Verdict != analysis.VerdictSuspicious {
		s.mlTelemetry.skips.Add(1)
		return current, false
	}

	s.mlTelemetry.predictionAttempts.Add(1)
	started := time.Now()
	decision, err := classifyWithRecovery(s.mlClassifier, current.Domain)
	s.mlTelemetry.observeLatency(time.Since(started))
	if err != nil {
		s.mlTelemetry.errors.Add(1)
		return current, false
	}
	s.mlTelemetry.observeProbability(decision.Probability)
	canaryConfigured := s.mlCanary.enabled()
	canarySelected := canaryConfigured && s.mlCanary.Eligible(current.Domain)
	if canaryConfigured {
		if canarySelected {
			s.mlTelemetry.canarySelected.Add(1)
		} else {
			s.mlTelemetry.canaryExcluded.Add(1)
		}
	}
	switch decision.Action {
	case analysis.MLActionPromoteMalicious:
		if canarySelected {
			s.mlTelemetry.canaryWouldBlock.Add(1)
		}
		if s.mlMode == analysis.MLModeShadow {
			s.mlTelemetry.shadowWouldBlock.Add(1)
			return current, false
		}
		if !canarySelected {
			s.mlTelemetry.canarySuppressed.Add(1)
			return current, false
		}
		s.mlTelemetry.enforcePromotions.Add(1)
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
			s.mlTelemetry.canaryWouldPass.Add(1)
		}
		if s.mlMode == analysis.MLModeShadow {
			s.mlTelemetry.shadowWouldPass.Add(1)
		}
		s.mlTelemetry.abstains.Add(1)
		return current, false
	default:
		s.mlTelemetry.errors.Add(1)
		return current, false
	}
}

func (t *mlTelemetry) observeProbability(probability float64) {
	if t == nil || math.IsNaN(probability) || math.IsInf(probability, 0) || probability < 0 || probability > 1 {
		return
	}
	index := int(probability * 10)
	if index >= len(mlProbabilityBuckets) {
		index = len(mlProbabilityBuckets) - 1
	}
	t.probabilityBuckets[index].Add(1)
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
