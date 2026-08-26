package risk

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"sync/atomic"
	"time"

	"safe-zone/internal/analysis"
)

type URLAnalysisContext struct {
	RequestedURL  string
	RedirectChain []string
}

type URLMLObservation struct {
	Mode          analysis.MLMode `json:"mode"`
	Sampled       bool            `json:"sampled"`
	Evaluated     bool            `json:"evaluated"`
	WouldPromote  bool            `json:"would_promote"`
	Probability   float64         `json:"probability,omitempty"`
	Action        string          `json:"action,omitempty"`
	ModelVersion  string          `json:"model_version,omitempty"`
	Revision      string          `json:"revision,omitempty"`
	ErrorClass    string          `json:"error_class,omitempty"`
	LatencyMicros int64           `json:"latency_us,omitempty"`
}

type URLMLShadowConfig struct {
	Percent int
	Seed    string
}

type URLMLSamplingStatus struct {
	Percent          int    `json:"percent"`
	Algorithm        string `json:"algorithm"`
	SelectorRevision string `json:"selector_revision"`
	Selected         int64  `json:"selected"`
	Excluded         int64  `json:"excluded"`
}

type URLMLDriftStatus struct {
	State                    string  `json:"state"`
	PopulationStabilityIndex float64 `json:"psi"`
	LiveSamples              int64   `json:"live_samples"`
	MinimumLiveSamples       int     `json:"minimum_live_samples"`
	ReferenceKind            string  `json:"reference_kind,omitempty"`
	ReferenceRows            int     `json:"reference_rows,omitempty"`
	OperationalReference     bool    `json:"operational_reference"`
	WatchThreshold           float64 `json:"watch_threshold,omitempty"`
	AlertThreshold           float64 `json:"alert_threshold,omitempty"`
	Interpretation           string  `json:"interpretation,omitempty"`
}

type URLMLStatus struct {
	Mode                  analysis.MLMode     `json:"mode"`
	Enabled               bool                `json:"enabled"`
	State                 string              `json:"state"`
	ModelVersion          string              `json:"model_version,omitempty"`
	Revision              string              `json:"revision,omitempty"`
	PolicyRevision        string              `json:"policy_revision,omitempty"`
	URLThreshold          float64             `json:"url_threshold,omitempty"`
	ContextRequests       int64               `json:"context_requests"`
	PredictionAttempts    int64               `json:"prediction_attempts"`
	WouldPromote          int64               `json:"would_promote"`
	WouldPass             int64               `json:"would_pass"`
	Errors                int64               `json:"errors"`
	Skips                 int64               `json:"skips"`
	LatencyP95Micros      int64               `json:"latency_p95_us"`
	LatencyCount          int64               `json:"latency_count"`
	LatencyAverageMicros  int64               `json:"latency_average_us"`
	LatencyHistogram      map[string]int64    `json:"latency_histogram_us"`
	ProbabilityHistogram  map[string]int64    `json:"probability_histogram"`
	ErrorHistogram        map[string]int64    `json:"error_histogram"`
	InputHistogram        map[string]int64    `json:"input_histogram"`
	VerdictHistogram      map[string]int64    `json:"primary_verdict_histogram"`
	WouldPromoteByVerdict map[string]int64    `json:"would_promote_by_primary_verdict"`
	Sampling              URLMLSamplingStatus `json:"sampling"`
	Drift                 URLMLDriftStatus    `json:"drift"`
}

type urlMLTelemetry struct {
	contextRequests       atomic.Int64
	predictionAttempts    atomic.Int64
	wouldPromote          atomic.Int64
	wouldPass             atomic.Int64
	errors                atomic.Int64
	skips                 atomic.Int64
	latencyCount          atomic.Int64
	latencyTotalMicros    atomic.Int64
	latencyBuckets        [len(mlLatencyBuckets) + 1]atomic.Int64
	probabilityBuckets    [len(mlProbabilityBuckets)]atomic.Int64
	selected              atomic.Int64
	excluded              atomic.Int64
	invalidContext        atomic.Int64
	predictionErrors      atomic.Int64
	queryPresent          atomic.Int64
	queryAbsent           atomic.Int64
	redirectBuckets       [3]atomic.Int64
	verdictBuckets        [3]atomic.Int64
	promoteVerdictBuckets [3]atomic.Int64
}

const urlMLSelectorAlgorithm = "sha256-domain-v1"

func (c URLMLShadowConfig) validate() error {
	if c.Percent < 1 || c.Percent > 100 {
		return fmt.Errorf("URL ML shadow percent must be between 1 and 100")
	}
	if c.Percent < 100 && strings.TrimSpace(c.Seed) == "" {
		return fmt.Errorf("URL ML shadow seed is required below 100 percent")
	}
	return nil
}

func (c URLMLShadowConfig) eligible(domain string) bool {
	if c.Percent >= 100 {
		return true
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(c.Seed) + "\x00" + strings.ToLower(strings.TrimSpace(domain))))
	return int(binary.BigEndian.Uint64(sum[:8])%100) < c.Percent
}

func (c URLMLShadowConfig) revision() string {
	material := fmt.Sprintf("algorithm=%s\npercent=%d\nseed=%s\n", urlMLSelectorAlgorithm, c.Percent, strings.TrimSpace(c.Seed))
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

func (t *urlMLTelemetry) observeLatency(duration time.Duration) {
	if t == nil {
		return
	}
	micros := duration.Microseconds()
	t.latencyCount.Add(1)
	t.latencyTotalMicros.Add(micros)
	for index, upper := range mlLatencyBuckets {
		if micros <= upper {
			t.latencyBuckets[index].Add(1)
			return
		}
	}
	t.latencyBuckets[len(mlLatencyBuckets)].Add(1)
}

func (t *urlMLTelemetry) observeProbability(probability float64) {
	if t == nil || math.IsNaN(probability) || math.IsInf(probability, 0) || probability < 0 || probability > 1 {
		return
	}
	index := int(probability * 10)
	if index >= len(mlProbabilityBuckets) {
		index = len(mlProbabilityBuckets) - 1
	}
	t.probabilityBuckets[index].Add(1)
}

func urlMLVerdictIndex(verdict analysis.Verdict) int {
	switch verdict {
	case analysis.VerdictSafe:
		return 0
	case analysis.VerdictSuspicious:
		return 1
	default:
		return 2
	}
}

func (s *Service) urlMLDriftStatus() URLMLDriftStatus {
	status := URLMLDriftStatus{State: "unavailable"}
	provider, ok := s.urlMLClassifier.(analysis.URLMonitoringReferenceProvider)
	if !ok {
		return status
	}
	reference := provider.URLMonitoringReference()
	status.ReferenceKind = reference.ReferenceKind
	status.ReferenceRows = reference.ReferenceRows
	status.OperationalReference = reference.Operational
	status.MinimumLiveSamples = reference.MinimumLiveSamples
	status.WatchThreshold = reference.PSIWatchThreshold
	status.AlertThreshold = reference.PSIAlertThreshold
	status.Interpretation = "population shift only; calibration requires labels"
	if len(reference.ProbabilityDistribution) != len(mlProbabilityBuckets) || len(reference.ProbabilityBuckets) != len(mlProbabilityBuckets) {
		return status
	}
	for index, name := range mlProbabilityBuckets {
		if reference.ProbabilityBuckets[index] != name {
			return status
		}
	}
	live := make([]float64, len(mlProbabilityBuckets))
	var total int64
	for index := range live {
		count := s.urlMLTelemetry.probabilityBuckets[index].Load()
		live[index] = float64(count)
		total += count
	}
	status.LiveSamples = total
	if total < int64(reference.MinimumLiveSamples) {
		status.State = "insufficient_data"
		return status
	}
	denominator := float64(total) + 0.5*float64(len(live))
	psi := 0.0
	for index, count := range live {
		liveShare := (count + 0.5) / denominator
		referenceShare := reference.ProbabilityDistribution[index]
		psi += (liveShare - referenceShare) * math.Log(liveShare/referenceShare)
	}
	status.PopulationStabilityIndex = psi
	if !reference.Operational {
		status.State = "proxy_shift"
		status.Interpretation = "diagnostic shift against a balanced offline proxy; non-blocking until a representative live baseline is frozen"
		return status
	}
	switch {
	case psi >= reference.PSIAlertThreshold:
		status.State = "alert"
	case psi >= reference.PSIWatchThreshold:
		status.State = "watch"
	default:
		status.State = "stable"
	}
	return status
}

func (t *urlMLTelemetry) latencyP95() int64 {
	if t == nil {
		return 0
	}
	total := t.latencyCount.Load()
	if total == 0 {
		return 0
	}
	target := (total*95 + 99) / 100
	var cumulative int64
	for index, upper := range mlLatencyBuckets {
		cumulative += t.latencyBuckets[index].Load()
		if cumulative >= target {
			return upper
		}
	}
	return -1
}

func (s *Service) URLMLStatus() URLMLStatus {
	if s == nil {
		return URLMLStatus{Mode: analysis.MLModeDisabled, State: "disabled"}
	}
	enabled := s.urlMLClassifier != nil && s.urlMLClassifier.Enabled()
	status := URLMLStatus{
		Mode:                 s.urlMLMode,
		Enabled:              enabled,
		State:                mlState(s.urlMLMode, enabled),
		PolicyRevision:       s.currentURLMLPolicyRevision(),
		ContextRequests:      s.urlMLTelemetry.contextRequests.Load(),
		PredictionAttempts:   s.urlMLTelemetry.predictionAttempts.Load(),
		WouldPromote:         s.urlMLTelemetry.wouldPromote.Load(),
		WouldPass:            s.urlMLTelemetry.wouldPass.Load(),
		Errors:               s.urlMLTelemetry.errors.Load(),
		Skips:                s.urlMLTelemetry.skips.Load(),
		LatencyP95Micros:     s.urlMLTelemetry.latencyP95(),
		LatencyCount:         s.urlMLTelemetry.latencyCount.Load(),
		LatencyHistogram:     make(map[string]int64, len(mlLatencyBuckets)+1),
		ProbabilityHistogram: make(map[string]int64, len(mlProbabilityBuckets)),
		ErrorHistogram: map[string]int64{
			"invalid_url_context": s.urlMLTelemetry.invalidContext.Load(),
			"prediction_error":    s.urlMLTelemetry.predictionErrors.Load(),
		},
		InputHistogram: map[string]int64{
			"query_present":    s.urlMLTelemetry.queryPresent.Load(),
			"query_absent":     s.urlMLTelemetry.queryAbsent.Load(),
			"redirects_0":      s.urlMLTelemetry.redirectBuckets[0].Load(),
			"redirects_1":      s.urlMLTelemetry.redirectBuckets[1].Load(),
			"redirects_2_to_5": s.urlMLTelemetry.redirectBuckets[2].Load(),
		},
		VerdictHistogram: map[string]int64{
			"safe":       s.urlMLTelemetry.verdictBuckets[0].Load(),
			"suspicious": s.urlMLTelemetry.verdictBuckets[1].Load(),
			"malicious":  s.urlMLTelemetry.verdictBuckets[2].Load(),
		},
		WouldPromoteByVerdict: map[string]int64{
			"safe":       s.urlMLTelemetry.promoteVerdictBuckets[0].Load(),
			"suspicious": s.urlMLTelemetry.promoteVerdictBuckets[1].Load(),
			"malicious":  s.urlMLTelemetry.promoteVerdictBuckets[2].Load(),
		},
		Sampling: URLMLSamplingStatus{
			Percent:          s.urlMLShadow.Percent,
			Algorithm:        urlMLSelectorAlgorithm,
			SelectorRevision: s.urlMLShadow.revision(),
			Selected:         s.urlMLTelemetry.selected.Load(),
			Excluded:         s.urlMLTelemetry.excluded.Load(),
		},
		Drift: s.urlMLDriftStatus(),
	}
	if status.LatencyCount > 0 {
		status.LatencyAverageMicros = s.urlMLTelemetry.latencyTotalMicros.Load() / status.LatencyCount
	}
	if enabled {
		status.Revision = s.urlMLClassifier.Revision()
	}
	if metadata, ok := s.urlMLClassifier.(analysis.URLClassifierMetadata); ok {
		status.ModelVersion = metadata.ModelVersion()
		status.URLThreshold = metadata.URLThreshold()
	}
	for index, upper := range mlLatencyBuckets {
		status.LatencyHistogram[fmt.Sprintf("le_%dus", upper)] = s.urlMLTelemetry.latencyBuckets[index].Load()
	}
	status.LatencyHistogram["gt_50000us"] = s.urlMLTelemetry.latencyBuckets[len(mlLatencyBuckets)].Load()
	for index, name := range mlProbabilityBuckets {
		status.ProbabilityHistogram[name] = s.urlMLTelemetry.probabilityBuckets[index].Load()
	}
	return status
}

func (s *Service) currentURLMLPolicyRevision() string {
	if s == nil || s.urlMLClassifier == nil || !s.urlMLClassifier.Enabled() {
		return ""
	}
	material := "model=" + s.urlMLClassifier.Revision() + "\nmode=" + string(s.urlMLMode) + "\nsampling=" + s.urlMLShadow.revision() + "\n"
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

func (s *Service) observeURLML(domain string, primaryVerdict analysis.Verdict, context URLAnalysisContext) *URLMLObservation {
	if s == nil {
		return &URLMLObservation{Mode: analysis.MLModeDisabled}
	}
	observation := &URLMLObservation{Mode: s.urlMLMode}
	s.urlMLTelemetry.contextRequests.Add(1)
	if s.urlMLMode != analysis.MLModeShadow || s.urlMLClassifier == nil || !s.urlMLClassifier.Enabled() {
		if s != nil {
			s.urlMLTelemetry.skips.Add(1)
		}
		return observation
	}
	if !s.urlMLShadow.eligible(domain) {
		s.urlMLTelemetry.excluded.Add(1)
		return observation
	}
	observation.Sampled = true
	s.urlMLTelemetry.selected.Add(1)
	s.urlMLTelemetry.predictionAttempts.Add(1)
	if strings.Contains(context.RequestedURL, "?") {
		s.urlMLTelemetry.queryPresent.Add(1)
	} else {
		s.urlMLTelemetry.queryAbsent.Add(1)
	}
	redirectIndex := len(context.RedirectChain)
	if redirectIndex > 2 {
		redirectIndex = 2
	}
	s.urlMLTelemetry.redirectBuckets[redirectIndex].Add(1)
	verdictIndex := urlMLVerdictIndex(primaryVerdict)
	s.urlMLTelemetry.verdictBuckets[verdictIndex].Add(1)
	started := time.Now()
	decision, err := s.urlMLClassifier.ClassifyURL(analysis.URLContext{
		RequestedURL:  context.RequestedURL,
		ExpectedHost:  domain,
		RedirectChain: append([]string(nil), context.RedirectChain...),
	})
	latency := time.Since(started)
	s.urlMLTelemetry.observeLatency(latency)
	observation.LatencyMicros = latency.Microseconds()
	if err != nil {
		s.urlMLTelemetry.errors.Add(1)
		observation.ErrorClass = classifyURLMLError(err)
		if observation.ErrorClass == "invalid_url_context" {
			s.urlMLTelemetry.invalidContext.Add(1)
		} else {
			s.urlMLTelemetry.predictionErrors.Add(1)
		}
		return observation
	}
	observation.Evaluated = true
	observation.Probability = decision.Probability
	observation.Action = decision.Action
	observation.ModelVersion = decision.ModelVersion
	observation.Revision = decision.Revision
	s.urlMLTelemetry.observeProbability(decision.Probability)
	if decision.Action == analysis.MLActionPromoteMalicious {
		observation.WouldPromote = true
		s.urlMLTelemetry.wouldPromote.Add(1)
		s.urlMLTelemetry.promoteVerdictBuckets[verdictIndex].Add(1)
	} else {
		s.urlMLTelemetry.wouldPass.Add(1)
	}
	return observation
}

func classifyURLMLError(err error) string {
	if err == nil {
		return ""
	}
	if strings.Contains(err.Error(), "invalid_url_context") {
		return "invalid_url_context"
	}
	return "prediction_error"
}
