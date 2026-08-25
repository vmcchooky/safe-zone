package risk

import (
	"crypto/sha256"
	"encoding/hex"
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
	Evaluated     bool            `json:"evaluated"`
	WouldPromote  bool            `json:"would_promote"`
	Probability   float64         `json:"probability,omitempty"`
	Action        string          `json:"action,omitempty"`
	ModelVersion  string          `json:"model_version,omitempty"`
	Revision      string          `json:"revision,omitempty"`
	ErrorClass    string          `json:"error_class,omitempty"`
	LatencyMicros int64           `json:"latency_us,omitempty"`
}

type URLMLStatus struct {
	Mode               analysis.MLMode `json:"mode"`
	Enabled            bool            `json:"enabled"`
	State              string          `json:"state"`
	ModelVersion       string          `json:"model_version,omitempty"`
	Revision           string          `json:"revision,omitempty"`
	PolicyRevision     string          `json:"policy_revision,omitempty"`
	URLThreshold       float64         `json:"url_threshold,omitempty"`
	PredictionAttempts int64           `json:"prediction_attempts"`
	WouldPromote       int64           `json:"would_promote"`
	WouldPass          int64           `json:"would_pass"`
	Errors             int64           `json:"errors"`
	Skips              int64           `json:"skips"`
	LatencyP95Micros   int64           `json:"latency_p95_us"`
}

type urlMLTelemetry struct {
	predictionAttempts atomic.Int64
	wouldPromote       atomic.Int64
	wouldPass          atomic.Int64
	errors             atomic.Int64
	skips              atomic.Int64
	latencyCount       atomic.Int64
	latencyBuckets     [len(mlLatencyBuckets) + 1]atomic.Int64
}

func (t *urlMLTelemetry) observeLatency(duration time.Duration) {
	if t == nil {
		return
	}
	micros := duration.Microseconds()
	t.latencyCount.Add(1)
	for index, upper := range mlLatencyBuckets {
		if micros <= upper {
			t.latencyBuckets[index].Add(1)
			return
		}
	}
	t.latencyBuckets[len(mlLatencyBuckets)].Add(1)
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
		Mode:               s.urlMLMode,
		Enabled:            enabled,
		State:              mlState(s.urlMLMode, enabled),
		PolicyRevision:     s.currentURLMLPolicyRevision(),
		PredictionAttempts: s.urlMLTelemetry.predictionAttempts.Load(),
		WouldPromote:       s.urlMLTelemetry.wouldPromote.Load(),
		WouldPass:          s.urlMLTelemetry.wouldPass.Load(),
		Errors:             s.urlMLTelemetry.errors.Load(),
		Skips:              s.urlMLTelemetry.skips.Load(),
		LatencyP95Micros:   s.urlMLTelemetry.latencyP95(),
	}
	if enabled {
		status.Revision = s.urlMLClassifier.Revision()
	}
	if metadata, ok := s.urlMLClassifier.(analysis.URLClassifierMetadata); ok {
		status.ModelVersion = metadata.ModelVersion()
		status.URLThreshold = metadata.URLThreshold()
	}
	return status
}

func (s *Service) currentURLMLPolicyRevision() string {
	if s == nil || s.urlMLClassifier == nil || !s.urlMLClassifier.Enabled() {
		return ""
	}
	material := "model=" + s.urlMLClassifier.Revision() + "\nmode=" + string(s.urlMLMode) + "\n"
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

func (s *Service) observeURLML(domain string, context URLAnalysisContext) *URLMLObservation {
	if s == nil {
		return &URLMLObservation{Mode: analysis.MLModeDisabled}
	}
	observation := &URLMLObservation{Mode: s.urlMLMode}
	if s.urlMLMode != analysis.MLModeShadow || s.urlMLClassifier == nil || !s.urlMLClassifier.Enabled() {
		if s != nil {
			s.urlMLTelemetry.skips.Add(1)
		}
		return observation
	}
	s.urlMLTelemetry.predictionAttempts.Add(1)
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
		return observation
	}
	observation.Evaluated = true
	observation.Probability = decision.Probability
	observation.Action = decision.Action
	observation.ModelVersion = decision.ModelVersion
	observation.Revision = decision.Revision
	if decision.Action == analysis.MLActionPromoteMalicious {
		observation.WouldPromote = true
		s.urlMLTelemetry.wouldPromote.Add(1)
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
