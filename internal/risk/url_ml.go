package risk

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"sync/atomic"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/logjson"
)

type URLAnalysisContext struct {
	RequestedURL  string
	RedirectChain []string
	// EventID is an opaque, caller-generated correlation ID. The server only
	// ever stores an HMAC fingerprint of it (see url_feedback.go).
	EventID string
	// CallerClass is a coarse, non-identifying caller category supplied by
	// the integration (ui|sdk|extension|proxy|other). It is used solely for
	// aggregate coverage breakdowns.
	CallerClass string
}

type URLMLObservation struct {
	Mode          analysis.MLMode `json:"mode"`
	Sampled       bool            `json:"sampled"`
	Evaluated     bool            `json:"evaluated"`
	WouldPromote  bool            `json:"would_promote"`
	Held          bool            `json:"held,omitempty"`
	HoldReason    string          `json:"hold_reason,omitempty"`
	Probability   float64         `json:"probability,omitempty"`
	Action        string          `json:"action,omitempty"`
	ModelVersion  string          `json:"model_version,omitempty"`
	Revision      string          `json:"revision,omitempty"`
	ErrorClass    string          `json:"error_class,omitempty"`
	LatencyMicros int64           `json:"latency_us,omitempty"`
}

// urlPromoteHoldTrustedHost is the hold reason when a model promote fires
// on a trusted-brand host with no host-side evidence. Fixed vocabulary.
const urlPromoteHoldTrustedHost = "trusted_host_without_host_evidence"

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
	Mode                  analysis.MLMode        `json:"mode"`
	Enabled               bool                   `json:"enabled"`
	State                 string                 `json:"state"`
	ModelVersion          string                 `json:"model_version,omitempty"`
	Revision              string                 `json:"revision,omitempty"`
	PolicyRevision        string                 `json:"policy_revision,omitempty"`
	URLThreshold          float64                `json:"url_threshold,omitempty"`
	ContextRequests       int64                  `json:"context_requests"`
	PredictionAttempts    int64                  `json:"prediction_attempts"`
	WouldPromote          int64                  `json:"would_promote"`
	WouldPromoteHeld      int64                  `json:"would_promote_held"`
	WouldPass             int64                  `json:"would_pass"`
	Errors                int64                  `json:"errors"`
	Skips                 int64                  `json:"skips"`
	LatencyP95Micros      int64                  `json:"latency_p95_us"`
	LatencyCount          int64                  `json:"latency_count"`
	LatencyAverageMicros  int64                  `json:"latency_average_us"`
	LatencyHistogram      map[string]int64       `json:"latency_histogram_us"`
	ProbabilityHistogram  map[string]int64       `json:"probability_histogram"`
	ErrorHistogram        map[string]int64       `json:"error_histogram"`
	InputHistogram        map[string]int64       `json:"input_histogram"`
	VerdictHistogram      map[string]int64       `json:"primary_verdict_histogram"`
	WouldPromoteByVerdict map[string]int64       `json:"would_promote_by_primary_verdict"`
	Sampling              URLMLSamplingStatus    `json:"sampling"`
	Drift                 URLMLDriftStatus       `json:"drift"`
	Coverage              URLMLCoverageStatus    `json:"coverage"`
	Feedback              URLMLFeedbackStatus    `json:"feedback"`
	Baseline              URLMLOpsBaselineStatus `json:"operational_baseline"`
}

// URLMLCoverageStatus tracks how much of total analysis traffic actually
// carries URL context, plus a coarse non-identifying caller breakdown and the
// structural reason context was missing.
type URLMLCoverageStatus struct {
	AnalyzeRequests         int64            `json:"analyze_requests"`
	URLContextRequests      int64            `json:"url_context_requests"`
	ContextCoverageRate     float64          `json:"context_coverage_rate"`
	RedirectChainPresent    int64            `json:"redirect_chain_present"`
	CallerBreakdown         map[string]int64 `json:"caller_breakdown"`
	MissingContextBreakdown map[string]int64 `json:"missing_context_breakdown"`
}

// URLMLFeedbackStatus aggregates privacy-safe label correlation counters.
// Calibration numbers exist only when labelled events exist. Persistence
// reports "memory" (ephemeral ring buffer) or "sqlite" (durable bounded
// retention); a degraded durable store keeps failing closed for labels.
type URLMLFeedbackStatus struct {
	Supported                   bool    `json:"supported"`
	Persistence                 string  `json:"persistence,omitempty"`
	RecordedEvents              int64   `json:"recorded_events"`
	LabelledEvents              int64   `json:"labelled_events"`
	ConfirmedMalicious          int64   `json:"confirmed_malicious"`
	ReportedBenignFalsePositive int64   `json:"reported_benign_false_positive"`
	WouldPromoteLabelled        int64   `json:"would_promote_labelled"`
	LabelledFalsePositiveRate   float64 `json:"labelled_false_positive_rate,omitempty"`
	Capacity                    int     `json:"capacity,omitempty"`
	KeyVersion                  int     `json:"key_version,omitempty"`
	PreviousKeyVersion          int     `json:"previous_key_version,omitempty"`
	RetentionHours              int     `json:"retention_hours,omitempty"`
	MaxRows                     int     `json:"max_rows,omitempty"`
	PersistenceErrors           int64   `json:"persistence_errors,omitempty"`
	Degraded                    bool    `json:"degraded,omitempty"`
	Note                        string  `json:"note,omitempty"`
}

// urlMLCallerClasses enumerates the fixed, bounded set of coarse caller
// categories tracked for coverage. Nothing here identifies an end user.
const urlMLCallerClassCount = 6

var urlMLCallerClasses = [urlMLCallerClassCount]string{"unspecified", "ui", "sdk", "extension", "proxy", "other"}

// urlMLMissingContextReasons enumerates the fixed, structural reasons an
// analyze request can carry no URL context. GET analysis is domain-only by
// contract; POST callers either did not send a URL or sent nothing at all.
const urlMLMissingContextReasonCount = 3

var urlMLMissingContextReasons = [urlMLMissingContextReasonCount]string{
	"get_domain_only",
	"post_not_provided",
	"unspecified",
}

func normalizeURLMLMissingContextReason(raw string) int {
	switch raw {
	case "get_domain_only":
		return 0
	case "post_not_provided":
		return 1
	default:
		return 2
	}
}

func normalizeURLMLCallerClass(raw string) string {
	switch raw {
	case "ui", "sdk", "extension", "proxy", "other":
		return raw
	case "":
		return "unspecified"
	default:
		return "other"
	}
}

type urlMLTelemetry struct {
	contextRequests       atomic.Int64
	predictionAttempts    atomic.Int64
	wouldPromote          atomic.Int64
	wouldPass             atomic.Int64
	heldPromote           atomic.Int64
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
	analyzeRequests       atomic.Int64
	urlContextRequests    atomic.Int64
	redirectPresent       atomic.Int64
	callerBuckets         [len(urlMLCallerClasses)]atomic.Int64
	missingContextBuckets [len(urlMLMissingContextReasons)]atomic.Int64
}

// noteMissingContext records the structural reason an analyze request carried
// no URL context. It is a fixed-bucket aggregate only.
func (t *urlMLTelemetry) noteMissingContext(reason string) {
	if t == nil {
		return
	}
	t.missingContextBuckets[normalizeURLMLMissingContextReason(reason)].Add(1)
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
	observeLatencyMicros(t.latencyBuckets[:], micros)
}

func (t *urlMLTelemetry) observeProbability(probability float64) {
	if t == nil {
		return
	}
	observeProbabilityMicros(t.probabilityBuckets[:], probability)
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
	var reference analysis.URLMonitoringReference
	if s.ml.urlMLOpsBaseline != nil {
		reference = analysis.URLMonitoringReference{
			ReferenceKind:           s.ml.urlMLOpsBaseline.ReferenceKind,
			ReferenceRows:           s.ml.urlMLOpsBaseline.ReferenceRows,
			Operational:             true,
			ProbabilityBuckets:      s.ml.urlMLOpsBaseline.BucketNames,
			ProbabilityDistribution: s.ml.urlMLOpsBaseline.Distribution,
			MinimumLiveSamples:      s.ml.urlMLOpsBaseline.MinimumLiveSamples,
			PSIWatchThreshold:       s.ml.urlMLOpsBaseline.WatchThreshold,
			PSIAlertThreshold:       s.ml.urlMLOpsBaseline.AlertThreshold,
		}
	} else {
		provider, ok := s.ml.urlMLClassifier.(analysis.URLMonitoringReferenceProvider)
		if !ok {
			return status
		}
		reference = provider.URLMonitoringReference()
	}
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
		count := s.ml.urlMLTelemetry.probabilityBuckets[index].Load()
		live[index] = float64(count)
		total += count
	}
	status.LiveSamples = total
	if total < int64(reference.MinimumLiveSamples) {
		status.State = "insufficient_data"
		return status
	}
	denominator := float64(total) + 0.5*float64(len(live))
	// The reference is a *normalized* distribution (url_baseline divides the
	// histogram by its total), while the live side is raw bucket counts. Those
	// are different scales, so they cannot be smoothed with the same absolute
	// constant: adding 0.5 to each of ten buckets is a rounding error against
	// ~1000 live samples but five times the reference's entire mass, which
	// distorted every share. Scaling the reference by ReferenceRows — the
	// sample count it was measured over — puts both sides on the same footing
	// so the two formulas become the same expression.
	//
	// The reference was previously used raw, and a zero-count reference bucket
	// is legal (url_baseline rejects only negative counts). That made
	// referenceShare 0, and since liveShare is always > 0 the term
	// log(liveShare/0) is +Inf: psi became +Inf for every live sample set
	// rather than only under drift, and +Inf is not representable in JSON, so
	// the whole /v1/status payload failed to encode after its 200 was written.
	//
	// With both sides on one scale, identical distributions score exactly 0 —
	// which is the property the 0.1/0.25 thresholds assume. Measured after the
	// fix: identical 0.00000, sampling noise 0.0065, a real shift 1.88742.
	//
	// A reference with no recorded row count cannot be placed on that scale, so
	// it yields no PSI rather than a fabricated one.
	referenceScale := float64(reference.ReferenceRows)
	if referenceScale <= 0 {
		return status
	}
	referenceDenominator := referenceScale + 0.5*float64(len(reference.ProbabilityDistribution))
	psi := 0.0
	for index, count := range live {
		liveShare := (count + 0.5) / denominator
		referenceCount := reference.ProbabilityDistribution[index] * referenceScale
		referenceShare := (referenceCount + 0.5) / referenceDenominator
		psi += (liveShare - referenceShare) * math.Log(liveShare/referenceShare)
	}
	// Defensive: a non-finite value here would break the status payload for
	// every consumer. Fail toward the more protective state and publish a
	// finite number rather than an unencodable one.
	if math.IsNaN(psi) || math.IsInf(psi, 0) {
		logjson.Warn("drift PSI was not finite; reporting alert", map[string]any{
			"service":         "risk",
			"reference_kind":  reference.ReferenceKind,
			"reference_rows":  reference.ReferenceRows,
			"live_samples":    status.LiveSamples,
			"watch_threshold": reference.PSIWatchThreshold,
			"alert_threshold": reference.PSIAlertThreshold,
		})
		psi = reference.PSIAlertThreshold
		status.State = "alert"
		status.Interpretation = "population stability index was not finite; treated as drift until the reference is re-frozen"
		status.PopulationStabilityIndex = psi
		return status
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
	return latencyP95Micros(t.latencyBuckets[:], t.latencyCount.Load())
}

// URLMLStatus reports the URL-ML subsystem state.
//
// ctx bounds the durable feedback read inside the snapshot. This is an
// observability call rather than a request-scoped one, so callers on the service
// side pass the service lifecycle context: the read should stop when the service
// shuts down rather than outliving it.
func (s *Service) URLMLStatus(ctx context.Context) URLMLStatus {
	if s == nil {
		return URLMLStatus{Mode: analysis.MLModeDisabled, State: "disabled"}
	}
	if ctx == nil {
		ctx = s.lifecycleCtx
	}
	enabled := s.ml.urlMLClassifier != nil && s.ml.urlMLClassifier.Enabled()
	status := URLMLStatus{
		Mode:                 s.ml.urlMLMode,
		Enabled:              enabled,
		State:                mlState(s.ml.urlMLMode, enabled),
		PolicyRevision:       s.currentURLMLPolicyRevision(),
		ContextRequests:      s.ml.urlMLTelemetry.contextRequests.Load(),
		PredictionAttempts:   s.ml.urlMLTelemetry.predictionAttempts.Load(),
		WouldPromote:         s.ml.urlMLTelemetry.wouldPromote.Load(),
		WouldPromoteHeld:     s.ml.urlMLTelemetry.heldPromote.Load(),
		WouldPass:            s.ml.urlMLTelemetry.wouldPass.Load(),
		Errors:               s.ml.urlMLTelemetry.errors.Load(),
		Skips:                s.ml.urlMLTelemetry.skips.Load(),
		LatencyP95Micros:     s.ml.urlMLTelemetry.latencyP95(),
		LatencyCount:         s.ml.urlMLTelemetry.latencyCount.Load(),
		LatencyHistogram:     make(map[string]int64, len(mlLatencyBuckets)+1),
		ProbabilityHistogram: make(map[string]int64, len(mlProbabilityBuckets)),
		ErrorHistogram: map[string]int64{
			"invalid_url_context": s.ml.urlMLTelemetry.invalidContext.Load(),
			"prediction_error":    s.ml.urlMLTelemetry.predictionErrors.Load(),
		},
		InputHistogram: map[string]int64{
			"query_present":    s.ml.urlMLTelemetry.queryPresent.Load(),
			"query_absent":     s.ml.urlMLTelemetry.queryAbsent.Load(),
			"redirects_0":      s.ml.urlMLTelemetry.redirectBuckets[0].Load(),
			"redirects_1":      s.ml.urlMLTelemetry.redirectBuckets[1].Load(),
			"redirects_2_to_5": s.ml.urlMLTelemetry.redirectBuckets[2].Load(),
		},
		VerdictHistogram: map[string]int64{
			"safe":       s.ml.urlMLTelemetry.verdictBuckets[0].Load(),
			"suspicious": s.ml.urlMLTelemetry.verdictBuckets[1].Load(),
			"malicious":  s.ml.urlMLTelemetry.verdictBuckets[2].Load(),
		},
		WouldPromoteByVerdict: map[string]int64{
			"safe":       s.ml.urlMLTelemetry.promoteVerdictBuckets[0].Load(),
			"suspicious": s.ml.urlMLTelemetry.promoteVerdictBuckets[1].Load(),
			"malicious":  s.ml.urlMLTelemetry.promoteVerdictBuckets[2].Load(),
		},
		Sampling: URLMLSamplingStatus{
			Percent:          s.ml.urlMLShadow.Percent,
			Algorithm:        urlMLSelectorAlgorithm,
			SelectorRevision: s.ml.urlMLShadow.revision(),
			Selected:         s.ml.urlMLTelemetry.selected.Load(),
			Excluded:         s.ml.urlMLTelemetry.excluded.Load(),
		},
		Drift: s.urlMLDriftStatus(),
	}
	status.Coverage = s.urlMLCoverageStatus()
	status.Feedback = s.ml.urlMLFeedback.status(ctx)
	status.Baseline = s.urlMLOpsBaselineStatus()
	if status.LatencyCount > 0 {
		status.LatencyAverageMicros = s.ml.urlMLTelemetry.latencyTotalMicros.Load() / status.LatencyCount
	}
	if enabled {
		status.Revision = s.ml.urlMLClassifier.Revision()
	}
	if metadata, ok := s.ml.urlMLClassifier.(analysis.URLClassifierMetadata); ok {
		status.ModelVersion = metadata.ModelVersion()
		status.URLThreshold = metadata.URLThreshold()
	}
	for index, upper := range mlLatencyBuckets {
		status.LatencyHistogram[fmt.Sprintf("le_%dus", upper)] = s.ml.urlMLTelemetry.latencyBuckets[index].Load()
	}
	status.LatencyHistogram["gt_50000us"] = s.ml.urlMLTelemetry.latencyBuckets[len(mlLatencyBuckets)].Load()
	for index, name := range mlProbabilityBuckets {
		status.ProbabilityHistogram[name] = s.ml.urlMLTelemetry.probabilityBuckets[index].Load()
	}
	return status
}

func (s *Service) currentURLMLPolicyRevision() string {
	if s == nil || s.ml.urlMLClassifier == nil || !s.ml.urlMLClassifier.Enabled() {
		return ""
	}
	material := "model=" + s.ml.urlMLClassifier.Revision() + "\nmode=" + string(s.ml.urlMLMode) + "\nsampling=" + s.ml.urlMLShadow.revision() + "\n"
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

func (s *Service) observeURLML(ctx context.Context, domain string, primaryVerdict analysis.Verdict, context URLAnalysisContext) *URLMLObservation {
	if s == nil {
		return &URLMLObservation{Mode: analysis.MLModeDisabled}
	}
	observation := &URLMLObservation{Mode: s.ml.urlMLMode}
	s.ml.urlMLTelemetry.contextRequests.Add(1)
	s.ml.urlMLTelemetry.urlContextRequests.Add(1)
	s.ml.urlMLTelemetry.callerBuckets[urlMLCallerIndex(context.CallerClass)].Add(1)
	if len(context.RedirectChain) > 0 {
		s.ml.urlMLTelemetry.redirectPresent.Add(1)
	}
	if s.ml.urlMLMode != analysis.MLModeShadow || s.ml.urlMLClassifier == nil || !s.ml.urlMLClassifier.Enabled() {
		s.ml.urlMLTelemetry.skips.Add(1)
		return observation
	}
	if !s.ml.urlMLShadow.eligible(domain) {
		s.ml.urlMLTelemetry.excluded.Add(1)
		return observation
	}
	observation.Sampled = true
	s.ml.urlMLTelemetry.selected.Add(1)
	s.ml.urlMLTelemetry.predictionAttempts.Add(1)
	if strings.Contains(context.RequestedURL, "?") {
		s.ml.urlMLTelemetry.queryPresent.Add(1)
	} else {
		s.ml.urlMLTelemetry.queryAbsent.Add(1)
	}
	redirectIndex := len(context.RedirectChain)
	if redirectIndex > 2 {
		redirectIndex = 2
	}
	s.ml.urlMLTelemetry.redirectBuckets[redirectIndex].Add(1)
	verdictIndex := urlMLVerdictIndex(primaryVerdict)
	s.ml.urlMLTelemetry.verdictBuckets[verdictIndex].Add(1)
	started := time.Now()
	decision, err := s.ml.urlMLClassifier.ClassifyURL(analysis.URLContext{
		RequestedURL:  context.RequestedURL,
		ExpectedHost:  domain,
		RedirectChain: append([]string(nil), context.RedirectChain...),
	})
	latency := time.Since(started)
	s.ml.urlMLTelemetry.observeLatency(latency)
	observation.LatencyMicros = latency.Microseconds()
	if err != nil {
		s.ml.urlMLTelemetry.errors.Add(1)
		observation.ErrorClass = classifyURLMLError(err)
		if observation.ErrorClass == "invalid_url_context" {
			s.ml.urlMLTelemetry.invalidContext.Add(1)
		} else {
			s.ml.urlMLTelemetry.predictionErrors.Add(1)
		}
		// Record the fingerprint even when classification failed so a caller who
		// observed sampled=true can label it without a spurious unknown_event.
		// The caller opted into feedback via event_id; without this the label
		// would be rejected even though the event was legitimately observed.
		s.ml.urlMLFeedback.record(ctx, context.EventID, -1, false)
		return observation
	}
	observation.Evaluated = true
	observation.Probability = decision.Probability
	observation.Action = decision.Action
	observation.ModelVersion = decision.ModelVersion
	observation.Revision = decision.Revision
	s.ml.urlMLTelemetry.observeProbability(decision.Probability)
	if decision.Action == analysis.MLActionPromoteMalicious {
		if reason := s.urlPromoteHoldReason(ctx, domain); reason != "" {
			observation.Held = true
			observation.HoldReason = reason
			s.ml.urlMLTelemetry.heldPromote.Add(1)
			s.ml.urlMLTelemetry.wouldPass.Add(1)
			s.ml.urlMLFeedback.record(ctx, context.EventID, decision.Probability, false)
			return observation
		}
		observation.WouldPromote = true
		s.ml.urlMLTelemetry.wouldPromote.Add(1)
		s.ml.urlMLTelemetry.promoteVerdictBuckets[verdictIndex].Add(1)
	} else {
		s.ml.urlMLTelemetry.wouldPass.Add(1)
	}
	s.ml.urlMLFeedback.record(ctx, context.EventID, decision.Probability, observation.WouldPromote)
	return observation
}

// urlPromoteHoldReason reports why a model promote is held, or "" to let it
// stand.
//
// The rule: on a host belonging to a trusted brand, do not promote on the
// model's say-so alone. A live exact feed IOC naming the host overrides it —
// scoped evidence wins, the PR-59 principle at the URL layer — because then
// there is a reason to believe the host itself is bad, not just its URL.
//
// The rationale is not "lure words in a path prove nothing", which is what this
// comment claimed until 2026-09-29 while the code never inspected a path. It
// is an asymmetry in cost: a false block on a real host breaks a service for
// every user behind the resolver, while the model missing a phish hosted on
// apple.com costs one visit. When the model is unsure about a host we know is
// legitimate, not promoting is the safe answer.
//
// So the guard is deliberately blanket. An attempt was made on 2026-09-29 to
// condition the hold on a lure marker appearing in the URL path, on the theory
// that this was the rule the comment described. It released two benign
// trusted-brand URLs and was measured as raising the guard's pinned
// false-positive ceiling from 12 to 14. Both were model false positives, so
// holding them was the guard working as intended; loosening it traded a real
// protection for a number that only production-traffic data could justify. The
// path logic was removed and the ceiling left at 12.
//
// URL-ML is shadow-only — this never enforces today — so what is at stake is
// the quality of the shadow data, not a live block.
//
// Lookup errors fail open (no hold): a blind guard must never suppress.
func (s *Service) urlPromoteHoldReason(ctx context.Context, domain string) string {
	if !analysis.IsTrustedBrandSuffix(domain, s.trustedBrands(ctx)) {
		return ""
	}
	hit, err := s.matchExactThreatFeed(ctx, domain)
	if err != nil {
		return ""
	}
	if hit {
		return ""
	}
	return urlPromoteHoldTrustedHost
}

// RecordURLFeedback correlates a caller label with an earlier shadow event.
// It only ever touches HMAC fingerprints; raw URLs are never involved.
//
// ctx bounds the durable lookup, so a caller that has gone away does not leave
// a query queued on the single SQLite connection.
func (s *Service) RecordURLFeedback(ctx context.Context, eventID, label string) (bool, string) {
	if s == nil || s.ml.urlMLFeedback == nil {
		return false, "unsupported"
	}
	if ctx == nil {
		ctx = s.lifecycleCtx
	}
	return s.ml.urlMLFeedback.apply(ctx, eventID, label)
}

func urlMLCallerIndex(raw string) int {
	class := normalizeURLMLCallerClass(raw)
	for index, name := range urlMLCallerClasses {
		if name == class {
			return index
		}
	}
	return 0
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

// urlMLCoverageStatus aggregates URL-context coverage over all analysis
// traffic, plus a bounded caller-class breakdown and the structural reasons
// for missing context.
func (s *Service) urlMLCoverageStatus() URLMLCoverageStatus {
	if s == nil {
		return URLMLCoverageStatus{
			CallerBreakdown:         map[string]int64{},
			MissingContextBreakdown: map[string]int64{},
		}
	}
	breakdown := make(map[string]int64, len(urlMLCallerClasses))
	var total int64
	for index, name := range urlMLCallerClasses {
		count := s.ml.urlMLTelemetry.callerBuckets[index].Load()
		breakdown[name] = count
		total += count
	}
	missing := make(map[string]int64, len(urlMLMissingContextReasons))
	for index, name := range urlMLMissingContextReasons {
		missing[name] = s.ml.urlMLTelemetry.missingContextBuckets[index].Load()
	}
	status := URLMLCoverageStatus{
		AnalyzeRequests:         s.ml.urlMLTelemetry.analyzeRequests.Load(),
		URLContextRequests:      total,
		RedirectChainPresent:    s.ml.urlMLTelemetry.redirectPresent.Load(),
		CallerBreakdown:         breakdown,
		MissingContextBreakdown: missing,
	}
	if status.AnalyzeRequests > 0 {
		status.ContextCoverageRate = float64(status.URLContextRequests) / float64(status.AnalyzeRequests)
	}
	return status
}

// urlMLOpsBaselineStatus reports the frozen operational baseline state. A
// load failure is surfaced as fail_open with an error class; it never blocks
// the classifier.
func (s *Service) urlMLOpsBaselineStatus() URLMLOpsBaselineStatus {
	if s == nil {
		return URLMLOpsBaselineStatus{}
	}
	if s.ml.urlMLOpsBaseline != nil {
		return s.ml.urlMLOpsBaseline.status()
	}
	return URLMLOpsBaselineStatus{
		Loaded:      false,
		Operational: false,
		FailOpen:    s.ml.urlMLOpsBaselineFailed,
		ErrorClass:  s.ml.urlMLOpsBaselineErrorClass,
	}
}
