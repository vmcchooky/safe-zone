package risk

import (
	"context"
	"encoding/json"
	"time"

	"safe-zone/internal/correlation"
)

// decisionIDFor returns the evaluation ID: the request correlation ID
// when the caller propagated one, otherwise a generated eval ID.
func decisionIDFor(ctx context.Context) string {
	if id := correlation.RequestID(ctx); id != "" {
		return id
	}
	return correlation.NewID("eval")
}

// layerTimer accumulates per-layer microseconds using only the bounded
// layer vocabulary, so timing series cannot explode in cardinality.
type layerTimer struct {
	timings map[string]int64
}

func (t *layerTimer) measure(layer string, fn func()) {
	start := time.Now()
	fn()
	if t.timings == nil {
		t.timings = make(map[string]int64)
	}
	t.timings[layer] += time.Since(start).Microseconds()
}

func mergeTimings(maps ...map[string]int64) map[string]int64 {
	merged := make(map[string]int64)
	for _, m := range maps {
		for layer, us := range m {
			merged[layer] += us
		}
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}

// encodeTrace serializes the assessment for the telemetry trace column.
// It never fails: on encoding error the timings are dropped but the
// coverage marker survives, so a broken trace cannot lose the verdict.
func encodeTrace(assess Assessment) string {
	encoded, err := json.Marshal(assess)
	if err != nil {
		fallback, _ := json.Marshal(Assessment{Coverage: assess.Coverage})
		return string(fallback)
	}
	return string(encoded)
}

func skippedLayer(layer, reason string) string {
	if reason == "" {
		return layer
	}
	return layer + ":" + reason
}

func newDomainAssessment() Assessment {
	return Assessment{
		Coverage: AssessmentCoverageDomainOnly,
		Skipped:  []string{skippedLayer(LayerWebsite, SkipNotObserved)},
	}
}

// engineSkippedLayers lists the assessment-engine stages bypassed by a
// short-circuit return. Fresh slice per call so appends never alias.
func engineSkippedLayers() []string {
	return []string{
		LayerThreatFeed, LayerLexical, LayerDomainML, LayerAIRefine,
		LayerEnrichment, LayerOSINT,
	}
}

func prependLayers(base, prefix []string) []string {
	out := make([]string, 0, len(prefix)+len(base))
	out = append(out, prefix...)
	return append(out, base...)
}
