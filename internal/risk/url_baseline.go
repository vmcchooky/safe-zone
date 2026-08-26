package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// URLOperationalBaseline is a frozen operational monitoring reference derived
// from real (non-proxy) shadow traffic on the target runtime. It only affects
// drift monitoring; it never changes classification, thresholds or verdicts.
// Loading failures are fail-open: the URL classifier stays available.
type URLOperationalBaseline struct {
	Path               string
	SHA256             string
	ModelVersion       string
	Revision           string
	ReferenceKind      string
	ReferenceRows      int
	TrafficScope       string
	RecordedAt         string
	BucketNames        []string
	Distribution       []float64
	MinimumLiveSamples int
	WatchThreshold     float64
	AlertThreshold     float64
}

type urlOpsBaselineFile struct {
	SchemaVersion          int    `json:"schema_version"`
	Kind                   string `json:"kind"`
	ModelVersion           string `json:"model_version"`
	Revision               string `json:"revision"`
	TrafficScope           string `json:"traffic_scope,omitempty"`
	RecordedAt             string `json:"recorded_at,omitempty"`
	DistributionHistograms struct {
		ProbabilityHistogram map[string]int64 `json:"probability_histogram"`
	} `json:"distribution_histograms"`
}

const (
	urlOpsBaselineWatchThreshold = 0.1
	urlOpsBaselineAlertThreshold = 0.25
	urlOpsBaselineMinSamples     = 100
)

// loadURLOperationalBaseline validates and normalizes a frozen operational
// baseline artifact. The model version and revision must match the loaded URL
// classifier exactly so a stale baseline can never be presented as current.
func loadURLOperationalBaseline(path, modelVersion, revision string) (*URLOperationalBaseline, error) {
	if path == "" {
		return nil, fmt.Errorf("baseline path is empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	sum := sha256.Sum256(raw)
	var file urlOpsBaselineFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("parse baseline: %w", err)
	}
	if file.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported baseline schema_version %d", file.SchemaVersion)
	}
	if file.Kind != "url_ml_shadow_operational_baseline" && file.Kind != "url_ml_operational_baseline" {
		return nil, fmt.Errorf("unexpected baseline kind %q", file.Kind)
	}
	if file.ModelVersion != modelVersion || file.Revision != revision {
		return nil, fmt.Errorf("baseline model mismatch: baseline=%s/%s classifier=%s/%s",
			file.ModelVersion, file.Revision, modelVersion, revision)
	}
	baseline := &URLOperationalBaseline{
		Path:               path,
		SHA256:             hex.EncodeToString(sum[:]),
		ModelVersion:       file.ModelVersion,
		Revision:           file.Revision,
		ReferenceKind:      "frozen_operational_shadow_traffic",
		TrafficScope:       file.TrafficScope,
		RecordedAt:         file.RecordedAt,
		MinimumLiveSamples: urlOpsBaselineMinSamples,
		WatchThreshold:     urlOpsBaselineWatchThreshold,
		AlertThreshold:     urlOpsBaselineAlertThreshold,
	}
	baseline.BucketNames = make([]string, len(mlProbabilityBuckets))
	baseline.Distribution = make([]float64, len(mlProbabilityBuckets))
	histogram := file.DistributionHistograms.ProbabilityHistogram
	var total float64
	for index, name := range mlProbabilityBuckets {
		count, ok := histogram[name]
		if !ok {
			return nil, fmt.Errorf("baseline probability histogram missing bucket %q", name)
		}
		if count < 0 {
			return nil, fmt.Errorf("baseline probability histogram bucket %q is negative", name)
		}
		baseline.BucketNames[index] = name
		baseline.Distribution[index] = float64(count)
		total += float64(count)
	}
	if total <= 0 {
		return nil, fmt.Errorf("baseline probability histogram is empty")
	}
	baseline.ReferenceRows = int(total)
	for index := range baseline.Distribution {
		baseline.Distribution[index] /= total
	}
	return baseline, nil
}

// URLMLOpsBaselineStatus reports whether a frozen operational reference is in
// use by drift monitoring. It never gates classification availability.
type URLMLOpsBaselineStatus struct {
	Loaded             bool    `json:"loaded"`
	Path               string  `json:"path,omitempty"`
	SHA256             string  `json:"sha256,omitempty"`
	ModelVersion       string  `json:"model_version,omitempty"`
	Revision           string  `json:"revision,omitempty"`
	ReferenceKind      string  `json:"reference_kind,omitempty"`
	ReferenceRows      int     `json:"reference_rows,omitempty"`
	TrafficScope       string  `json:"traffic_scope,omitempty"`
	Operational        bool    `json:"operational_reference"`
	FailOpen           bool    `json:"fail_open,omitempty"`
	ErrorClass         string  `json:"error_class,omitempty"`
	MinimumLiveSamples int     `json:"minimum_live_samples,omitempty"`
	WatchThreshold     float64 `json:"watch_threshold,omitempty"`
	AlertThreshold     float64 `json:"alert_threshold,omitempty"`
	RecordedAt         string  `json:"recorded_at,omitempty"`
}

// status exposes non-identifying provenance for operators.
func (b *URLOperationalBaseline) status() URLMLOpsBaselineStatus {
	return URLMLOpsBaselineStatus{
		Loaded:             true,
		Path:               b.Path,
		SHA256:             b.SHA256,
		ModelVersion:       b.ModelVersion,
		Revision:           b.Revision,
		ReferenceKind:      b.ReferenceKind,
		ReferenceRows:      b.ReferenceRows,
		TrafficScope:       b.TrafficScope,
		Operational:        true,
		MinimumLiveSamples: b.MinimumLiveSamples,
		WatchThreshold:     b.WatchThreshold,
		AlertThreshold:     b.AlertThreshold,
		RecordedAt:         b.RecordedAt,
	}
}
