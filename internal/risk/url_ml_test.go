package risk

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
)

type fakeURLClassifier struct {
	decision analysis.MLDecision
	err      error
}

type monitoringURLClassifier struct {
	fakeURLClassifier
	reference analysis.URLMonitoringReference
}

func (m *monitoringURLClassifier) URLMonitoringReference() analysis.URLMonitoringReference {
	return m.reference
}

func (f *fakeURLClassifier) Enabled() bool    { return true }
func (f *fakeURLClassifier) Revision() string { return "url-test-revision" }
func (f *fakeURLClassifier) ClassifyURL(analysis.URLContext) (analysis.MLDecision, error) {
	return f.decision, f.err
}

func TestURLMLShadowObservesWithoutChangingDomainVerdict(t *testing.T) {
	classifier := &fakeURLClassifier{decision: analysis.MLDecision{
		Probability:  0.99,
		Action:       analysis.MLActionPromoteMalicious,
		ModelVersion: "url-test-v1",
		Revision:     "url-test-revision",
	}}
	service := NewService(Options{
		AnalysisConfig:  config.DefaultAnalysisConfig(),
		URLMLClassifier: classifier,
		URLMLMode:       analysis.MLModeShadow,
	})
	defer func() { _ = service.Close() }()

	baseline := service.Analyze(context.Background(), "example.com", ClientInfo{})
	observed := service.AnalyzeWithOptions(
		context.Background(),
		"example.com",
		ClientInfo{},
		AnalyzeOptions{URLContext: &URLAnalysisContext{
			RequestedURL: "https://example.com/login?token=synthetic-secret",
		}},
	)

	if observed.Verdict != baseline.Verdict || observed.Score != baseline.Score {
		t.Fatalf("URL shadow changed domain result: baseline=%+v observed=%+v", baseline.Result, observed.Result)
	}
	if observed.URLML == nil || !observed.URLML.Sampled || !observed.URLML.Evaluated || !observed.URLML.WouldPromote {
		t.Fatalf("missing URL shadow observation: %+v", observed.URLML)
	}
	status := service.URLMLStatus()
	if status.PredictionAttempts != 1 || status.WouldPromote != 1 || status.Errors != 0 {
		t.Fatalf("unexpected URL ML status: %+v", status)
	}
	if status.ProbabilityHistogram["gte_0_90"] != 1 || status.VerdictHistogram["safe"] != 1 || status.Sampling.Selected != 1 {
		t.Fatalf("missing aggregate URL telemetry: %+v", status)
	}
}

func TestURLMLFailureFailsOpenWithoutRawContext(t *testing.T) {
	service := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		URLMLClassifier: &fakeURLClassifier{
			err: errors.New("invalid_url_context: host_mismatch"),
		},
		URLMLMode: analysis.MLModeShadow,
	})
	defer func() { _ = service.Close() }()

	result := service.AnalyzeWithOptions(
		context.Background(),
		"safe.example",
		ClientInfo{},
		AnalyzeOptions{URLContext: &URLAnalysisContext{
			RequestedURL: "https://evil.example/login?token=do-not-log",
		}},
	)

	if result.URLML == nil || result.URLML.Evaluated || result.URLML.ErrorClass != "invalid_url_context" {
		t.Fatalf("unexpected fail-open observation: %+v", result.URLML)
	}
	if result.URLML.ModelVersion != "" || result.URLML.Revision != "" {
		t.Fatalf("error response exposed unexpected model fields: %+v", result.URLML)
	}
}

func TestURLMLModeRejectsEnforce(t *testing.T) {
	t.Setenv("SAFE_ZONE_URL_ML_MODE", "enforce")
	if _, _, err := loadURLMLFromEnv(); err == nil {
		t.Fatal("expected URL ML enforce mode to be rejected")
	}
}

func TestURLMLRequestedShadowWithoutClassifierReportsDegraded(t *testing.T) {
	service := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		URLMLMode:      analysis.MLModeShadow,
	})
	defer func() { _ = service.Close() }()

	status := service.URLMLStatus()
	if status.Mode != analysis.MLModeShadow || status.Enabled || status.State != "degraded" {
		t.Fatalf("unexpected unavailable URL shadow status: %+v", status)
	}
}

func TestURLMLShadowSamplingIsStableAndDoesNotEvaluateExcludedDomains(t *testing.T) {
	classifier := &fakeURLClassifier{decision: analysis.MLDecision{
		Probability: 0.75,
		Action:      analysis.MLActionPromoteMalicious,
	}}
	shadow := URLMLShadowConfig{Percent: 25, Seed: "round-2-test"}
	service := NewService(Options{
		AnalysisConfig:  config.DefaultAnalysisConfig(),
		URLMLClassifier: classifier,
		URLMLMode:       analysis.MLModeShadow,
		URLMLShadow:     shadow,
	})
	defer func() { _ = service.Close() }()

	selectedDomain := ""
	excludedDomain := ""
	for index := 0; index < 1000 && (selectedDomain == "" || excludedDomain == ""); index++ {
		domain := fmt.Sprintf("sample-%d.example", index)
		if shadow.eligible(domain) {
			selectedDomain = domain
		} else {
			excludedDomain = domain
		}
	}
	if selectedDomain == "" || excludedDomain == "" {
		t.Fatal("failed to find deterministic sampling fixtures")
	}
	for _, domain := range []string{selectedDomain, excludedDomain, selectedDomain, excludedDomain} {
		result := service.AnalyzeWithOptions(context.Background(), domain, ClientInfo{}, AnalyzeOptions{
			URLContext: &URLAnalysisContext{RequestedURL: "https://" + domain + "/login"},
		})
		if result.URLML.Sampled != shadow.eligible(domain) {
			t.Fatalf("unstable URL sampling for %s: %+v", domain, result.URLML)
		}
	}
	status := service.URLMLStatus()
	if status.Sampling.Selected != 2 || status.Sampling.Excluded != 2 || status.PredictionAttempts != 2 {
		t.Fatalf("unexpected sampling telemetry: %+v", status)
	}
}

func TestURLMLShadowConfigRequiresSeedForPartialTraffic(t *testing.T) {
	t.Setenv("SAFE_ZONE_URL_ML_SHADOW_PERCENT", "10")
	t.Setenv("SAFE_ZONE_URL_ML_SHADOW_SEED", "")
	if _, err := loadURLMLShadowFromEnv(analysis.MLModeShadow); err == nil {
		t.Fatal("expected partial URL shadow without seed to fail")
	}
	t.Setenv("SAFE_ZONE_URL_ML_SHADOW_SEED", "stable-seed")
	config, err := loadURLMLShadowFromEnv(analysis.MLModeShadow)
	if err != nil || config.Percent != 10 {
		t.Fatalf("unexpected URL shadow config: %+v err=%v", config, err)
	}
}

func TestURLMLDriftReportsPopulationShiftAfterMinimumSamples(t *testing.T) {
	distribution := make([]float64, len(mlProbabilityBuckets))
	for index := range distribution {
		distribution[index] = 0.1
	}
	classifier := &monitoringURLClassifier{
		fakeURLClassifier: fakeURLClassifier{decision: analysis.MLDecision{
			Probability: 0.99,
			Action:      analysis.MLActionPromoteMalicious,
		}},
		reference: analysis.URLMonitoringReference{
			ReferenceKind:           "test-balanced-proxy",
			ReferenceRows:           1000,
			Operational:             true,
			ProbabilityBuckets:      append([]string(nil), mlProbabilityBuckets[:]...),
			ProbabilityDistribution: distribution,
			MinimumLiveSamples:      100,
			PSIWatchThreshold:       0.10,
			PSIAlertThreshold:       0.25,
		},
	}
	service := NewService(Options{
		AnalysisConfig:  config.DefaultAnalysisConfig(),
		URLMLClassifier: classifier,
		URLMLMode:       analysis.MLModeShadow,
	})
	defer func() { _ = service.Close() }()

	for index := 0; index < 100; index++ {
		domain := fmt.Sprintf("drift-%d.example", index)
		service.AnalyzeWithOptions(context.Background(), domain, ClientInfo{}, AnalyzeOptions{
			URLContext: &URLAnalysisContext{RequestedURL: "https://" + domain + "/login"},
		})
	}
	status := service.URLMLStatus()
	if status.Drift.State != "alert" || status.Drift.LiveSamples != 100 || status.Drift.PopulationStabilityIndex <= 0.25 {
		t.Fatalf("unexpected URL drift status: %+v", status.Drift)
	}
}

func TestURLMLBalancedProxyShiftIsDiagnosticNotAlert(t *testing.T) {
	distribution := make([]float64, len(mlProbabilityBuckets))
	for index := range distribution {
		distribution[index] = 0.1
	}
	classifier := &monitoringURLClassifier{
		fakeURLClassifier: fakeURLClassifier{decision: analysis.MLDecision{
			Probability: 0.99,
			Action:      analysis.MLActionPromoteMalicious,
		}},
		reference: analysis.URLMonitoringReference{
			ReferenceKind:           "balanced-offline-proxy",
			ReferenceRows:           1000,
			Operational:             false,
			ProbabilityBuckets:      append([]string(nil), mlProbabilityBuckets[:]...),
			ProbabilityDistribution: distribution,
			MinimumLiveSamples:      10,
			PSIWatchThreshold:       0.10,
			PSIAlertThreshold:       0.25,
		},
	}
	service := NewService(Options{
		AnalysisConfig:  config.DefaultAnalysisConfig(),
		URLMLClassifier: classifier,
		URLMLMode:       analysis.MLModeShadow,
	})
	defer func() { _ = service.Close() }()

	for index := 0; index < 10; index++ {
		domain := fmt.Sprintf("proxy-%d.example", index)
		service.AnalyzeWithOptions(context.Background(), domain, ClientInfo{}, AnalyzeOptions{
			URLContext: &URLAnalysisContext{RequestedURL: "https://" + domain + "/login"},
		})
	}
	status := service.URLMLStatus()
	if status.Drift.State != "proxy_shift" || status.Drift.OperationalReference {
		t.Fatalf("offline proxy unexpectedly became an operational alert: %+v", status.Drift)
	}
}
