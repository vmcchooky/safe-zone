package risk

import (
	"context"
	"errors"
	"testing"

	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
)

type fakeURLClassifier struct {
	decision analysis.MLDecision
	err      error
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
	if observed.URLML == nil || !observed.URLML.Evaluated || !observed.URLML.WouldPromote {
		t.Fatalf("missing URL shadow observation: %+v", observed.URLML)
	}
	status := service.URLMLStatus()
	if status.PredictionAttempts != 1 || status.WouldPromote != 1 || status.Errors != 0 {
		t.Fatalf("unexpected URL ML status: %+v", status)
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
