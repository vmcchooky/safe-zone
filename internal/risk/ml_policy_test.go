package risk

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/config"
)

type fakeMLClassifier struct {
	decision analysis.MLDecision
	calls    int
	revision string
}

func (f *fakeMLClassifier) Enabled() bool { return f != nil }
func (f *fakeMLClassifier) Revision() string {
	if f.revision == "" {
		return "fake-revision"
	}
	return f.revision
}
func (f *fakeMLClassifier) Classify(string) (analysis.MLDecision, error) {
	f.calls++
	return f.decision, nil
}

func newMLPolicyTestService(classifier analysis.DomainClassifier, mode analysis.MLMode) *Service {
	canary := MLCanaryConfig{}
	if mode == analysis.MLModeEnforce {
		canary = MLCanaryConfig{Percent: 100, Seed: "test-enforce"}
	}
	return NewService(Options{
		AIProvider:          "",
		AnalysisConfig:      config.DefaultAnalysisConfig(),
		MLClassifier:        classifier,
		MLMode:              mode,
		MLCanary:            canary,
		TTLAllowed:          time.Hour,
		TTLSuspicious:       time.Hour,
		TTLBlocked:          time.Hour,
		ConfigReloadEnabled: false,
	})
}

func TestMLEnforcePromotesSuspiciousAndSkipsAI(t *testing.T) {
	fake := &fakeMLClassifier{decision: analysis.MLDecision{
		Probability:  0.93,
		Action:       analysis.MLActionPromoteMalicious,
		ModelVersion: "test-model",
	}}
	service := newMLPolicyTestService(fake, analysis.MLModeEnforce)
	defer service.Close()

	result := service.Analyze(context.Background(), "login-security-example.com", ClientInfo{}).Result
	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected ML promotion, got %s", result.Verdict)
	}
	if result.Score != 93 || result.Confidence != 0.93 {
		t.Fatalf("expected calibrated result fields, got score=%d confidence=%v", result.Score, result.Confidence)
	}
	if !containsReason(result.Reasons, mlClassifierReason) {
		t.Fatalf("missing stable ML reason: %#v", result.Reasons)
	}
	if fake.calls != 1 {
		t.Fatalf("expected one ML call, got %d", fake.calls)
	}
	if status := service.MLStatus(); status.EnforcePromotions != 1 || status.LLMFallbacks != 0 {
		t.Fatalf("unexpected ML telemetry: %+v", status)
	}
}

func TestMLShadowDoesNotChangeVerdict(t *testing.T) {
	fake := &fakeMLClassifier{decision: analysis.MLDecision{
		Probability: 0.99,
		Action:      analysis.MLActionPromoteMalicious,
	}}
	service := newMLPolicyTestService(fake, analysis.MLModeShadow)
	defer service.Close()

	result := service.Analyze(context.Background(), "login-security-example.com", ClientInfo{}).Result
	if result.Verdict != analysis.VerdictSuspicious {
		t.Fatalf("shadow mode changed verdict to %s", result.Verdict)
	}
	if status := service.MLStatus(); status.ShadowWouldBlock != 1 || status.EnforcePromotions != 0 {
		t.Fatalf("unexpected shadow telemetry: %+v", status)
	}
}

func TestMLShadowRecordsWouldPassAndProbabilityBucket(t *testing.T) {
	fake := &fakeMLClassifier{decision: analysis.MLDecision{
		Probability: 0.12,
		Action:      analysis.MLActionAbstain,
	}}
	service := newMLPolicyTestService(fake, analysis.MLModeShadow)
	defer service.Close()

	result := service.Analyze(context.Background(), "login-security-example.com", ClientInfo{}).Result
	if result.Verdict != analysis.VerdictSuspicious {
		t.Fatalf("shadow mode changed verdict to %s", result.Verdict)
	}
	status := service.MLStatus()
	if status.State != "ready" || status.ShadowWouldPass != 1 || status.ShadowWouldBlock != 0 {
		t.Fatalf("unexpected shadow status: %+v", status)
	}
	if status.ProbabilityHistogram["0_10_0_19"] != 1 {
		t.Fatalf("expected probability histogram sample, got %+v", status.ProbabilityHistogram)
	}
}

func TestMLDisabledPreservesFlowAndDoesNotCallClassifier(t *testing.T) {
	fake := &fakeMLClassifier{decision: analysis.MLDecision{
		Probability: 0.99,
		Action:      analysis.MLActionPromoteMalicious,
	}}
	service := newMLPolicyTestService(fake, analysis.MLModeDisabled)
	defer service.Close()

	result := service.Analyze(context.Background(), "login-security-example.com", ClientInfo{}).Result
	if result.Verdict != analysis.VerdictSuspicious {
		t.Fatalf("disabled mode changed verdict to %s", result.Verdict)
	}
	if fake.calls != 0 {
		t.Fatalf("disabled mode called classifier %d times", fake.calls)
	}
}

func TestMLRuntimeConfigValidation(t *testing.T) {
	t.Run("rejects unknown mode", func(t *testing.T) {
		t.Setenv("SAFE_ZONE_ML_MODE", "observe")
		if _, _, err := loadMLFromEnv(); err == nil {
			t.Fatal("expected invalid ML mode error")
		}
	})
	t.Run("enforce requires bundle", func(t *testing.T) {
		t.Setenv("SAFE_ZONE_ML_MODE", "enforce")
		t.Setenv("SAFE_ZONE_ML_BUNDLE_DIR", "")
		if _, _, err := loadMLFromEnv(); err == nil {
			t.Fatal("expected missing bundle error")
		}
	})
	t.Run("optional shadow keeps requested mode when bundle is unavailable", func(t *testing.T) {
		t.Setenv("SAFE_ZONE_ML_MODE", "shadow")
		t.Setenv("SAFE_ZONE_ML_BUNDLE_DIR", "missing")
		t.Setenv("SAFE_ZONE_ML_REQUIRED", "false")
		mode, classifier, err := loadMLFromEnv()
		if err != nil {
			t.Fatalf("optional shadow bundle should fail open: %v", err)
		}
		if mode != analysis.MLModeShadow || classifier != nil {
			t.Fatalf("expected degraded shadow mode, got mode=%q classifier=%v", mode, classifier)
		}
	})
	t.Run("rejects threshold outside range", func(t *testing.T) {
		t.Setenv("SAFE_ZONE_ML_MODE", "shadow")
		t.Setenv("SAFE_ZONE_ML_BUNDLE_DIR", "missing")
		t.Setenv("SAFE_ZONE_ML_BLOCK_THRESHOLD", "1.0")
		if _, _, err := loadMLFromEnv(); err == nil {
			t.Fatal("expected invalid threshold error")
		}
	})
	t.Run("enforce requires bounded canary", func(t *testing.T) {
		t.Setenv("SAFE_ZONE_ML_CANARY_PERCENT", "0")
		t.Setenv("SAFE_ZONE_ML_CANARY_SEED", "")
		if _, err := loadMLCanaryFromEnv(analysis.MLModeEnforce); err == nil {
			t.Fatal("expected enforce without canary to fail")
		}
	})
	t.Run("shadow accepts configured canary observation", func(t *testing.T) {
		t.Setenv("SAFE_ZONE_ML_CANARY_PERCENT", "5")
		t.Setenv("SAFE_ZONE_ML_CANARY_SEED", "phase5-test")
		canary, err := loadMLCanaryFromEnv(analysis.MLModeShadow)
		if err != nil {
			t.Fatal(err)
		}
		if canary.Percent != 5 || !canary.enabled() {
			t.Fatalf("unexpected canary config: %+v", canary)
		}
	})
	t.Run("rejects invalid canary percent", func(t *testing.T) {
		t.Setenv("SAFE_ZONE_ML_CANARY_PERCENT", "101")
		t.Setenv("SAFE_ZONE_ML_CANARY_SEED", "phase5-test")
		if _, err := loadMLCanaryFromEnv(analysis.MLModeShadow); err == nil {
			t.Fatal("expected invalid canary percent to fail")
		}
	})
	t.Run("rejects non-numeric canary percent", func(t *testing.T) {
		t.Setenv("SAFE_ZONE_ML_CANARY_PERCENT", "ten")
		t.Setenv("SAFE_ZONE_ML_CANARY_SEED", "phase5-test")
		if _, err := loadMLCanaryFromEnv(analysis.MLModeShadow); err == nil {
			t.Fatal("expected non-numeric canary percent to fail")
		}
	})
}

func TestAnalysisCacheInvalidatesWhenModelRevisionChanges(t *testing.T) {
	redisServer := miniredis.RunT(t)
	classifierV1 := &fakeMLClassifier{
		decision: analysis.MLDecision{Probability: 0.95, Action: analysis.MLActionPromoteMalicious},
		revision: "model-v1",
	}
	classifierV2 := &fakeMLClassifier{
		decision: analysis.MLDecision{Probability: 0.10, Action: analysis.MLActionAbstain},
		revision: "model-v2",
	}
	serviceV1 := NewService(Options{
		Redis:               cache.NewRedis(redisServer.Addr(), "", 0),
		RedisTimeout:        100 * time.Millisecond,
		AnalysisConfig:      config.DefaultAnalysisConfig(),
		MLClassifier:        classifierV1,
		MLMode:              analysis.MLModeEnforce,
		MLCanary:            MLCanaryConfig{Percent: 100, Seed: "cache-v1"},
		TTLAllowed:          time.Hour,
		TTLSuspicious:       time.Hour,
		TTLBlocked:          time.Hour,
		ConfigReloadEnabled: false,
	})
	serviceV2 := NewService(Options{
		Redis:               cache.NewRedis(redisServer.Addr(), "", 0),
		RedisTimeout:        100 * time.Millisecond,
		AnalysisConfig:      config.DefaultAnalysisConfig(),
		MLClassifier:        classifierV2,
		MLMode:              analysis.MLModeEnforce,
		MLCanary:            MLCanaryConfig{Percent: 100, Seed: "cache-v2"},
		TTLAllowed:          time.Hour,
		TTLSuspicious:       time.Hour,
		TTLBlocked:          time.Hour,
		ConfigReloadEnabled: false,
	})
	defer serviceV1.Close()
	defer serviceV2.Close()

	domain := "login-security-example.com"
	first := serviceV1.Analyze(context.Background(), domain, ClientInfo{}).Result
	if first.Verdict != analysis.VerdictMalicious || classifierV1.calls != 1 {
		t.Fatalf("expected v1 promotion, result=%+v calls=%d", first, classifierV1.calls)
	}
	second := serviceV2.Analyze(context.Background(), domain, ClientInfo{}).Result
	if second.Verdict != analysis.VerdictSuspicious || classifierV2.calls != 1 {
		t.Fatalf("expected v2 cache miss and abstain, result=%+v calls=%d", second, classifierV2.calls)
	}
}

func containsReason(reasons []string, expected string) bool {
	for _, reason := range reasons {
		if reason == expected {
			return true
		}
	}
	return false
}
