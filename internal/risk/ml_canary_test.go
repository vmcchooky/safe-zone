package risk

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/config"
)

func TestMLCanarySelectorIsDeterministicAndNormalized(t *testing.T) {
	canary := MLCanaryConfig{Percent: 5, Seed: "phase5-selector"}
	if err := canary.validate(); err != nil {
		t.Fatal(err)
	}

	first := canary.Eligible("Login-Security-Example.com.")
	for i := 0; i < 20; i++ {
		if got := canary.Eligible("login-security-example.com"); got != first {
			t.Fatalf("selector changed for equivalent normalized domain: first=%v got=%v", first, got)
		}
	}
	if canary.revision() == "" {
		t.Fatal("configured selector must expose a revision")
	}
}

func TestMLCanarySelectorApproximatesConfiguredHashSpace(t *testing.T) {
	canary := MLCanaryConfig{Percent: 10, Seed: "phase5-distribution"}
	selected := 0
	const total = 10_000
	for i := 0; i < total; i++ {
		if canary.Eligible(fmt.Sprintf("candidate-%05d.example.com", i)) {
			selected++
		}
	}
	if selected < 850 || selected > 1_150 {
		t.Fatalf("10%% selector selected %d/%d domains", selected, total)
	}
}

func TestMLShadowObservesCanaryWithoutChangingVerdict(t *testing.T) {
	fake := &fakeMLClassifier{decision: analysis.MLDecision{
		Probability: 0.99,
		Action:      analysis.MLActionPromoteMalicious,
	}}
	service := NewService(Options{
		AIProvider:          "",
		AnalysisConfig:      config.DefaultAnalysisConfig(),
		MLClassifier:        fake,
		MLMode:              analysis.MLModeShadow,
		MLCanary:            MLCanaryConfig{Percent: 100, Seed: "shadow-observation"},
		TTLAllowed:          time.Hour,
		TTLSuspicious:       time.Hour,
		TTLBlocked:          time.Hour,
		ConfigReloadEnabled: false,
	})
	defer service.Close()

	result := service.Analyze(context.Background(), "login-security-example.com", ClientInfo{}).Result
	if result.Verdict != analysis.VerdictSuspicious {
		t.Fatalf("shadow canary changed verdict to %s", result.Verdict)
	}
	status := service.MLStatus()
	if !status.Canary.Configured || status.Canary.SelectedPredictions != 1 || status.Canary.SelectedWouldBlock != 1 {
		t.Fatalf("unexpected canary observation: %+v", status.Canary)
	}
	if status.EnforcePromotions != 0 || status.Canary.EnforceSuppressed != 0 {
		t.Fatalf("shadow performed enforcement: %+v", status)
	}
}

func TestMLEnforceSuppressesPredictionOutsideCanary(t *testing.T) {
	canary := MLCanaryConfig{Percent: 1, Seed: "bounded-enforce"}
	domain := findDomainByEligibility(t, canary, false)
	fake := &fakeMLClassifier{decision: analysis.MLDecision{
		Probability: 0.99,
		Action:      analysis.MLActionPromoteMalicious,
	}}
	service := NewService(Options{
		AIProvider:          "",
		AnalysisConfig:      config.DefaultAnalysisConfig(),
		MLClassifier:        fake,
		MLMode:              analysis.MLModeEnforce,
		MLCanary:            canary,
		TTLAllowed:          time.Hour,
		TTLSuspicious:       time.Hour,
		TTLBlocked:          time.Hour,
		ConfigReloadEnabled: false,
	})
	defer service.Close()

	result := service.Analyze(context.Background(), domain, ClientInfo{}).Result
	if result.Verdict != analysis.VerdictSuspicious {
		t.Fatalf("excluded canary domain changed verdict to %s", result.Verdict)
	}
	status := service.MLStatus()
	if status.EnforcePromotions != 0 || status.Canary.EnforceSuppressed != 1 || status.Canary.ExcludedPredictions != 1 {
		t.Fatalf("unexpected bounded enforce telemetry: %+v", status)
	}
}

func TestMLPolicyRevisionSeparatesShadowAndEnforceCache(t *testing.T) {
	redisServer := miniredis.RunT(t)
	classifier := &fakeMLClassifier{
		decision: analysis.MLDecision{Probability: 0.95, Action: analysis.MLActionPromoteMalicious},
		revision: "shared-model",
	}
	base := Options{
		RedisTimeout:        100 * time.Millisecond,
		AnalysisConfig:      config.DefaultAnalysisConfig(),
		MLClassifier:        classifier,
		TTLAllowed:          time.Hour,
		TTLSuspicious:       time.Hour,
		TTLBlocked:          time.Hour,
		ConfigReloadEnabled: false,
	}
	shadowOptions := base
	shadowOptions.Redis = cache.NewRedis(redisServer.Addr(), "", 0)
	shadowOptions.MLMode = analysis.MLModeShadow
	shadowOptions.MLCanary = MLCanaryConfig{Percent: 10, Seed: "cache-policy"}
	enforceOptions := base
	enforceOptions.Redis = cache.NewRedis(redisServer.Addr(), "", 0)
	enforceOptions.MLMode = analysis.MLModeEnforce
	enforceOptions.MLCanary = MLCanaryConfig{Percent: 100, Seed: "cache-policy"}

	shadow := NewService(shadowOptions)
	enforce := NewService(enforceOptions)
	defer shadow.Close()
	defer enforce.Close()

	domain := "login-security-example.com"
	first := shadow.Analyze(context.Background(), domain, ClientInfo{})
	second := enforce.Analyze(context.Background(), domain, ClientInfo{})
	if first.Verdict != analysis.VerdictSuspicious || second.Verdict != analysis.VerdictMalicious {
		t.Fatalf("mode-specific cache isolation failed: shadow=%s enforce=%s", first.Verdict, second.Verdict)
	}
	if second.CacheHit {
		t.Fatal("enforce reused a shadow cache entry")
	}
	if shadow.MLStatus().PolicyRevision == enforce.MLStatus().PolicyRevision {
		t.Fatal("shadow and enforce must have different ML policy revisions")
	}
}

func findDomainByEligibility(t *testing.T, canary MLCanaryConfig, want bool) string {
	t.Helper()
	for i := 0; i < 10_000; i++ {
		domain := fmt.Sprintf("login-security-%05d.example.com", i)
		if canary.Eligible(domain) == want {
			return domain
		}
	}
	t.Fatalf("unable to find domain with canary eligibility %v", want)
	return ""
}
