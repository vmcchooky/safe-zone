package risk

import (
	"strings"
	"testing"

	"safe-zone/internal/config"
)

// An unsupported OSINT mode must fail startup before any store or cache is
// created so a mistyped value never silently changes lookup behavior.
func TestNewServiceFromEnvForRoleERejectsInvalidOSINTMode(t *testing.T) {
	t.Setenv("SAFE_ZONE_OSINT_MODE", "turbo_mode")

	_, err := NewServiceFromEnvForRoleE("core-api")
	if err == nil {
		t.Fatal("expected startup failure for unsupported OSINT mode")
	}
	if !strings.Contains(err.Error(), "unsupported OSINT mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// A configured-but-failed operational baseline must be reported as fail-open
// with a stable error class; a missing baseline must not claim failure; a
// loaded baseline must report Loaded without fail-open.
func TestURLMLOpsBaselineStatusReflectsFailure(t *testing.T) {
	failed := NewService(Options{
		AnalysisConfig:           config.DefaultAnalysisConfig(),
		URLOpsBaselineFailed:     true,
		URLOpsBaselineErrorClass: "baseline_load",
	})
	defer func() { _ = failed.Close() }()

	status := failed.urlMLOpsBaselineStatus()
	if status.Loaded || !status.FailOpen || status.ErrorClass != "baseline_load" {
		t.Fatalf("expected fail-open status, got %+v", status)
	}

	notConfigured := NewService(Options{AnalysisConfig: config.DefaultAnalysisConfig()})
	defer func() { _ = notConfigured.Close() }()

	status = notConfigured.urlMLOpsBaselineStatus()
	if status.FailOpen || status.ErrorClass != "" {
		t.Fatalf("expected clean status when no baseline is configured, got %+v", status)
	}

	loaded := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		URLOpsBaseline: &URLOperationalBaseline{Path: "base.json", SHA256: "abc"},
	})
	defer func() { _ = loaded.Close() }()

	status = loaded.urlMLOpsBaselineStatus()
	if !status.Loaded || status.FailOpen {
		t.Fatalf("expected loaded baseline status, got %+v", status)
	}
}
