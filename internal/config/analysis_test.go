package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnalysisConfigValidate(t *testing.T) {
	cfg := DefaultAnalysisConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should be valid: %v", err)
	}

	cfg.DigitRatioThreshold = 1.1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid digit ratio threshold")
	}

	cfg = DefaultAnalysisConfig()
	cfg.Keywords = append(cfg.Keywords, cfg.Keywords[0])
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected duplicate keywords to be rejected")
	}

	cfg = DefaultAnalysisConfig()
	cfg.Keywords[0] = " login "
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected surrounding keyword whitespace to be rejected")
	}

	cfg = DefaultAnalysisConfig()
	cfg.Keywords = nil
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected empty keywords to be allowed: %v", err)
	}
}

func TestLoadAnalysisConfigPreservesDefaultKeywordsWhenFieldOmitted(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "analysis.json")
	if err := os.WriteFile(path, []byte(`{"long_domain_length":42}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAFE_ZONE_CONFIG_FILE_ROOT", root)

	cfg := LoadAnalysisConfig("analysis.json")
	if cfg.LongDomainLength != 42 {
		t.Fatalf("expected overridden long_domain_length, got %d", cfg.LongDomainLength)
	}
	if len(cfg.Keywords) != len(DefaultAnalysisConfig().Keywords) {
		t.Fatalf("expected default keywords to be preserved, got %d", len(cfg.Keywords))
	}
}

func TestLoadAnalysisConfigAllowsExplicitEmptyKeywords(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "analysis.json")
	if err := os.WriteFile(path, []byte(`{"keywords":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAFE_ZONE_CONFIG_FILE_ROOT", root)

	cfg := LoadAnalysisConfig("analysis.json")
	if cfg.Keywords == nil {
		t.Fatal("expected explicit empty keywords slice to be preserved")
	}
	if len(cfg.Keywords) != 0 {
		t.Fatalf("expected explicit empty keywords, got %v", cfg.Keywords)
	}
}
