package config

import "testing"

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
}
