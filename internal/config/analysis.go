package config

import (
	"encoding/json"
	"fmt"
	"strings"

	"safe-zone/internal/logjson"
	"safe-zone/internal/safefile"
)

type AnalysisConfig struct {
	PunycodeScore        int      `json:"punycode_score"`
	LongDomainLength     int      `json:"long_domain_length"`
	LongDomainScore      int      `json:"long_domain_score"`
	HyphenCountThreshold int      `json:"hyphen_count_threshold"`
	HyphenScore          int      `json:"hyphen_score"`
	DigitRatioThreshold  float64  `json:"digit_ratio_threshold"`
	DigitRatioScore      int      `json:"digit_ratio_score"`
	MixedScriptScore     int      `json:"mixed_script_score"`
	Keywords             []string `json:"keywords"`
	KeywordBaseScore     int      `json:"keyword_base_score"`
	KeywordMatchScore    int      `json:"keyword_match_score"`
	KeywordMultipleBonus int      `json:"keyword_multiple_bonus"`
	BrandSpoofingScore   int      `json:"brand_spoofing_score"`
	EntropyThreshold     float64  `json:"entropy_threshold"`
	EntropyScore         int      `json:"entropy_score"`
}

func DefaultAnalysisConfig() AnalysisConfig {
	return AnalysisConfig{
		PunycodeScore:        35,
		LongDomainLength:     24,
		LongDomainScore:      15,
		HyphenCountThreshold: 3,
		HyphenScore:          10,
		DigitRatioThreshold:  0.25,
		DigitRatioScore:      10,
		MixedScriptScore:     25,
		Keywords:             []string{"login", "secure", "verify", "account", "update", "support", "wallet", "dichvucong", "congan", "vneid", "phatnguoi", "xulyphat", "nganhang", "xacthuc", "cungcap"},
		KeywordBaseScore:     15,
		KeywordMatchScore:    10,
		KeywordMultipleBonus: 10,
		BrandSpoofingScore:   50,
		EntropyThreshold:     3.0,
		EntropyScore:         35,
	}
}

func LoadAnalysisConfig(path string) AnalysisConfig {
	defaults := DefaultAnalysisConfig()

	if path == "" {
		return defaults
	}

	data, err := safefile.ReadFileWithin(ConfigFileRoot(), path)
	if err != nil {
		logjson.Warn("analysis config read failed, using defaults", map[string]any{
			"path":  path,
			"error": err.Error(),
		})
		return defaults
	}

	var cfg AnalysisConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		logjson.Warn("analysis config parse failed, using defaults", map[string]any{
			"path":  path,
			"error": err.Error(),
		})
		return defaults
	}

	return cfg
}

func (c AnalysisConfig) GetKeywords() []string {
	// Fallback to defaults if empty due to misconfiguration
	if len(c.Keywords) == 0 {
		return DefaultAnalysisConfig().Keywords
	}
	// Allocate a new slice to avoid concurrent modification / race condition on underlying array
	kw := make([]string, len(c.Keywords))
	for i, k := range c.Keywords {
		kw[i] = strings.ToLower(k)
	}
	return kw
}

func (c AnalysisConfig) Clone() AnalysisConfig {
	c.Keywords = append([]string(nil), c.Keywords...)
	return c
}

func (c AnalysisConfig) Validate() error {
	ranges := []struct {
		name       string
		value, min int
		max        int
	}{
		{"punycode_score", c.PunycodeScore, 0, 100},
		{"long_domain_length", c.LongDomainLength, 10, 253},
		{"long_domain_score", c.LongDomainScore, 0, 100},
		{"hyphen_count_threshold", c.HyphenCountThreshold, 1, 20},
		{"hyphen_score", c.HyphenScore, 0, 100},
		{"digit_ratio_score", c.DigitRatioScore, 0, 100},
		{"mixed_script_score", c.MixedScriptScore, 0, 100},
		{"keyword_base_score", c.KeywordBaseScore, 0, 100},
		{"keyword_match_score", c.KeywordMatchScore, 0, 100},
		{"keyword_multiple_bonus", c.KeywordMultipleBonus, 0, 100},
		{"brand_spoofing_score", c.BrandSpoofingScore, 0, 100},
		{"entropy_score", c.EntropyScore, 0, 100},
	}
	for _, item := range ranges {
		if item.value < item.min || item.value > item.max {
			return fmt.Errorf("%s must be between %d and %d", item.name, item.min, item.max)
		}
	}
	if c.DigitRatioThreshold < 0 || c.DigitRatioThreshold > 1 {
		return fmt.Errorf("digit_ratio_threshold must be between 0 and 1")
	}
	if c.EntropyThreshold < 0 || c.EntropyThreshold > 8 {
		return fmt.Errorf("entropy_threshold must be between 0 and 8")
	}
	if len(c.Keywords) == 0 || len(c.Keywords) > 200 {
		return fmt.Errorf("keywords must contain between 1 and 200 entries")
	}
	seen := make(map[string]struct{}, len(c.Keywords))
	for _, keyword := range c.Keywords {
		trimmed := strings.TrimSpace(keyword)
		if keyword != trimmed {
			return fmt.Errorf("keywords must not contain leading or trailing whitespace")
		}
		keyword = strings.ToLower(trimmed)
		if keyword == "" || len(keyword) > 64 {
			return fmt.Errorf("keywords must be non-empty and at most 64 characters")
		}
		if _, exists := seen[keyword]; exists {
			return fmt.Errorf("keywords must not contain duplicates")
		}
		seen[keyword] = struct{}{}
	}
	return nil
}
