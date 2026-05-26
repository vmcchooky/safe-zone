package config

import (
	"encoding/json"
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
		EntropyThreshold:     3.9,
		EntropyScore:         15,
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
