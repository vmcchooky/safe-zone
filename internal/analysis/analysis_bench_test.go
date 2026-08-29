package analysis

import (
	"testing"

	"safe-zone/internal/config"
)

func BenchmarkAnalyzeSafeDomain(b *testing.B) {
	analyzer := NewAnalyzerWithBrandStore(config.DefaultAnalysisConfig(), nil)
	for b.Loop() {
		_ = analyzer.Analyze("example.com")
	}
}

func BenchmarkAnalyzeSuspiciousDomain(b *testing.B) {
	analyzer := NewAnalyzerWithBrandStore(config.DefaultAnalysisConfig(), nil)
	for b.Loop() {
		_ = analyzer.Analyze("secure-login-wallet-example.com")
	}
}
