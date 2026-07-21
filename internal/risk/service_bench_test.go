package risk

import (
	"context"
	"testing"
	"time"

	"safe-zone/internal/config"
)

func BenchmarkAnalyzeNoRedis(b *testing.B) {
	service := NewService(Options{
		RedisTimeout:   10 * time.Millisecond,
		TTLAllowed:     time.Hour,
		TTLSuspicious:  time.Hour,
		TTLBlocked:     time.Hour,
		AnalysisConfig: config.DefaultAnalysisConfig(),
	})
	defer service.Close()

	ctx := context.Background()
	client := ClientInfo{}
	b.ReportAllocs()
	for b.Loop() {
		_ = service.Analyze(ctx, "secure-login-wallet-example.com", client)
	}
}
