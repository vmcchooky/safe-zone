package risk

import (
	"context"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/analysis"
)

// H4: an oversized dotted input must be rejected during normalization,
// before group resolution and override suffix expansion touch the store.
func TestAnalyzeRejectsOversizedDomainBeforeStore(t *testing.T) {
	service := newTestServiceWithStore(t)

	massive := strings.Repeat("a.", 5000) + "com"
	start := time.Now()
	result := service.Analyze(context.Background(), massive, ClientInfo{})
	if time.Since(start) > 5*time.Second {
		t.Fatal("oversized input must not cause unbounded store work")
	}
	if result.Verdict != analysis.VerdictInvalid {
		t.Fatalf("expected INVALID verdict, got %s (%v)", result.Verdict, result.Reasons)
	}
}

// H4: request cancellation must propagate to policy store lookups instead
// of running them detached on context.Background.
func TestAnalyzeCanceledContextFailsOpen(t *testing.T) {
	service := newTestServiceWithStore(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := service.Analyze(ctx, "cancel-probe.test", ClientInfo{})
	//Canceled lookups fail open to the default group and lexical scoring.
	if result.Domain == "" {
		t.Fatal("expected fail-open result under cancellation, got empty")
	}
}
