package ai

import (
	"context"

	"safe-zone/internal/analysis"
)

// Provider defines the interface that all AI models must implement
// to perform secondary refinement of domain risk classifications.
type Provider interface {
	// Refine analyzes a domain in context of its current heuristic analysis results
	// and returns a revised result with a verdict, confidence score, and justification.
	Refine(ctx context.Context, domain string, current analysis.Result) (analysis.Result, error)

	// Enabled returns true if the provider has all necessary configuration (like API keys)
	// and is ready to accept requests.
	Enabled() bool
}
