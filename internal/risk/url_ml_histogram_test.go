package risk

import (
	"context"
	"testing"
)

// TestURLMLErrorHistogramKeys pins the fixed keys of the URL-ML error
// histogram through the real status builder. The ops alert contract checker
// (internal/api/handlers/ops_contract_test.go) references these keys by name
// — a map cannot be shape-walked — so a rename here must update
// ops/alerts/safe-zone-alert-rules.yaml in the same change.
func TestURLMLErrorHistogramKeys(t *testing.T) {
	service := newTestServiceWithStore(t)

	status := service.ml.URLMLStatus(context.Background())
	for _, key := range []string{"prediction_error", "invalid_url_context"} {
		if _, ok := status.ErrorHistogram[key]; !ok {
			t.Errorf("error_histogram key %q missing from the live status shape; update the alert contract", key)
		}
	}
}
