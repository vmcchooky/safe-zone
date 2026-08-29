package risk

import (
	"strings"
	"testing"
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
