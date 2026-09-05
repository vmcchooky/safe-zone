package risk

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	_ = os.Setenv("SAFE_ZONE_ADBLOCK_ENABLED", "false")
	_ = os.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")
	// Shadow observation defaults off for every test in this package; tests
	// that need it enabled must opt in explicitly with t.Setenv so a leaked
	// host environment can never flip hermetic fixtures.
	_ = os.Setenv("SAFE_ZONE_ADBLOCK_SHADOW_EXACT_ENABLED", "false")
	os.Exit(m.Run())
}
