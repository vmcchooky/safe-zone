package risk

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	_ = os.Setenv("SAFE_ZONE_ADBLOCK_ENABLED", "false")
	_ = os.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")
	os.Exit(m.Run())
}
