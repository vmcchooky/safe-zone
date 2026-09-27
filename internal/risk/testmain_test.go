package risk

import (
	"os"
	"strings"
	"testing"
)

// TestMain makes this package hermetic against the developer's ambient
// environment.
//
// This matters more than it looks. `config.String`/`config.Bool` read straight
// from the process environment, and a workstation that has been used to run the
// stack carries roughly 140 SAFE_ZONE_* variables, several of them
// production-shaped. On 2026-09-27 that produced three failures in this package
// that looked like a missing ML bundle:
//
//	ML bundle load failed: bundle file missing: domain_threat_lgbm.txt
//
// The bundle files were present the whole time. SAFE_ZONE_ML_BUNDLE_DIR pointed
// at /app/models/safe-zone/current, a container path that does not exist on the
// host, and SAFE_ZONE_ML_REQUIRED=true turned that into a startup error. A
// missing-file message sent the investigation after the wrong cause, and the
// failure was then mislabelled as pre-existing for several sessions.
//
// The rule therefore is: nothing from the host environment may reach a test.
// Everything is cleared here, and any test that needs a specific value sets it
// with t.Setenv, which runs after this and wins.
func TestMain(m *testing.M) {
	for _, entry := range os.Environ() {
		name, _, found := strings.Cut(entry, "=")
		if !found || !strings.HasPrefix(name, "SAFE_ZONE_") {
			continue
		}
		_ = os.Unsetenv(name)
	}
	// Shadow observation defaults off for every test in this package; tests
	// that need it enabled must opt in explicitly with t.Setenv so a leaked
	// host environment can never flip hermetic fixtures.
	_ = os.Setenv("SAFE_ZONE_ADBLOCK_SHADOW_EXACT_ENABLED", "false")
	os.Exit(m.Run())
}
