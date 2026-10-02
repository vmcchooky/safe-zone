package ratelimit

import (
	"os"
	"strings"
	"testing"
)

// TestMain makes this package hermetic against the developer's ambient
// environment, following the precedent in internal/risk.
//
// It matters for one variable in particular. SAFE_ZONE_TRUSTED_PROXIES is
// read once in init(), before any test runs, so its value is the one the
// developer happens to have exported. A workstation used to run the Compose
// stack typically carries the bridge list, which would silently make every
// test in this package trust the Docker network — and any test that forgets to
// pin the list with SetTrustedProxies would then be asserting the wrong
// behaviour while still passing.
//
// The rule is the same as internal/risk: nothing from the host environment
// reaches a test, and a test that needs a value sets it with t.Setenv or
// SetTrustedProxies, both of which run after this.
func TestMain(m *testing.M) {
	for _, entry := range os.Environ() {
		name, _, found := strings.Cut(entry, "=")
		if !found || !strings.HasPrefix(name, "SAFE_ZONE_") {
			continue
		}
		_ = os.Unsetenv(name)
	}
	os.Exit(m.Run())
}
