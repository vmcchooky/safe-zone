package handlers

import (
	"os"
	"strings"
	"testing"
)

// TestMain makes this package hermetic against the developer's ambient
// environment, following the precedent in internal/risk.
//
// Two variables matter here. SAFE_ZONE_TRUSTED_PROXIES and
// SAFE_ZONE_FORCE_SECURE_COOKIES both feed the session cookie's Secure
// attribute, and SAFE_ZONE_ENV feeds the production default for it. A
// workstation used to run the stack carries all three, production-shaped. A
// test that expects the local default would then get the production behaviour
// and pass or fail for the wrong reason.
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
