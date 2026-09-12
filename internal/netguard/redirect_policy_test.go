package netguard

import (
	"net/http"
	"testing"
)

// The redirect policy is the shared enforcement point for feed sync,
// OSINT fetches and whitelist updates: every hop is validated, with IP
// literals decided locally (no DNS) so these cases are deterministic
// offline.
func TestRedirectPolicy(t *testing.T) {
	cases := []struct {
		name         string
		allowPrivate bool
		target       string
		hops         int
		wantBlocked  bool
	}{
		{"public IP allowed", false, "http://93.184.216.34/warning", 1, false},
		{"private IP blocked", false, "http://127.0.0.1/warning", 1, true},
		{"link-local blocked", false, "http://169.254.169.254/x", 1, true},
		{"private allowed on opt-in", true, "http://127.0.0.1/warning", 1, false},
		// Opt-in disables all address checks including link-local: an
		// explicit operator choice, documented here so it stays visible.
		{"link-local allowed on opt-in", true, "http://169.254.169.254/x", 1, false},
		{"non-http scheme blocked", true, "ftp://93.184.216.34/x", 1, true},
		{"hop limit enforced", false, "http://93.184.216.34/x", 11, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tc.target, nil)
			if err != nil {
				t.Fatal(err)
			}
			hops := make([]*http.Request, tc.hops)
			err = RedirectPolicy(tc.allowPrivate)(req, hops)
			if tc.wantBlocked && err == nil {
				t.Fatalf("expected %q to be blocked", tc.target)
			}
			if !tc.wantBlocked && err != nil {
				t.Fatalf("expected %q to pass, got %v", tc.target, err)
			}
			if tc.wantBlocked && err != nil {
				if got := err.Error(); len(got) < 8 ||
					(got[:7] != "blocked" && got[:7] != "stopped") {
					t.Fatalf("blocked hops must explain why, got %q", got)
				}
			}
		})
	}
}
