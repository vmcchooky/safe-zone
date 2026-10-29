package netguard

import (
	"net/http"
	"net/url"
	"testing"
)

// TestValidateParsedURLDefersNonLiteralHostsToDialGate pins the layered
// defense honestly: ValidateURL is a string-level gate. Hostnames that are
// not IP literals for net.ParseIP — the decimal/octal/short-form encodings
// of 127.0.0.1 — pass this gate and are refused later, by ResolveAllowedIPs
// at dial time (or by failing DNS resolution outright). The loopback spellings
// that ARE literals are the control: the gate refuses them regardless of
// userinfo or trailing-dot decoration. If any expectation here changes, the
// dial gate (GuardedTransport.DialContext → ResolveAllowedIPs) remains the
// authority.
func TestValidateParsedURLDefersNonLiteralHostsToDialGate(t *testing.T) {
	tests := []struct {
		raw        string
		wantPasses bool
		note       string
	}{
		{"http://2130706433/", true, "decimal 127.0.0.1 is not an IP literal for net.ParseIP"},
		{"http://0177.0.0.1/", true, "octal 127.0.0.1 is not an IP literal for net.ParseIP"},
		{"http://127.1/", true, "short-form 127.0.0.1 is not an IP literal for net.ParseIP"},
		{"http://foo@127.0.0.1/", false, "userinfo does not hide the loopback literal"},
		{"http://localhost./", false, "trailing dot still means loopback"},
		{"http://127.0.0.1/", false, "plain loopback literal"},
	}
	for _, tt := range tests {
		parsed, err := url.Parse(tt.raw)
		if err != nil {
			t.Fatalf("parse %s: %v", tt.raw, err)
		}
		err = ValidateParsedURL(parsed, false)
		if tt.wantPasses && err != nil {
			t.Errorf("%s (%s): unexpectedly rejected at the string gate: %v", tt.raw, tt.note, err)
		}
		if !tt.wantPasses && err == nil {
			t.Errorf("%s (%s): unexpectedly accepted at the string gate", tt.raw, tt.note)
		}
	}
}

// TestRedirectPolicyIsMethodAgnostic pins that every redirect is
// policy-checked the same way regardless of which method carries it: the
// policy looks at where a hop points, not at the verb.
func TestRedirectPolicyIsMethodAgnostic(t *testing.T) {
	policy := RedirectPolicy(false)

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
		public, err := http.NewRequest(method, "http://198.51.100.10/next", nil)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		if err := policy(public, []*http.Request{public}); err != nil {
			t.Errorf("%s redirect to a public target rejected: %v", method, err)
		}

		private, err := http.NewRequest(method, "http://10.0.0.9/drain", nil)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		if err := policy(private, []*http.Request{private}); err == nil {
			t.Errorf("%s redirect to a private target was allowed", method)
		}
	}
}
