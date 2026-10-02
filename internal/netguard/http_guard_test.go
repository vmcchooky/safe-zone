package netguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"testing"
)

// The gap: net.IP's predicates cover IsUnspecified only for exactly 0.0.0.0,
// but Linux routes the whole 0.0.0.0/8 to loopback, so http://0.0.0.1/ is a
// request to localhost and must be rejected.
func TestIsBlockedIPRejectsNonRoutableV4(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		blocked bool
	}{
		// 0.0.0.0/8 routes to loopback on Linux.
		{"this-network exact", "0.0.0.0", true},
		{"this-network low", "0.0.0.1", true},
		{"this-network mid", "0.1.2.3", true},
		{"this-network high", "0.255.255.255", true},
		// IETF protocol assignments.
		{"192.0.0.0/24 first", "192.0.0.0", true},
		{"192.0.0.0/24 mid", "192.0.0.170", true},
		{"192.0.0.0/24 last", "192.0.0.255", true},
		// Benchmarking.
		{"198.18.0.0/15 first", "198.18.0.0", true},
		{"198.18.0.0/15 mid", "198.19.255.1", true},
		{"198.18.0.0/15 last", "198.19.255.255", true},
		// Reserved, including the broadcast address.
		{"240.0.0.0/4 first", "240.0.0.0", true},
		{"240.0.0.0/4 mid", "250.1.2.3", true},
		{"limited broadcast", "255.255.255.255", true},

		// Adjacent routable space must stay usable.
		{"just above this-network", "1.0.0.1", false},
		{"just below 192.0.0.0/24", "191.255.255.255", false},
		{"just above 192.0.0.0/24", "192.0.1.1", false},
		{"just below 198.18.0.0/15", "198.17.255.255", false},
		{"just above 198.18.0.0/15", "198.20.0.0", false},
		// There is no routable address just below 240.0.0.0/4: 224-239 is
		// multicast, which was already blocked before this range was added.
		{"top of multicast", "239.255.255.255", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("cannot parse %q", tc.ip)
			}
			if got := IsBlockedIP(ip); got != tc.blocked {
				t.Fatalf("IsBlockedIP(%s) = %v, want %v", tc.ip, got, tc.blocked)
			}
		})
	}
}

// Documentation ranges must stay reachable: they are used pervasively in
// fixtures and examples, and blocking them would break suites without adding
// protection. One of them is 0.0.0.0/8's neighbour 1.0.0.0/8? no — TEST-NET-1
// is 192.0.2.0/24, which sits just above the IETF protocol block.
func TestDocumentationRangesRemainReachable(t *testing.T) {
	for _, ip := range []string{"192.0.2.1", "198.51.100.1", "203.0.113.1", "198.20.0.1"} {
		if IsBlockedIP(net.ParseIP(ip)) {
			t.Fatalf("%s is a documentation range and must stay usable in fixtures", ip)
		}
	}
}

// A nil address is not a routable destination. It was not handled before, and
// a nil reaching the predicate previously fell through to "allowed".
func TestIsBlockedIPTreatsNilAsBlocked(t *testing.T) {
	if !IsBlockedIP(nil) {
		t.Fatal("a nil address must be treated as blocked, not as allowed")
	}
}

// A guarded transport must not consult the ambient proxy environment. With a
// proxy configured, DialContext receives the *proxy's* address, so the
// destination the guard exists to check is never the one validated — and the
// proxy is public, so the check passes and the guard silently does nothing.
func TestGuardedTransportIgnoresTheAmbientProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://198.51.100.1:3128")
	t.Setenv("HTTPS_PROXY", "http://198.51.100.1:3128")
	t.Setenv("ALL_PROXY", "http://198.51.100.1:3128")
	t.Setenv(OutboundProxyEnv, "")

	transport, ok := GuardedTransport(nil, false).(*http.Transport)
	if !ok {
		t.Fatal("GuardedTransport should return an *http.Transport for a nil base")
	}
	if transport.Proxy != nil {
		t.Fatal("a guarded transport must not carry a proxy function: the proxy address would be validated instead of the destination")
	}
}

// The opt-in has to actually restore proxying, otherwise an egress-only
// deployment silently stops fetching anything.
func TestGuardedTransportHonoursTheExplicitProxyOptIn(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://198.51.100.1:3128")
	t.Setenv(OutboundProxyEnv, "true")

	transport, ok := GuardedTransport(nil, false).(*http.Transport)
	if !ok {
		t.Fatal("GuardedTransport should return an *http.Transport for a nil base")
	}
	if transport.Proxy == nil {
		t.Fatal("SAFE_ZONE_OUTBOUND_PROXY=true must restore proxying")
	}

	req, err := http.NewRequest(http.MethodGet, "https://example.test/feed", nil)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, err := transport.Proxy(req)
	if err != nil {
		t.Fatalf("proxy func returned an error: %v", err)
	}
	if proxyURL == nil || proxyURL.Hostname() != "198.51.100.1" {
		t.Fatalf("proxy = %v, want the HTTPS_PROXY host", proxyURL)
	}
}

// A base that is not an *http.Transport cannot be address-checked, so the
// guard refuses it. It used to be wrapped in a validating shim that looked
// protected while the custom RoundTripper kept its own connection policy —
// including whether it proxied, which is the hole this guard exists to close.
func TestGuardedTransportRefusesACustomBaseRoundTripper(t *testing.T) {
	dialed := false
	custom := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		dialed = true
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})

	guarded := GuardedTransport(custom, false)
	req, err := http.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guarded.RoundTrip(req); err == nil {
		t.Fatal("a custom base RoundTripper must be refused, not wrapped")
	} else if !errors.Is(err, ErrUnguardableTransport) {
		t.Fatalf("error = %v, want it to wrap ErrUnguardableTransport", err)
	}
	if dialed {
		t.Fatal("the custom RoundTripper was invoked: the guard let the request through")
	}
}

// The refusal must not depend on the proxy environment either way.
func TestGuardedTransportRefusesCustomBaseWithProxyConfigured(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://198.51.100.1:3128")
	t.Setenv(OutboundProxyEnv, "")

	guarded := GuardedTransport(roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("should never be called")
	}), false)
	req, err := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guarded.RoundTrip(req); !errors.Is(err, ErrUnguardableTransport) {
		t.Fatalf("error = %v, want ErrUnguardableTransport", err)
	}
}

// The opt-in warning is a one-shot latch, so it must track the configuration:
// turning the opt-in off clears it, and a later re-enable warns again instead of
// being swallowed.
func TestProxyBypassWarningTracksConfiguration(t *testing.T) {
	t.Cleanup(func() { t.Setenv(OutboundProxyEnv, "") })

	t.Setenv(OutboundProxyEnv, "true")
	if GuardedTransport(nil, false).(*http.Transport).Proxy == nil {
		t.Fatal("opt-in must restore proxying")
	}
	if !proxyBypassWarned.Load() {
		t.Fatal("enabling the opt-in must raise the warning")
	}
	// Still enabled: the warning must not repeat.
	_ = GuardedTransport(nil, false)
	if !proxyBypassWarned.Load() {
		t.Fatal("the warned flag must stay set while the opt-in is on")
	}

	// Turning it off clears the latch, so a re-enable is not silent.
	t.Setenv(OutboundProxyEnv, "false")
	if GuardedTransport(nil, false).(*http.Transport).Proxy != nil {
		t.Fatal("the opt-in must remove proxying")
	}
	if proxyBypassWarned.Load() {
		t.Fatal("disabling the opt-in must clear the warned flag")
	}

	t.Setenv(OutboundProxyEnv, "true")
	_ = GuardedTransport(nil, false)
	if !proxyBypassWarned.Load() {
		t.Fatal("re-enabling the opt-in must warn again, not be swallowed by a stale latch")
	}
}

// A request for a blocked destination must be refused even with a proxy
// configured, at every address class the guard now covers.
func TestBlockedDestinationIsRefusedEvenWithProxyConfigured(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://198.51.100.1:3128")
	t.Setenv(OutboundProxyEnv, "")

	client := NewHTTPClient(nil, 0, false)
	for _, target := range []string{
		"http://0.0.0.1/admin",
		"http://10.0.0.5/",
		"http://100.64.0.1/",
		"http://[2002:7f00:0001::1]/", // 6to4 form of 127.0.0.1
	} {
		resp, err := client.Get(target)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("a request to %s must be refused, not proxied", target)
		}
	}
}

// Every caller of the rule must agree. The osint and tlsinspect copies had
// drifted from netguard's twice, so an address one rejected could be accepted
// by another.
func TestBlockedPredicateIsConsistentAcrossCallers(t *testing.T) {
	addresses := []string{
		"127.0.0.1", "0.0.0.1", "0.1.2.3", "10.0.0.1", "192.168.1.1",
		"172.16.0.1", "169.254.169.254", "100.64.0.1", "100.127.255.255",
		"192.0.0.170", "198.18.0.1", "240.0.0.1", "255.255.255.255",
		"224.0.0.1", "::1", "::", "fe80::1", "fc00::1", "ff02::1", "::ffff:127.0.0.1",
		"1.1.1.1", "8.8.8.8", "203.0.113.1", "2606:4700::1111",
	}
	for _, address := range addresses {
		t.Run(address, func(t *testing.T) {
			ip := net.ParseIP(address)
			if ip == nil {
				t.Fatalf("cannot parse %q", address)
			}
			want := IsBlockedIP(ip)

			// The same answer must come out of the checks the fetches actually
			// run, both at the string level and after resolution.
			if _, err := ResolveAllowedIPs(context.Background(), address, false); (err != nil) != want {
				t.Fatalf("ResolveAllowedIPs(%s) error = %v, but IsBlockedIP = %v", address, err, want)
			}
			parsed, parseErr := url.Parse("http://" + net.JoinHostPort(normalizeHost(address), "") + "/x")
			if parseErr != nil {
				t.Fatalf("parse %q: %v", address, parseErr)
			}
			if err := ValidateParsedURL(parsed, false); (err != nil) != want {
				t.Fatalf("ValidateParsedURL(%s) error = %v, but IsBlockedIP = %v", address, err, want)
			}
		})
	}
}

// IPv4-mapped IPv6 forms must resolve to the same verdict as the bare address,
// otherwise ::ffff:127.0.0.1 walks past a check that 127.0.0.1 would not.
func TestIPv4MappedAddressesMatchTheirBareForm(t *testing.T) {
	pairs := [][2]string{
		{"::ffff:127.0.0.1", "127.0.0.1"},
		{"::ffff:10.0.0.1", "10.0.0.1"},
		{"::ffff:0.0.0.1", "0.0.0.1"},
		{"::ffff:100.64.0.1", "100.64.0.1"},
		{"::ffff:1.1.1.1", "1.1.1.1"},
	}
	for _, pair := range pairs {
		mapped, bare := net.ParseIP(pair[0]), net.ParseIP(pair[1])
		if got, want := IsBlockedIP(mapped), IsBlockedIP(bare); got != want {
			t.Fatalf("IsBlockedIP(%s) = %v but IsBlockedIP(%s) = %v", pair[0], got, pair[1], want)
		}
	}
}

// A private opt-in still has to allow private targets, otherwise a deployment
// that legitimately fetches from an internal host is broken by this change.
func TestAllowPrivateStillPermitsInternalTargets(t *testing.T) {
	for _, address := range []string{"10.0.0.1", "192.168.1.1", "0.0.0.1", "100.64.0.1"} {
		if _, err := ResolveAllowedIPs(context.Background(), address, true); err != nil {
			t.Fatalf("allowPrivate must permit %s, got %v", address, err)
		}
	}
}

// Sanity: an ordinary public destination is not blocked, i.e. the guard did not
// become blanket-deny. A literal address is used rather than a test server
// because httptest listens on loopback, which this guard is supposed to
// refuse — that is the behaviour TestGuardedTransportIgnoresTheAmbientProxy
// relies on.
func TestPublicDestinationIsNotBlockedByTheGuard(t *testing.T) {
	for _, address := range []string{"1.1.1.1", "8.8.8.8", "203.0.113.1", "2606:4700::1111"} {
		ips, err := ResolveAllowedIPs(context.Background(), address, false)
		if err != nil {
			t.Fatalf("public address %s must be allowed, got %v", address, err)
		}
		if len(ips) == 0 {
			t.Fatalf("public address %s resolved to nothing", address)
		}
		parsed, parseErr := url.Parse("http://" + net.JoinHostPort(address, "") + "/x")
		if parseErr != nil {
			t.Fatalf("parse %q: %v", address, parseErr)
		}
		if err := ValidateParsedURL(parsed, false); err != nil {
			t.Fatalf("ValidateParsedURL(%s) = %v, want nil", address, err)
		}
	}
}
