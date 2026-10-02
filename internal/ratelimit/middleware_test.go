package ratelimit

import (
	"net/http"
	"testing"
)

// withTrustedProxies installs an explicit trusted proxy list for one test and
// restores the process default afterwards.
func withTrustedProxies(t *testing.T, cidrs ...string) {
	t.Helper()
	previous := TrustedProxies()
	parsed, err := ParseTrustedProxies(joinCIDRs(cidrs))
	if err != nil {
		t.Fatalf("parse trusted proxies: %v", err)
	}
	SetTrustedProxies(parsed)
	t.Cleanup(func() { SetTrustedProxies(previous) })
}

func joinCIDRs(cidrs []string) string {
	out := ""
	for i, c := range cidrs {
		if i > 0 {
			out += ","
		}
		out += c
	}
	return out
}

// A forwarded chain in which every hop is a trusted proxy has no
// identifiable client. The leftmost entry is the value furthest from the
// socket and the most attacker-controlled one in the header, so returning it
// let a client pick its own rate-limit key. This must fail closed to the
// socket address instead.
func TestFullyTrustedForwardedChainFailsClosedToSocketAddress(t *testing.T) {
	previous := TrustedProxies()
	t.Cleanup(func() { SetTrustedProxies(previous) })

	loopback, err := ParseTrustedProxies("127.0.0.0/8,::1/128,10.0.0.0/8,192.168.0.0/16")
	if err != nil {
		t.Fatalf("parse list: %v", err)
	}
	SetTrustedProxies(loopback)

	cases := []struct {
		name       string
		remoteAddr string
		xff        string
	}{
		{"every hop private", "127.0.0.1:12345", "10.0.0.9, 192.168.1.10"},
		{"single trusted hop", "127.0.0.1:12345", "192.168.1.10"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.RemoteAddr = tc.remoteAddr
			req.Header.Set("X-Forwarded-For", tc.xff)

			if got, want := ClientIP(req), hostOnly(tc.remoteAddr); got != want {
				t.Fatalf("ClientIP = %s, want the socket address %s: a fully trusted chain must not yield a client-chosen IP", got, want)
			}
		})
	}
}

// A public client behind the bridge proxy is unaffected: its own address is
// not in the trusted list, so the rightmost non-trusted hop is still correct.
// This is the case the Compose default is sized for.
func TestPublicClientBehindBridgeIsUnaffected(t *testing.T) {
	withTrustedProxies(t, "127.0.0.0/8", "::1/128", "172.16.0.0/12")

	cases := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{"no spoofing", "172.18.0.5:5000", "203.0.113.77", "203.0.113.77"},
		// The client prepends a forged hop; Caddy appends the real one. The
		// real address is not trusted, so the walk stops there and the forge
		// is discarded.
		{"client prepends a forged hop", "172.18.0.5:5000", "6.6.6.6, 203.0.113.77", "203.0.113.77"},
		{"chained internal proxies", "172.18.0.5:5000", "6.6.6.6, 203.0.113.77, 172.20.0.4", "203.0.113.77"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.RemoteAddr = tc.remoteAddr
			req.Header.Set("X-Forwarded-For", tc.xff)

			if got := ClientIP(req); got != tc.want {
				t.Fatalf("ClientIP = %s, want %s", got, tc.want)
			}
		})
	}
}

// Known residual, pinned deliberately: a client whose own source address is
// inside a trusted range is indistinguishable from a proxy hop, so the walk
// skips it and honours whatever sits to its left. No header heuristic can
// separate those two cases, so the mitigation is the trust list itself —
// prefer a /32 for the proxy over a subnet. This test exists so that anyone
// narrowing or widening the list finds out that this property is what they
// are trading, and so a future change to the walk order cannot silently alter
// it.
func TestClientInsideTrustedRangeCanStillForge(t *testing.T) {
	withTrustedProxies(t, "127.0.0.0/8", "::1/128", "172.16.0.0/12")

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	// A client on the bridge network, so Caddy appends a bridge address.
	req.RemoteAddr = "172.18.0.5:5000"
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 172.19.0.77")

	if got := ClientIP(req); got != "6.6.6.6" {
		t.Fatalf("ClientIP = %s, want 6.6.6.6 (documented residual)", got)
	}

	// Trusting the proxy address exactly closes it: the client address is no
	// longer in the list, so it is not skipped.
	withTrustedProxies(t, "127.0.0.0/8", "::1/128", "172.18.0.5/32")
	exact, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	exact.RemoteAddr = "172.18.0.5:5000"
	exact.Header.Set("X-Forwarded-For", "6.6.6.6, 172.19.0.77")
	if got := ClientIP(exact); got != "172.19.0.77" {
		t.Fatalf("with a /32 proxy list ClientIP = %s, want 172.19.0.77: an exact proxy address closes the forgery", got)
	}
}

// Overly broad prefixes effectively disable forwarded-header filtering, so
// they must be detected even though the operator asked for them.
func TestOverBroadProxyPrefixesAreDetected(t *testing.T) {
	broad := []string{"0.0.0.0/0", "::/0", "10.0.0.0/8", "0.0.0.0/7"}
	for _, cidr := range broad {
		nets, err := ParseTrustedProxies(cidr)
		if err != nil {
			t.Fatalf("parse %s: %v", cidr, err)
		}
		if !overBroadProxyPrefix(nets[0]) {
			t.Fatalf("%s must be reported as over-broad", cidr)
		}
	}

	tight := []string{"172.16.0.0/12", "192.168.1.0/24", "127.0.0.0/8", "203.0.113.0/24"}
	for _, cidr := range tight {
		nets, err := ParseTrustedProxies(cidr)
		if err != nil {
			t.Fatalf("parse %s: %v", cidr, err)
		}
		if overBroadProxyPrefix(nets[0]) {
			t.Fatalf("%s is a reasonable proxy range and must not be reported", cidr)
		}
	}
}

func TestClientIP(t *testing.T) {
	// The default trust list is loopback-only, so the forwarded-header cases
	// below have to opt the proxy network in explicitly. This is the point of
	// SAFE_ZONE_TRUSTED_PROXIES: a peer is trusted because the operator said
	// so, not because it happens to sit in a private range.
	withTrustedProxies(t, "127.0.0.0/8", "::1/128", "172.16.0.0/12", "10.0.0.0/8", "192.168.0.0/16")

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xri        string
		expected   string
	}{
		{
			name:       "no headers, non-trusted proxy",
			remoteAddr: "203.0.113.1:12345",
			expected:   "203.0.113.1",
		},
		{
			name:       "fake xff from non-trusted proxy",
			remoteAddr: "203.0.113.1:12345",
			xff:        "1.2.3.4",
			expected:   "203.0.113.1",
		},
		{
			name:       "fake xri from non-trusted proxy",
			remoteAddr: "203.0.113.1:12345",
			xri:        "1.2.3.4",
			expected:   "203.0.113.1",
		},
		{
			name:       "xff from trusted proxy (localhost)",
			remoteAddr: "127.0.0.1:12345",
			xff:        "1.2.3.4",
			expected:   "1.2.3.4",
		},
		{
			name:       "xff from trusted proxy (docker network)",
			remoteAddr: "172.17.0.2:54321",
			xff:        "8.8.8.8, 1.2.3.4",
			expected:   "1.2.3.4",
		},
		{
			name:       "spoofed xff from trusted proxy uses rightmost client hop",
			remoteAddr: "127.0.0.1:12345",
			xff:        "1.2.3.4, 198.51.100.23",
			expected:   "198.51.100.23",
		},
		{
			name:       "multiple trusted proxies return first untrusted hop from right",
			remoteAddr: "127.0.0.1:12345",
			xff:        "198.51.100.23, 10.0.0.9",
			expected:   "198.51.100.23",
		},
		{
			name:       "all trusted xff hops fall back to the socket address",
			remoteAddr: "127.0.0.1:12345",
			xff:        "192.168.1.10, 10.0.0.9",
			expected:   "127.0.0.1",
		},
		{
			name:       "xri from trusted proxy",
			remoteAddr: "10.0.0.5:8080",
			xri:        "9.9.9.9",
			expected:   "9.9.9.9",
		},
		{
			name:       "xff and xri from trusted proxy (xff wins)",
			remoteAddr: "192.168.1.100:12345",
			xff:        "1.1.1.1",
			xri:        "2.2.2.2",
			expected:   "1.1.1.1",
		},
		{
			name:       "invalid xff falls back to xri",
			remoteAddr: "127.0.0.1:12345",
			xff:        "not-an-ip",
			xri:        "2.2.2.2",
			expected:   "2.2.2.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				req.Header.Set("X-Real-IP", tt.xri)
			}

			ip := ClientIP(req)
			if ip != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, ip)
			}
		})
	}
}

// The regression this default exists for: with the whole RFC1918 space
// trusted, any LAN host could choose its own rate-limit key and defeat the
// per-IP login limiter. With the loopback-only default a private-range peer is
// untrusted, so its forwarded headers are discarded and the socket address is
// used as the key.
func TestPrivateRangePeerCannotForgeItsOwnClientIP(t *testing.T) {
	previous := TrustedProxies()
	t.Cleanup(func() { SetTrustedProxies(previous) })
	SetTrustedProxies(nil) // exercise the shipped default: trust nobody

	spoofed := []string{"1.2.3.4", "8.8.8.8", "127.0.0.1"}
	for _, peer := range []string{"10.0.0.5:8080", "172.17.0.2:54321", "192.168.1.100:12345"} {
		for _, forged := range spoofed {
			req, err := http.NewRequest("GET", "/", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.RemoteAddr = peer
			req.Header.Set("X-Forwarded-For", forged)
			req.Header.Set("X-Real-IP", forged)

			if got := ClientIP(req); got != hostOnly(peer) {
				t.Fatalf("peer %s forged %s: ClientIP = %s, want the socket address %s", peer, forged, got, hostOnly(peer))
			}
		}
	}
}

func hostOnly(addr string) string {
	for i := 0; i < len(addr); i++ {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}

// The shipped default must stay loopback-only: widening it silently
// re-opens the LAN spoofing hole documented above.
func TestDefaultTrustedProxiesIsLoopbackOnly(t *testing.T) {
	parsed, err := ParseTrustedProxies(DefaultTrustedProxies)
	if err != nil {
		t.Fatalf("parse default trusted proxies: %v", err)
	}
	for _, network := range parsed {
		for _, routable := range []string{"10.0.0.5", "172.17.0.2", "192.168.1.100"} {
			if network.Contains(parseHeaderIP(routable)) {
				t.Fatalf("%s is trusted by the default list; only loopback may be", routable)
			}
		}
	}
	for _, loopback := range []string{"127.0.0.1", "::1"} {
		found := false
		for _, network := range parsed {
			if network.Contains(parseHeaderIP(loopback)) {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s must stay trusted by default", loopback)
		}
	}
}

func TestParseTrustedProxiesRejectsMalformedEntry(t *testing.T) {
	if _, err := ParseTrustedProxies("127.0.0.0/8,not-a-cidr"); err == nil {
		t.Fatal("a malformed CIDR must be reported so the caller can fail closed")
	}
	if _, err := ParseTrustedProxies("  , 10.0.0.0/8 ,"); err != nil {
		t.Fatalf("blank entries must be skipped, got %v", err)
	}
}
