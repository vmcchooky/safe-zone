package netguard_test

import (
	"net"
	"testing"

	"safe-zone/internal/netguard"
)

// The outbound address rule had three near-identical copies — one here, one in
// osint, one in tlsinspect — and they had drifted apart twice. The osint copy
// omitted the CGNAT check, so an OSINT source resolving into 100.64.0.0/10 (the
// carrier-NAT and Tailscale range) was fetched where netguard would have
// rejected it. The tlsinspect copy omitted multicast.
//
// This table is the shared contract. Any package that reimplements the rule
// will disagree with it, and the drift becomes visible as a failing test rather
// than as a silent hole in one fetch path.
func TestOutboundAddressContract(t *testing.T) {
	tests := []struct {
		address string
		blocked bool
		why     string
	}{
		// Loopback and the 0.0.0.0/8 "this network" range, which Linux routes to
		// loopback even though only the exact address is "unspecified".
		{"127.0.0.1", true, "loopback"},
		{"0.0.0.0", true, "unspecified"},
		{"0.0.0.1", true, "0.0.0.0/8 routes to loopback on Linux"},
		{"0.255.255.255", true, "0.0.0.0/8 routes to loopback on Linux"},

		// Private ranges.
		{"10.0.0.1", true, "RFC 1918"},
		{"172.16.0.1", true, "RFC 1918"},
		{"192.168.1.1", true, "RFC 1918"},

		// Link-local, which is where cloud metadata endpoints live. This is the
		// single most important row in the table: 169.254.169.254 is the target
		// of the classic SSRF credential-theft technique.
		{"169.254.169.254", true, "cloud metadata endpoint"},
		{"169.254.1.1", true, "link-local"},

		// Carrier-grade NAT / Tailscale. The osint copy missed this one.
		{"100.64.0.1", true, "RFC 6598 CGNAT"},
		{"100.127.255.255", true, "RFC 6598 CGNAT last"},

		// Non-routable IPv4 that net.IP's own predicates do not cover.
		{"192.0.0.170", true, "IETF protocol assignments"},
		{"198.18.0.1", true, "benchmarking"},
		{"240.0.0.1", true, "reserved"},
		{"255.255.255.255", true, "limited broadcast"},

		// Multicast and IPv6 equivalents.
		{"224.0.0.1", true, "multicast"},
		{"239.255.255.255", true, "multicast"},
		{"ff02::1", true, "IPv6 multicast"},
		{"::1", true, "IPv6 loopback"},
		{"::", true, "IPv6 unspecified"},
		{"fe80::1", true, "IPv6 link-local"},
		{"fc00::1", true, "IPv6 unique-local"},

		// IPv4-mapped IPv6 must not be a way around any of the above.
		{"::ffff:127.0.0.1", true, "IPv4-mapped loopback"},
		{"::ffff:169.254.169.254", true, "IPv4-mapped metadata endpoint"},
		{"::ffff:10.0.0.1", true, "IPv4-mapped private"},

		// IPv6 transition ranges carry an IPv4 destination that the v4 checks
		// never see, because To4() returns nil for them. Without these rows
		// IsBlockedIP(127.0.0.1) is true while IsBlockedIP(2002:7f00:0001::1) —
		// the same host — is false.
		{"2002:7f00:0001::1", true, "6to4 form of 127.0.0.1"},
		{"2002:0a00:0001::1", true, "6to4 form of 10.0.0.0/8"},
		{"2002:a9fe:a9fe::1", true, "6to4 form of the 169.254.169.254 metadata endpoint"},
		{"2001:0:4136:e378::1", true, "Teredo"},
		{"64:ff9b::a00:1", true, "NAT64 well-known prefix, 10.0.0.1"},
		{"64:ff9b::7f00:1", true, "NAT64 well-known prefix, 127.0.0.1"},
		{"::7f00:1", true, "IPv4-compatible IPv6, 127.0.0.1"},

		// Genuinely routable.
		{"1.1.1.1", false, "public resolver"},
		{"8.8.8.8", false, "public resolver"},
		{"9.9.9.9", false, "public resolver"},
		{"208.67.222.222", false, "public resolver"},
		{"2606:4700:4700::1111", false, "public IPv6"},
		{"2001:4860:4860::8888", false, "public IPv6 (Google DNS)"},
	}

	for _, tc := range tests {
		t.Run(tc.address, func(t *testing.T) {
			ip := net.ParseIP(tc.address)
			if ip == nil {
				t.Fatalf("cannot parse %q", tc.address)
			}
			if got := netguard.IsBlockedIP(ip); got != tc.blocked {
				t.Fatalf("IsBlockedIP(%s) = %v, want %v (%s)", tc.address, got, tc.blocked, tc.why)
			}
		})
	}
}
