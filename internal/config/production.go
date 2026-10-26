package config

import (
	"fmt"
	"net"
	"strings"
)

// ValidateIP parses an IP address, returning an error instead of the silent
// nil that net.ParseIP returns for a malformed value.
func ValidateIP(value string) (net.IP, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, fmt.Errorf("IP address is empty")
	}
	parsed := net.ParseIP(trimmed)
	if parsed == nil {
		return nil, fmt.Errorf("%q is not a valid IP address", value)
	}
	return parsed, nil
}

func mustCIDRs(cidrs ...string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("builtin CIDR %q must parse: %v", cidr, err))
		}
		nets = append(nets, block)
	}
	return nets
}

// documentationNets are the IETF documentation ranges. They are guaranteed
// never to be routable, so a sinkhole that answers with one sends every
// blocked client into a black hole instead of a block page.
var documentationNets = mustCIDRs(
	"192.0.2.0/24",    // TEST-NET-1 (RFC 5737)
	"198.51.100.0/24", // TEST-NET-2 (RFC 5737)
	"203.0.113.0/24",  // TEST-NET-3 (RFC 5737)
	"2001:db8::/32",   // IPv6 documentation (RFC 3849)
	"3fff::/20",       // IPv6 documentation (RFC 9637)
)

// specialPurposeNets are the remaining special-purpose ranges that net.IP's
// predicates do not classify as loopback, unspecified, multicast, link-local,
// private, or documentation. A public block page must not point at them:
// clients either cannot route the answer or would be sent to a bench/test
// network. 240.0.0.0/4 includes the 255.255.255.255 limited broadcast.
var specialPurposeNets = mustCIDRs(
	"0.0.0.0/8",      // "this network" (RFC 1122)
	"192.0.0.0/24",   // IETF protocol assignments (RFC 6890)
	"192.88.99.0/24", // 6to4 relay anycast, deprecated (RFC 7526)
	"198.18.0.0/15",  // benchmarking (RFC 2544)
	"240.0.0.0/4",    // reserved, includes 255.255.255.255
	"100::/64",       // discard-only (RFC 6666)
	"2001:2::/48",    // benchmarking (RFC 5180)
	"2001:10::/28",   // ORCHID (RFC 4843)
	"2001:20::/28",   // ORCHIDv2 (RFC 7343)
)

// sharedAddressSpaceNets is RFC 6598 carrier-grade NAT space. It is not
// private, but it is not globally routable either; warn instead of rejecting
// because an ISP-hosted block page can legitimately live there.
var sharedAddressSpaceNets = mustCIDRs("100.64.0.0/10")

func inNets(ip net.IP, nets []*net.IPNet) bool {
	for _, block := range nets {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateProductionBlockPageIP checks a SAFE_ZONE_BLOCK_PAGE_IP value for
// production use with the sinkhole strategy.
//
// It returns an error for addresses that can never serve the block page or
// that would leak a block as a connection failure to a special-purpose range:
// loopback, unspecified, multicast, link-local, documentation (RFC 5737/3849/
// 9637), reserved, and the other non-routable ranges listed above. A
// placeholder from the shipped env examples ("replace-with-*") also fails:
// the value was never filled in, and the previous behavior resolved it to nil
// and silently answered NOERROR/NODATA.
//
// A valid but private (RFC 1918 / IPv6 ULA) or RFC 6598 shared address
// returns a non-empty warning and no error: internal and ISP-hosted
// deployments can legitimately sinkhole to such an address, but the choice is
// worth surfacing in the log.
func ValidateProductionBlockPageIP(value string) (warning string, err error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || strings.HasPrefix(strings.ToLower(trimmed), "replace-with-") {
		return "", fmt.Errorf("SAFE_ZONE_BLOCK_PAGE_IP is %q; set the public IP of the block page host", value)
	}

	ip, err := ValidateIP(trimmed)
	if err != nil {
		return "", fmt.Errorf("SAFE_ZONE_BLOCK_PAGE_IP %s", err)
	}

	switch {
	case ip.IsLoopback():
		return "", fmt.Errorf("SAFE_ZONE_BLOCK_PAGE_IP %s is a loopback address; blocked clients would connect to themselves, not the block page", ip)
	case ip.IsUnspecified():
		return "", fmt.Errorf("SAFE_ZONE_BLOCK_PAGE_IP %s is the unspecified address; blocked clients would have nowhere to connect", ip)
	case ip.IsMulticast() || ip.IsLinkLocalMulticast():
		return "", fmt.Errorf("SAFE_ZONE_BLOCK_PAGE_IP %s is a multicast address; it cannot serve a block page", ip)
	case ip.IsLinkLocalUnicast():
		return "", fmt.Errorf("SAFE_ZONE_BLOCK_PAGE_IP %s is a link-local address; it is not reachable across the network", ip)
	case inNets(ip, documentationNets):
		return "", fmt.Errorf("SAFE_ZONE_BLOCK_PAGE_IP %s is an IETF documentation address; it is never routable", ip)
	case inNets(ip, specialPurposeNets):
		return "", fmt.Errorf("SAFE_ZONE_BLOCK_PAGE_IP %s is a special-purpose address; it is not globally routable", ip)
	}

	if ip.IsPrivate() {
		return fmt.Sprintf("SAFE_ZONE_BLOCK_PAGE_IP %s is a private address; acceptable only when the block page is reachable from every blocked client network", ip), nil
	}
	if inNets(ip, sharedAddressSpaceNets) {
		return fmt.Sprintf("SAFE_ZONE_BLOCK_PAGE_IP %s is shared address space (RFC 6598); acceptable only when every blocked client can reach it", ip), nil
	}
	return "", nil
}
