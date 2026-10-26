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

// ietfTestNets are the IPv4 documentation ranges from RFC 5737. They are
// guaranteed never to be routable, so a sinkhole that answers with one sends
// every blocked client into a black hole instead of a block page.
var ietfTestNets = func() []*net.IPNet {
	nets := make([]*net.IPNet, 0, 3)
	for _, cidr := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("builtin TEST-NET CIDR %q must parse: %v", cidr, err))
		}
		nets = append(nets, block)
	}
	return nets
}()

func inTestNet(ip net.IP) bool {
	for _, block := range ietfTestNets {
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
// loopback, unspecified, multicast, link-local, and the RFC 5737 TEST-NETs.
// A placeholder from the shipped env examples ("replace-with-*") also fails:
// the value was never filled in, and the previous behavior resolved it to nil
// and silently answered NOERROR/NODATA.
//
// A valid but private (RFC 1918 / IPv6 ULA) address returns a non-empty
// warning and no error: internal deployments legitimately sinkhole to a
// private block page, but the choice is worth surfacing in the log.
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
	case inTestNet(ip):
		return "", fmt.Errorf("SAFE_ZONE_BLOCK_PAGE_IP %s is an IETF documentation (TEST-NET) address; it is never routable", ip)
	}

	if ip.IsPrivate() {
		return fmt.Sprintf("SAFE_ZONE_BLOCK_PAGE_IP %s is a private address; acceptable only when the block page is reachable from every blocked client network", ip), nil
	}
	return "", nil
}
