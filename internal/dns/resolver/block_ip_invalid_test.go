package resolver

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// A malformed SAFE_ZONE_BLOCK_PAGE_IP used to produce a nil answer that
// BlockedDNSMessage skipped, so a blocked domain resolved as NOERROR/NODATA
// and the client reached the origin. The block must never disappear.
func TestBlockIPv4NeverReturnsNil(t *testing.T) {
	for _, blockPageIP := range []string{"", "not-an-ip", "203.0.113.999", "   "} {
		r := &Resolver{Config: Config{BlockPageIP: blockPageIP, BlockStrategy: BlockStrategySinkhole}}

		if ip := r.BlockIPv4(); ip == nil {
			t.Fatalf("BlockIPv4 returned nil for block page IP %q", blockPageIP)
		} else if !ip.Equal(net.IPv4zero) {
			t.Fatalf("BlockIPv4 for %q = %v, want the null IP fallback", blockPageIP, ip)
		}
	}
}

func TestBlockIPv6NeverReturnsNil(t *testing.T) {
	for _, blockPageIP := range []string{"", "not-an-ip", "203.0.113.999"} {
		r := &Resolver{Config: Config{BlockPageIP: blockPageIP, BlockStrategy: BlockStrategySinkhole}}

		if ip := r.BlockIPv6(); ip == nil {
			t.Fatalf("BlockIPv6 returned nil for block page IP %q", blockPageIP)
		} else if !ip.Equal(net.IPv6zero) {
			t.Fatalf("BlockIPv6 for %q = %v, want the null IP fallback", blockPageIP, ip)
		}
	}
}

func TestBlockAddressesKeepValidValues(t *testing.T) {
	r := &Resolver{Config: Config{BlockPageIP: "203.0.113.7", BlockStrategy: BlockStrategySinkhole}}

	if ip := r.BlockIPv4(); ip == nil || ip.String() != "203.0.113.7" {
		t.Fatalf("BlockIPv4 = %v, want 203.0.113.7", ip)
	}
}

// The end-to-end symptom of the bug: a blocked domain must still receive an
// answer rather than an empty NOERROR/NODATA response.
func TestBlockedMessageAnswersEvenWithInvalidBlockPageIP(t *testing.T) {
	r := &Resolver{Config: Config{BlockPageIP: "not-an-ip", BlockStrategy: BlockStrategySinkhole}}

	query := new(dns.Msg)
	query.SetQuestion("phishing.example.", dns.TypeA)

	response, err := r.BlockedDNSMessage(query)
	if err != nil {
		t.Fatalf("BlockedDNSMessage returned an error: %v", err)
	}
	if len(response.Answer) == 0 {
		t.Fatal("blocked query got an empty answer; the block silently disappeared")
	}
}
