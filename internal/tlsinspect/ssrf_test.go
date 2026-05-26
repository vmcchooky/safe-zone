package tlsinspect

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestInspectBlocksUnsafeResolvedIPs(t *testing.T) {
	original := lookupIPAddr
	defer func() { lookupIPAddr = original }()

	tests := []string{
		"127.0.0.1",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.10",
		"169.254.1.1",
		"100.64.0.1",
		"::1",
		"fe80::1",
		"fc00::1",
	}

	for _, ip := range tests {
		t.Run(ip, func(t *testing.T) {
			lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			result := Inspect(ctx, "unsafe.example")
			if result.HasTLS {
				t.Fatal("expected unsafe IP inspection to be blocked")
			}
			if len(result.Reasons) != 1 || result.Reasons[0] != "tls: blocked connection to private ip" {
				t.Fatalf("unexpected reasons: %#v", result.Reasons)
			}
		})
	}
}
