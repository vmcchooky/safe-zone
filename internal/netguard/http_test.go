package netguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"testing"
)

func TestIsBlockedIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		blocked bool
	}{
		// RFC 6598 carrier-grade NAT boundaries.
		{"CGNAT first address", "100.64.0.1", true},
		{"CGNAT last address", "100.127.255.254", true},
		{"CGNAT network address", "100.64.0.0", true},
		{"CGNAT broadcast address", "100.127.255.255", true},
		{"below CGNAT range", "100.63.255.255", false},
		{"above CGNAT range", "100.128.0.0", false},
		// Other blocked classes.
		{"IPv4 loopback", "127.0.0.1", true},
		{"IPv6 loopback", "::1", true},
		{"private 10/8", "10.0.0.1", true},
		{"private 192.168/16", "192.168.1.1", true},
		{"private 172.16/12", "172.16.0.1", true},
		{"link-local metadata", "169.254.169.254", true},
		{"unspecified", "0.0.0.0", true},
		// Public addresses must stay allowed.
		{"public IPv4 DNS", "8.8.8.8", false},
		{"public IPv4", "93.184.216.34", false},
		{"public IPv6", "2606:4700:4700::1111", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			if got := IsBlockedIP(ip); got != tt.blocked {
				t.Fatalf("IsBlockedIP(%s) = %v, want %v", tt.ip, got, tt.blocked)
			}
		})
	}
}

func TestValidateParsedURLRejectsSensitiveTargets(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"CGNAT literal", "http://100.64.0.1/dns-query"},
		{"CGNAT upper literal", "http://100.127.255.254/dns-query"},
		{"loopback literal", "http://127.0.0.1:8080/dns-query"},
		{"private literal", "http://192.168.1.1/admin"},
		{"link-local metadata", "http://169.254.169.254/latest/meta-data/"},
		{"localhost hostname", "http://localhost:8080/feed"},
		{"localhost subdomain", "http://api.localhost/feed"},
		{"non-HTTP scheme", "ftp://example.com/feed"},
		{"missing host", "http:///path-only"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := url.Parse(tt.url)
			if err != nil {
				t.Fatalf("parse url: %v", err)
			}
			err = ValidateParsedURL(parsed, false)
			if err == nil {
				t.Fatalf("expected %q to be rejected", tt.url)
			}
			if !errors.Is(err, ErrBlockedAddress) && tt.url != "ftp://example.com/feed" && tt.url != "http:///path-only" {
				t.Fatalf("expected ErrBlockedAddress for %q, got %v", tt.url, err)
			}
		})
	}
}

func TestValidateParsedURLAcceptsPublicTargets(t *testing.T) {
	for _, raw := range []string{
		"https://cloudflare-dns.com/dns-query",
		"http://8.8.8.8/dns-query",
		"https://93.184.216.34/feed.txt",
	} {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse url: %v", err)
		}
		if err := ValidateParsedURL(parsed, false); err != nil {
			t.Fatalf("expected %q to pass, got %v", raw, err)
		}
	}
}

func TestResolveAllowedIPsBlocksCGNATLiteral(t *testing.T) {
	for _, host := range []string{"100.64.0.1", "100.127.255.254"} {
		if _, err := ResolveAllowedIPs(context.Background(), host, false); !errors.Is(err, ErrBlockedAddress) {
			t.Fatalf("expected CGNAT host %q to be blocked, got %v", host, err)
		}
	}
	if _, err := ResolveAllowedIPs(context.Background(), "8.8.8.8", false); err != nil {
		t.Fatalf("expected public literal to resolve, got %v", err)
	}
}

func TestCheckRedirectRejectsBlockedHops(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"redirect into CGNAT", "http://100.64.0.1/dns-query"},
		{"redirect into loopback", "http://127.0.0.1:9000/secret"},
		{"redirect into metadata", "http://169.254.169.254/latest/meta-data/"},
		{"redirect into private range", "http://10.0.0.5/admin"},
		{"redirect to non-HTTP scheme", "ftp://example.com/feed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := url.Parse(tt.url)
			if err != nil {
				t.Fatalf("parse url: %v", err)
			}
			req := &http.Request{URL: parsed, Header: http.Header{}}
			err = CheckRedirect(req, nil)
			if err == nil {
				t.Fatalf("expected redirect to %q to be rejected", tt.url)
			}
			if tt.url != "ftp://example.com/feed" && !errors.Is(err, ErrBlockedAddress) {
				t.Fatalf("expected ErrBlockedAddress for %q, got %v", tt.url, err)
			}
		})
	}
}

func TestCheckRedirectAcceptsPublicHops(t *testing.T) {
	parsed, err := url.Parse("http://198.51.100.10/feed.txt")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	req := &http.Request{URL: parsed, Header: http.Header{}}
	if err := CheckRedirect(req, nil); err != nil {
		t.Fatalf("expected public redirect hop to pass, got %v", err)
	}
}

func TestCheckRedirectCapsRedirectDepth(t *testing.T) {
	parsed, err := url.Parse("http://198.51.100.10/feed.txt")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	via := make([]*http.Request, 10)
	req := &http.Request{URL: parsed, Header: http.Header{}}
	if err := CheckRedirect(req, via); err == nil {
		t.Fatal("expected redirect depth cap to reject the 11th hop")
	}
}
