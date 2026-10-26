package config

import "testing"

func TestValidateIP(t *testing.T) {
	if _, err := ValidateIP("203.0.113.7"); err != nil {
		t.Fatalf("expected a valid IP, got %v", err)
	}
	if _, err := ValidateIP("2001:db8::1"); err != nil {
		t.Fatalf("expected a valid IPv6, got %v", err)
	}
	if _, err := ValidateIP(""); err == nil {
		t.Fatal("expected an empty value to fail")
	}
	if _, err := ValidateIP("127.0.0.999"); err == nil {
		t.Fatal("expected a malformed address to fail")
	}
}

func TestValidateProductionBlockPageIPAcceptsRoutablePublicIP(t *testing.T) {
	for _, value := range []string{"93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"} {
		warning, err := ValidateProductionBlockPageIP(value)
		if err != nil {
			t.Fatalf("expected %q to be accepted, got %v", value, err)
		}
		if warning != "" {
			t.Fatalf("expected no warning for %q, got %q", value, warning)
		}
	}
}

func TestValidateProductionBlockPageIPRejectsPlaceholderAndEmpty(t *testing.T) {
	for _, value := range []string{"", "replace-with-vps-public-ip", "replace-with-shared-vps-public-ip", "REPLACE-WITH-staging-ip"} {
		if _, err := ValidateProductionBlockPageIP(value); err == nil {
			t.Fatalf("expected placeholder %q to be rejected", value)
		}
	}
}

func TestValidateProductionBlockPageIPRejectsSpecialUseRanges(t *testing.T) {
	cases := []struct {
		value string
		why   string
	}{
		{"127.0.0.1", "IPv4 loopback"},
		{"127.8.8.8", "IPv4 loopback range"},
		{"::1", "IPv6 loopback"},
		{"0.0.0.0", "IPv4 unspecified"},
		{"::", "IPv6 unspecified"},
		{"224.0.0.1", "IPv4 multicast"},
		{"ff02::1", "IPv6 multicast"},
		{"169.254.1.1", "IPv4 link-local"},
		{"fe80::1", "IPv6 link-local"},
		{"192.0.2.1", "TEST-NET-1"},
		{"192.0.2.254", "TEST-NET-1 last host"},
		{"198.51.100.77", "TEST-NET-2"},
		{"203.0.113.200", "TEST-NET-3"},
		{"255.255.255.255", "IPv4 limited broadcast"},
		{"0.1.2.3", "0.0.0.0/8 this-network range"},
		{"192.0.0.9", "IETF protocol assignments"},
		{"192.88.99.1", "6to4 relay anycast"},
		{"198.18.0.1", "benchmarking range"},
		{"240.0.0.1", "reserved range"},
		{"100::1", "IPv6 discard-only range"},
		{"2001:2::1", "IPv6 benchmarking range"},
		{"2001:db8::1", "IPv6 documentation range"},
		{"3fff::1", "IPv6 documentation range (RFC 9637)"},
	}
	for _, tc := range cases {
		if _, err := ValidateProductionBlockPageIP(tc.value); err == nil {
			t.Fatalf("expected %s (%s) to be rejected", tc.value, tc.why)
		}
	}
}

func TestValidateProductionBlockPageIPWarnsOnPrivateRanges(t *testing.T) {
	for _, value := range []string{"10.0.0.5", "172.16.4.4", "192.168.1.10", "fd00::10"} {
		warning, err := ValidateProductionBlockPageIP(value)
		if err != nil {
			t.Fatalf("expected private %s to be allowed with a warning, got %v", value, err)
		}
		if warning == "" {
			t.Fatalf("expected a warning for private %s", value)
		}
	}
}

func TestValidateProductionBlockPageIPWarnsOnSharedAddressSpace(t *testing.T) {
	warning, err := ValidateProductionBlockPageIP("100.64.0.1")
	if err != nil {
		t.Fatalf("expected RFC 6598 shared address space to be allowed with a warning, got %v", err)
	}
	if warning == "" {
		t.Fatal("expected a warning for RFC 6598 shared address space")
	}
}

// 192.0.2.0/24 sits inside neither the private nor the loopback space, but it
// is documentation range: the rejection must not be swallowed by an earlier
// IsPrivate check ordering bug.
func TestValidateProductionBlockPageIPTestNetIsRejectedNotWarned(t *testing.T) {
	warning, err := ValidateProductionBlockPageIP("198.51.100.10")
	if err == nil {
		t.Fatal("expected TEST-NET-2 to be rejected")
	}
	if warning != "" {
		t.Fatalf("a rejected address must not also carry a warning, got %q", warning)
	}
}

func TestValidateProductionBlockPageIPIPv6DocumentationIsRejectedNotWarned(t *testing.T) {
	for _, value := range []string{"2001:db8::1", "3fff::1"} {
		warning, err := ValidateProductionBlockPageIP(value)
		if err == nil {
			t.Fatalf("expected IPv6 documentation address %s to be rejected", value)
		}
		if warning != "" {
			t.Fatalf("a rejected address must not also carry a warning, got %q", warning)
		}
	}
}
