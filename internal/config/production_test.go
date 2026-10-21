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
