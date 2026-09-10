package analysis

import (
	"strings"
	"testing"
)

// H4: inputs that cannot be DNS names must be rejected before any
// suffix expansion or database work. Bounds follow RFC 1035 wire limits
// (253 total bytes without trailing dot, 63 bytes per label).
func TestNormalizeDomainDNSBounds(t *testing.T) {
	longLabel := strings.Repeat("a", 64)
	maxLabel := strings.Repeat("b", 63)
	// 253 bytes total: 63+1+63+1+63+1+61.
	maxDomain := maxLabel + "." + maxLabel + "." + maxLabel + "." + strings.Repeat("c", 61)
	if len(maxDomain) != 253 {
		t.Fatalf("fixture must be exactly 253 bytes, got %d", len(maxDomain))
	}

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"total over 253", maxDomain + "x", true},
		{"total exactly 253", maxDomain, false},
		{"label over 63", longLabel + ".com", true},
		{"label exactly 63", maxLabel + ".com", false},
		{"empty middle label", "a..com", true},
		{"leading dot", ".example.com", true},
		{"many short labels", strings.Repeat("a.", 5000) + "com", true},
		{"normal domain", "mail.example.com", false},
		{"url with long path stays valid host", "https://" + maxLabel + ".com/" + strings.Repeat("p", 5000), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeDomain(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NormalizeDomain(%q...) error = %v; wantErr %v", tt.input[:min(40, len(tt.input))], err, tt.wantErr)
			}
			if !tt.wantErr && got == "" {
				t.Fatalf("expected normalized domain for %q", tt.name)
			}
		})
	}
}
