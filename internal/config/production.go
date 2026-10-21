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
