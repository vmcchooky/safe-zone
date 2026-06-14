package ratelimit

import (
	"net/http"
	"testing"
)

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xri        string
		expected   string
	}{
		{
			name:       "no headers, non-trusted proxy",
			remoteAddr: "203.0.113.1:12345",
			expected:   "203.0.113.1",
		},
		{
			name:       "fake xff from non-trusted proxy",
			remoteAddr: "203.0.113.1:12345",
			xff:        "1.2.3.4",
			expected:   "203.0.113.1",
		},
		{
			name:       "fake xri from non-trusted proxy",
			remoteAddr: "203.0.113.1:12345",
			xri:        "1.2.3.4",
			expected:   "203.0.113.1",
		},
		{
			name:       "xff from trusted proxy (localhost)",
			remoteAddr: "127.0.0.1:12345",
			xff:        "1.2.3.4",
			expected:   "1.2.3.4",
		},
		{
			name:       "xff from trusted proxy (docker network)",
			remoteAddr: "172.17.0.2:54321",
			xff:        "8.8.8.8, 1.2.3.4",
			expected:   "8.8.8.8",
		},
		{
			name:       "xri from trusted proxy",
			remoteAddr: "10.0.0.5:8080",
			xri:        "9.9.9.9",
			expected:   "9.9.9.9",
		},
		{
			name:       "xff and xri from trusted proxy (xff wins)",
			remoteAddr: "192.168.1.100:12345",
			xff:        "1.1.1.1",
			xri:        "2.2.2.2",
			expected:   "1.1.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				req.Header.Set("X-Real-IP", tt.xri)
			}

			ip := ClientIP(req)
			if ip != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, ip)
			}
		})
	}
}
