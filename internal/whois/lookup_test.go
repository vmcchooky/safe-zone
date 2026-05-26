package whois_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/whois"
)

// ── Mock WHOIS TCP server ─────────────────────────────────────────────────────

// startMockWHOIS starts a TCP server that responds with body for any query.
// Returns the server address and a cleanup function.
func startMockWHOIS(t *testing.T, responses map[string]string) (addr string, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				scanner := bufio.NewScanner(c)
				if !scanner.Scan() {
					return
				}
				domain := strings.TrimSpace(scanner.Text())
				body, ok := responses[domain]
				if !ok {
					body = responses["*"] // fallback
				}
				fmt.Fprint(c, body)
			}(conn)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

// ── ParseAndScore tests (via ParseAndScoreForTest) ────────────────────────────

func TestParseAndScore_FreshDomain(t *testing.T) {
	raw := whoisResponse(time.Now().Add(-3 * 24 * time.Hour)) // 3 days old
	r := whois.ParseAndScoreForTest(raw)
	if !r.Found {
		t.Fatal("expected Found=true")
	}
	if r.Score < 25 {
		t.Errorf("expected score >= 25 for < 7 day domain, got %d", r.Score)
	}
	hasReason(t, r.Reasons, "7 days")
}

func TestParseAndScore_ModeratelyNewDomain(t *testing.T) {
	raw := whoisResponse(time.Now().Add(-15 * 24 * time.Hour)) // 15 days old
	r := whois.ParseAndScoreForTest(raw)
	if r.Score < 15 {
		t.Errorf("expected score >= 15 for < 30 day domain, got %d", r.Score)
	}
	hasReason(t, r.Reasons, "30 days")
}

func TestParseAndScore_SlightlyNewDomain(t *testing.T) {
	raw := whoisResponse(time.Now().Add(-45 * 24 * time.Hour)) // 45 days old
	r := whois.ParseAndScoreForTest(raw)
	if r.Score < 5 {
		t.Errorf("expected score >= 5 for < 90 day domain, got %d", r.Score)
	}
	hasReason(t, r.Reasons, "90 days")
}

func TestParseAndScore_OldDomain(t *testing.T) {
	raw := whoisResponse(time.Now().Add(-5 * 365 * 24 * time.Hour)) // 5 years old
	r := whois.ParseAndScoreForTest(raw)
	if r.Score != 0 {
		t.Errorf("expected score 0 for old domain, got %d", r.Score)
	}
}

func TestParseAndScore_PrivacyGuard(t *testing.T) {
	raw := `Creation Date: ` + time.Now().Add(-200*24*time.Hour).Format(time.RFC3339) + `
Registrar: WhoisGuard, Inc.
`
	r := whois.ParseAndScoreForTest(raw)
	if !r.PrivacyGuard {
		t.Error("expected PrivacyGuard=true")
	}
	hasReason(t, r.Reasons, "privacy")
}

func TestParseAndScore_MultipleDateFormats(t *testing.T) {
	formats := []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02",
		"02-Jan-2006",
	}
	for _, layout := range formats {
		raw := "creation date: " + time.Now().Add(-3*24*time.Hour).Format(layout)
		r := whois.ParseAndScoreForTest(raw)
		if !r.Found {
			t.Errorf("expected Found=true for layout %q, raw: %q", layout, raw)
		}
	}
}

func TestParseAndScore_MissingDate(t *testing.T) {
	raw := "Registrar: SomeRegistrar\nStatus: active\n"
	r := whois.ParseAndScoreForTest(raw)
	if r.Found {
		t.Error("expected Found=false when no date found")
	}
	if r.Score != 0 {
		t.Errorf("expected score 0 for missing date, got %d", r.Score)
	}
}

// ── Lookup tests ──────────────────────────────────────────────────────────────

func TestLookup_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// This won't actually reach a WHOIS server — timeout triggers immediately.
	r := whois.Lookup(ctx, "example.com")
	// With a real unsupported TLD or timeout, result should be zero-score (fail-open).
	if r.Score < 0 {
		t.Errorf("score should be >= 0, got %d", r.Score)
	}
}

func TestLookup_UnsupportedTLD(t *testing.T) {
	r := whois.Lookup(context.Background(), "example.invalidtld")
	if r.Found {
		t.Error("expected Found=false for unsupported TLD")
	}
	if r.Score != 0 {
		t.Errorf("expected score 0 for unsupported TLD, got %d", r.Score)
	}
}

// ── RegisteredDomain tests ────────────────────────────────────────────────────

func TestRegisteredDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"mail.example.com", "example.com"},
		{"example.com", "example.com"},
		{"a.b.c.example.org", "example.org"},
		{"example.co", "example.co"},
		{"vietcombank.com.vn", "vietcombank.com.vn"},
		{"phishing-vietcombank.com.vn", "phishing-vietcombank.com.vn"},
		{"mail.phishing-vietcombank.com.vn", "phishing-vietcombank.com.vn"},
		{"example.co.uk", "example.co.uk"},
		{"sub.example.co.uk", "example.co.uk"},
		{"example.gov.vn", "example.gov.vn"},
		{"sub.example.gov.vn", "example.gov.vn"},
		{"", ""},
	}
	for _, tt := range tests {
		got := whois.RegisteredDomainForTest(tt.input)
		if got != tt.want {
			t.Errorf("RegisteredDomain(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func whoisResponse(created time.Time) string {
	return fmt.Sprintf(`Domain Name: example.com
Creation Date: %s
Registrar: Example Registrar, Inc.
Status: active
`, created.Format(time.RFC3339))
}

func hasReason(t *testing.T, reasons []string, substr string) {
	t.Helper()
	for _, r := range reasons {
		if strings.Contains(r, substr) {
			return
		}
	}
	t.Errorf("expected a reason containing %q, got: %v", substr, reasons)
}
