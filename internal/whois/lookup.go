package whois

import (
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"safe-zone/internal/store"
)

// Result contains WHOIS domain age analysis results.
// All fields are safe to use even when Found is false (fail-open).
type Result struct {
	Found          bool      `json:"found"`
	RegisteredDate time.Time `json:"registered_date,omitempty"`
	DomainAgeDays  int       `json:"domain_age_days"`
	Registrar      string    `json:"registrar,omitempty"`
	PrivacyGuard   bool      `json:"privacy_guard"`
	Score          int       `json:"score"`
	Reasons        []string  `json:"reasons"`
}

// whoisServers maps common TLD to their WHOIS server.
var whoisServers = map[string]string{
	"com":    "whois.verisign-grs.com",
	"net":    "whois.verisign-grs.com",
	"org":    "whois.pir.org",
	"info":   "whois.afilias.net",
	"biz":    "whois.biz",
	"io":     "whois.nic.io",
	"co":     "whois.nic.co",
	"us":     "whois.nic.us",
	"uk":     "whois.nic.uk",
	"app":    "whois.nic.google",
	"dev":    "whois.nic.google",
	"xyz":    "whois.nic.xyz",
	"site":   "whois.nic.site",
	"store":  "whois.nic.store",
	"shop":   "whois.nic.shop",
	"online": "whois.nic.online",
	"club":   "whois.nic.club",
	"vn":     "whois.dot.vn",
}

var whoisDialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

const defaultQueryTimeout = 5 * time.Second
const defaultCacheTTL = 7 * 24 * time.Hour

// datePatterns are tried in order to extract creation dates from WHOIS text.
var datePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)creation date:\s*(.+)`),
	regexp.MustCompile(`(?i)registration date:\s*(.+)`),
	regexp.MustCompile(`(?i)created:\s*(.+)`),
	regexp.MustCompile(`(?i)registered:\s*(.+)`),
	regexp.MustCompile(`(?i)domain registration date:\s*(.+)`),
	regexp.MustCompile(`(?i)registration time:\s*(.+)`),
}

// registrarPatterns extract the registrar name.
var registrarPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)registrar:\s*(.+)`),
	regexp.MustCompile(`(?i)registrar name:\s*(.+)`),
}

// privacyKeywords indicate privacy-protection services in registrar names.
var privacyKeywords = []string{
	"privacy", "protect", "whoisguard", "domains by proxy",
	"perfect privacy", "contact privacy", "private registration",
}

// Lookup queries WHOIS for the registered domain and returns a scored Result.
// Returns a zero-score Result on any error (fail-open).
func Lookup(ctx context.Context, domain string) Result {
	return LookupWithCache(ctx, domain, nil, defaultCacheTTL)
}

// LookupWithCache queries WHOIS with an optional SQLite cache.
func LookupWithCache(ctx context.Context, domain string, db *store.DB, ttl time.Duration) Result {
	registered := RegisteredDomain(domain)
	if registered == "" {
		return Result{Reasons: []string{}}
	}
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	if db != nil && db.Enabled() {
		if cached, ok, err := db.GetWhoisCache(registered, time.Now()); err == nil && ok {
			if cached.RawText != "" {
				return parseAndScore(cached.RawText)
			}
			return Result{
				Found:          cached.Found,
				RegisteredDate: cached.RegisteredDate,
				DomainAgeDays:  cached.DomainAgeDays,
				Registrar:      cached.Registrar,
				PrivacyGuard:   cached.PrivacyGuard,
				Score:          cached.Score,
				Reasons:        append([]string(nil), cached.Reasons...),
			}
		}
	}

	tld := tldOf(registered)
	server, ok := whoisServers[tld]
	if !ok {
		return Result{Reasons: []string{}} // unsupported TLD — skip silently
	}

	raw, err := query(ctx, server, registered)
	if err != nil {
		return Result{Reasons: []string{}} // network error — fail open
	}

	result := parseAndScore(raw)
	if db != nil && db.Enabled() {
		_ = db.SetWhoisCache(registered, store.WhoisCacheEntry{
			Domain:         registered,
			Found:          result.Found,
			RegisteredDate: result.RegisteredDate,
			DomainAgeDays:  result.DomainAgeDays,
			Registrar:      result.Registrar,
			PrivacyGuard:   result.PrivacyGuard,
			Score:          result.Score,
			Reasons:        append([]string(nil), result.Reasons...),
			RawText:        raw,
		}, ttl)
	}
	return result
}

// query sends a WHOIS TCP query and returns the raw text response.
func query(ctx context.Context, server, domain string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultQueryTimeout)
		defer cancel()
	}

	conn, err := whoisDialContext(ctx, "tcp", net.JoinHostPort(server, "43"))
	if err != nil {
		return "", fmt.Errorf("whois dial %s: %w", server, err)
	}
	defer conn.Close()

	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)

	_, err = fmt.Fprintf(conn, "%s\r\n", domain)
	if err != nil {
		return "", fmt.Errorf("whois write: %w", err)
	}

	var sb strings.Builder
	if _, err := io.Copy(&sb, conn); err != nil {
		return "", fmt.Errorf("whois read: %w", err)
	}
	return sb.String(), nil
}

// parseAndScore extracts date, registrar, and scores the Result.
func parseAndScore(raw string) Result {
	r := Result{Reasons: []string{}}

	// Extract creation date.
	created, ok := parseCreationDate(raw)
	if !ok {
		return r // can't determine age — fail open, no penalty
	}

	r.Found = true
	r.RegisteredDate = created
	r.DomainAgeDays = int(time.Since(created).Hours() / 24)

	// Extract registrar.
	r.Registrar = extractField(raw, registrarPatterns)

	// Detect privacy guard.
	regLower := strings.ToLower(r.Registrar + " " + raw[:min(len(raw), 2000)])
	for _, kw := range privacyKeywords {
		if strings.Contains(regLower, kw) {
			r.PrivacyGuard = true
			break
		}
	}

	// Score by age.
	switch {
	case r.DomainAgeDays < 7:
		r.Score += 25
		r.Reasons = append(r.Reasons, "whois: domain registered < 7 days ago")
	case r.DomainAgeDays < 30:
		r.Score += 15
		r.Reasons = append(r.Reasons, "whois: domain registered < 30 days ago")
	case r.DomainAgeDays < 90:
		r.Score += 5
		r.Reasons = append(r.Reasons, "whois: domain registered < 90 days ago")
	}

	if r.PrivacyGuard {
		r.Score += 5
		r.Reasons = append(r.Reasons, "whois: privacy guard enabled")
	}

	return r
}

// parseCreationDate tries all date patterns and formats.
func parseCreationDate(raw string) (time.Time, bool) {
	for _, pat := range datePatterns {
		m := pat.FindStringSubmatch(raw)
		if len(m) < 2 {
			continue
		}
		val := strings.TrimSpace(m[1])
		// Strip trailing comments (e.g., " (some text)" or " // comment")
		if i := strings.Index(val, " ("); i > 0 {
			val = val[:i]
		}
		for _, layout := range dateLayouts {
			if t, err := time.Parse(layout, val); err == nil {
				return t.UTC(), true
			}
		}
	}
	return time.Time{}, false
}

// dateLayouts are tried in order when parsing WHOIS date strings.
var dateLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02",
	"02-Jan-2006",
	"January 02 2006",
	"Jan 02 2006",
	"02/01/2006",
	"2006.01.02",
}

// extractField returns the first match of any pattern in raw, trimmed.
func extractField(raw string, patterns []*regexp.Regexp) string {
	for _, pat := range patterns {
		m := pat.FindStringSubmatch(raw)
		if len(m) >= 2 {
			return strings.TrimSpace(m[1])
		}
	}
	return ""
}

var secondLevelSuffixes = map[string]bool{
	"com":  true,
	"gov":  true,
	"net":  true,
	"edu":  true,
	"org":  true,
	"co":   true,
	"ac":   true,
	"biz":  true,
	"info": true,
	"pro":  true,
	"name": true,
	"me":   true,
}

// RegisteredDomain extracts the apex/registered domain from a full FQDN.
// e.g. "mail.example.com" → "example.com", "vietcombank.com.vn" → "vietcombank.com.vn".
func RegisteredDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ""
	}
	// Nếu có từ 3 phần trở lên và phần kề cuối là một hậu tố phổ biến (e.g. com, gov, co),
	// thì tên miền đăng ký bao gồm cả 3 phần cuối (ví dụ: vietcombank.com.vn).
	if len(parts) >= 3 && secondLevelSuffixes[parts[len(parts)-2]] {
		return strings.Join(parts[len(parts)-3:], ".")
	}
	// Ngược lại, trả về 2 phần cuối (ví dụ: example.com).
	return strings.Join(parts[len(parts)-2:], ".")
}

// tldOf returns the TLD (last label) of a domain.
func tldOf(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ParseAndScoreForTest exposes parseAndScore for white-box unit testing.
func ParseAndScoreForTest(raw string) Result {
	return parseAndScore(raw)
}

// RegisteredDomainForTest exposes RegisteredDomain for testing.
func RegisteredDomainForTest(domain string) string {
	return RegisteredDomain(domain)
}
