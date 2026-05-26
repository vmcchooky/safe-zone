package tlsinspect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"time"
)

// Result contains the outcome of inspecting a domain's TLS certificate.
// All fields are safe to use even when HasTLS is false (fail-open).
type Result struct {
	HasTLS      bool      `json:"has_tls"`
	Valid       bool      `json:"valid"`
	SelfSigned  bool      `json:"self_signed"`
	Expired     bool      `json:"expired"`
	Issuer      string    `json:"issuer"`
	Subject     string    `json:"subject"`
	SANMatch    bool      `json:"san_match"`
	CertAgeDays int       `json:"cert_age_days"`
	IsWildcard  bool      `json:"is_wildcard"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Score       int       `json:"score"`
	Reasons     []string  `json:"reasons"`
}

// Package-level resolver function supporting test mock injection
var lookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

// Inspect performs a TLS handshake to domain:443, extracts the leaf certificate
// and returns a scored Result. Returns a zero-score Result on any error (fail-open).
func Inspect(ctx context.Context, domain string) Result {
	// 1. Resolve IP addresses first to prevent SSRF using lookupIPAddr (supports test mocks)
	ips, err := lookupIPAddr(ctx, domain)
	if err != nil || len(ips) == 0 {
		return Result{HasTLS: false, Reasons: []string{}}
	}

	// Filter for the first valid public IP
	var publicIP net.IP
	for _, ipAddr := range ips {
		if isPublicIP(ipAddr.IP) {
			publicIP = ipAddr.IP
			break
		}
	}

	if publicIP == nil {
		return Result{
			HasTLS:  false,
			Reasons: []string{"tls: blocked connection to private ip"},
		}
	}

	// 2. Perform secure TLS dialing using the resolved public IP
	dialer := &tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: true,   // #nosec G402 -- intentional: we inspect the cert ourselves
			ServerName:         domain, // Keep domain for SNI
			MinVersion:         tls.VersionTLS12,
		},
		NetDialer: &net.Dialer{
			Timeout: 3 * time.Second, // explicit connection timeout to prevent hanging
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(publicIP.String(), "443"))
	if err != nil {
		// No TLS or unreachable — minor signal only (don't penalise)
		return Result{HasTLS: false, Reasons: []string{}}
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return Result{HasTLS: false, Reasons: []string{}}
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return Result{HasTLS: true, Reasons: []string{}}
	}

	cert := state.PeerCertificates[0]
	return scoreResult(domain, cert)
}

func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Check standard loopback, private, link-local, unspecified
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return false
	}
	// Explicitly check Carrier-Grade NAT (CGNAT) Shared Address Space (RFC 6598: 100.64.0.0/10)
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return false
		}
	}
	return true
}

// scoreResult builds a Result from a parsed x509 leaf certificate.
func scoreResult(domain string, cert *x509.Certificate) Result {
	r := Result{
		HasTLS:    true,
		Issuer:    cert.Issuer.CommonName,
		Subject:   cert.Subject.CommonName,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		Reasons:   []string{},
	}

	now := time.Now()

	// Expired check
	if now.After(cert.NotAfter) {
		r.Expired = true
		r.Score += 20
		r.Reasons = append(r.Reasons, "tls: certificate expired")
	} else {
		r.Valid = true
	}

	// Self-signed: issuer == subject
	if cert.Issuer.String() == cert.Subject.String() {
		r.SelfSigned = true
		r.Score += 25
		r.Reasons = append(r.Reasons, "tls: self-signed certificate")
	}

	// Certificate age
	certAge := now.Sub(cert.NotBefore)
	r.CertAgeDays = int(certAge.Hours() / 24)
	if r.CertAgeDays < 7 && !r.Expired {
		r.Score += 15
		r.Reasons = append(r.Reasons, "tls: certificate issued < 7 days ago")
	}

	// SAN / CN mismatch
	r.SANMatch = certMatchesDomain(cert, domain)
	if !r.SANMatch {
		r.Score += 30
		r.Reasons = append(r.Reasons, "tls: certificate name does not match domain")
	}

	// Wildcard cert
	for _, name := range cert.DNSNames {
		if strings.HasPrefix(name, "*.") {
			r.IsWildcard = true
			break
		}
	}
	if !r.IsWildcard && strings.HasPrefix(cert.Subject.CommonName, "*.") {
		r.IsWildcard = true
	}

	// Cap score
	if r.Score > 100 {
		r.Score = 100
	}

	return r
}

// certMatchesDomain reports whether the certificate's SANs or CN covers domain.
func certMatchesDomain(cert *x509.Certificate, domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	// Check SAN DNS names first (preferred over CN per RFC 6125)
	for _, san := range cert.DNSNames {
		san = strings.ToLower(san)
		if matchHostname(san, domain) {
			return true
		}
	}

	// Fallback to CN
	cn := strings.ToLower(cert.Subject.CommonName)
	return matchHostname(cn, domain)
}

// matchHostname matches a name pattern (possibly wildcard) against a hostname.
func matchHostname(pattern, host string) bool {
	if pattern == host {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	// Wildcard: *.example.com matches mail.example.com but NOT example.com
	suffix := pattern[1:] // ".example.com"
	return strings.HasSuffix(host, suffix) && strings.Count(host, ".") == strings.Count(suffix, ".")
}

// InspectCert scores a pre-parsed x509 certificate for the given domain.
// This is the testable core of Inspect — it requires no network access.
func InspectCert(domain string, cert *x509.Certificate) Result {
	return scoreResult(domain, cert)
}
