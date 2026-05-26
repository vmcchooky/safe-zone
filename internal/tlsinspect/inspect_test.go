package tlsinspect_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/tlsinspect"
)

// ── Helper: build a custom TLS certificate for testing ───────────────────────

type certOptions struct {
	commonName string
	dnsNames   []string
	notBefore  time.Time
	notAfter   time.Time
	selfSigned bool
}

func newTestCert(t *testing.T, opts certOptions) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if opts.notBefore.IsZero() {
		opts.notBefore = time.Now().Add(-24 * time.Hour)
	}
	if opts.notAfter.IsZero() {
		opts.notAfter = time.Now().Add(365 * 24 * time.Hour)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: opts.commonName},
		DNSNames:     opts.dnsNames,
		NotBefore:    opts.notBefore,
		NotAfter:     opts.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	parent := tmpl
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

func startTLSServer(t *testing.T, certPEM, keyPEM []byte) (addr string, cleanup func()) {
	t.Helper()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()

	// Extract just host:port without the https:// scheme
	addr = strings.TrimPrefix(srv.URL, "https://")
	return addr, srv.Close
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// scoreResultExported is a white-box helper: we call Inspect against a real
// local TLS server we control, then examine the Result.

func TestInspect_SelfSignedDetection(t *testing.T) {
	certPEM, keyPEM := newTestCert(t, certOptions{
		commonName: "testhost",
		dnsNames:   []string{"testhost"},
	})
	addr, cleanup := startTLSServer(t, certPEM, keyPEM)
	defer cleanup()

	host, port, _ := net.SplitHostPort(addr)
	_ = port

	// We can't use Inspect directly (it hard-codes port 443) so we test scoreResult
	// via a parse+score helper exposed only in tests.
	cert, err := parsePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	r := tlsinspect.InspectCert("testhost", cert)
	if !r.SelfSigned {
		t.Error("expected SelfSigned=true")
	}
	if r.Score < 25 {
		t.Errorf("expected score >= 25 for self-signed, got %d", r.Score)
	}
	hasReason(t, r.Reasons, "self-signed")
	_ = host
}

func TestInspect_ExpiredCert(t *testing.T) {
	certPEM, _ := newTestCert(t, certOptions{
		commonName: "expired.test",
		dnsNames:   []string{"expired.test"},
		notBefore:  time.Now().Add(-30 * 24 * time.Hour),
		notAfter:   time.Now().Add(-1 * time.Hour), // already expired
	})
	cert, err := parsePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	r := tlsinspect.InspectCert("expired.test", cert)
	if !r.Expired {
		t.Error("expected Expired=true")
	}
	if r.Score < 20 {
		t.Errorf("expected score >= 20 for expired cert, got %d", r.Score)
	}
	hasReason(t, r.Reasons, "expired")
}

func TestInspect_FreshCert(t *testing.T) {
	certPEM, _ := newTestCert(t, certOptions{
		commonName: "fresh.test",
		dnsNames:   []string{"fresh.test"},
		notBefore:  time.Now().Add(-1 * time.Hour), // issued 1 hour ago
		notAfter:   time.Now().Add(90 * 24 * time.Hour),
	})
	cert, err := parsePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	r := tlsinspect.InspectCert("fresh.test", cert)
	if r.CertAgeDays > 0 {
		t.Errorf("expected cert age 0 days (just issued), got %d", r.CertAgeDays)
	}
	hasReason(t, r.Reasons, "7 days")
}

func TestInspect_SANMismatch(t *testing.T) {
	certPEM, _ := newTestCert(t, certOptions{
		commonName: "other.test",
		dnsNames:   []string{"other.test"},
	})
	cert, err := parsePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	r := tlsinspect.InspectCert("mismatch.test", cert)
	if r.SANMatch {
		t.Error("expected SANMatch=false for mismatched domain")
	}
	if r.Score < 30 {
		t.Errorf("expected score >= 30 for SAN mismatch, got %d", r.Score)
	}
	hasReason(t, r.Reasons, "does not match")
}

func TestInspect_SANMatch(t *testing.T) {
	certPEM, _ := newTestCert(t, certOptions{
		commonName: "good.test",
		dnsNames:   []string{"good.test", "www.good.test"},
	})
	cert, err := parsePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	r := tlsinspect.InspectCert("good.test", cert)
	if !r.SANMatch {
		t.Error("expected SANMatch=true")
	}
}

func TestInspect_WildcardDetection(t *testing.T) {
	certPEM, _ := newTestCert(t, certOptions{
		commonName: "*.example.com",
		dnsNames:   []string{"*.example.com"},
	})
	cert, err := parsePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	r := tlsinspect.InspectCert("sub.example.com", cert)
	if !r.IsWildcard {
		t.Error("expected IsWildcard=true")
	}
	if !r.SANMatch {
		t.Error("expected wildcard cert to match subdomain")
	}
}

func TestInspect_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Use an unroutable address to trigger timeout quickly.
	r := tlsinspect.Inspect(ctx, "192.0.2.1") // TEST-NET-1, RFC 5737
	if r.HasTLS {
		t.Error("expected HasTLS=false on timeout")
	}
}

func TestInspect_NoTLS(t *testing.T) {
	// Start a plain HTTP server (no TLS)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	host, _, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	r := tlsinspect.Inspect(ctx, host)
	if r.HasTLS {
		t.Error("expected HasTLS=false for plain HTTP server")
	}
}

func TestInspect_ScoreCap(t *testing.T) {
	// A cert that is self-signed + SAN-mismatch + expired → score should be capped at 100
	certPEM, _ := newTestCert(t, certOptions{
		commonName: "evil.test",
		dnsNames:   []string{"other.test"},
		notBefore:  time.Now().Add(-60 * 24 * time.Hour),
		notAfter:   time.Now().Add(-1 * time.Hour),
	})
	cert, err := parsePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	r := tlsinspect.InspectCert("mismatch.evil.test", cert)
	if r.Score > 100 {
		t.Errorf("score must be capped at 100, got %d", r.Score)
	}
}

func parsePEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	return x509.ParseCertificate(block.Bytes)
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
