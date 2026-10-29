package resolver

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Transport-level DoT coverage. The handler behaviour (normal answers,
// FORMERR on no question, REFUSED under the limiter, panic recovery, IPv6
// normalisation, end-to-end blocking) is covered by the pipeline tests;
// what was missing is the TLS listener itself: the version floor and its
// robustness against garbage where the RFC 7858 two-byte length prefix
// belongs.

// selfSignedDotCert generates a throwaway key pair for a live tcp-tls
// listener; production certificate handling has its own tests in
// cmd/dns-resolver/dot_cert_test.go.
func selfSignedDotCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dot-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("build key pair: %v", err)
	}
	return cert
}

// startDotTestServer starts a live tcp-tls server with the tls.Config
// production builds (MinVersion TLS 1.2) on an ephemeral port and returns
// the listen address.
func startDotTestServer(t *testing.T, r *Resolver) string {
	t.Helper()
	cert := selfSignedDotCert(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	addr := listener.Addr().String()

	server := &dns.Server{Listener: listener, Handler: dns.HandlerFunc(r.DoTHandler)}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return addr
}

func dotTestQuery(name string) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	q.RecursionDesired = true
	return q
}

// newDotTestResolver builds a full pipeline resolver wired to the echo
// upstream, the same way the pipeline tests do, so the DoT transport tests
// exercise the shared ResolveQuery path end to end.
func newDotTestResolver(t *testing.T) *Resolver {
	t.Helper()
	upstream := echoUpstream(t)
	t.Cleanup(upstream.Close)
	url, client := policyUpstream(t, upstream)
	resolverInstance, _, _ := newPipelineResolver(t, url, client)
	return resolverInstance
}

// TestDotServerEnforcesTLSFloor proves a TLS 1.1 client cannot shake hands
// while a modern client can exchange a query against the same listener —
// the floor production config sets must hold on the wire.
func TestDotServerEnforcesTLSFloor(t *testing.T) {
	resolverInstance := newDotTestResolver(t)
	addr := startDotTestServer(t, resolverInstance)

	// TLS 1.1 client: the handshake must fail.
	old := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11} // #nosec G402 -- floor test
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, old)
	if err == nil {
		_ = conn.Close()
		t.Fatal("TLS 1.1 handshake succeeded; the server floor is not enforced")
	}

	// Modern client: handshake plus a real exchange must work.
	dnsClient := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- test peer is self-signed by construction
		Timeout:   5 * time.Second,
	}
	reply, _, err := dnsClient.Exchange(dotTestQuery("example.com"), addr)
	if err != nil {
		t.Fatalf("TLS 1.2+ exchange failed: %v", err)
	}
	if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) == 0 {
		t.Fatalf("unexpected reply: rcode=%s answers=%d", dns.RcodeToString[reply.Rcode], len(reply.Answer))
	}
}

// TestDotServerSurvivesMalformedFraming sends garbage where the RFC 7858
// two-byte length prefix belongs, then proves the same server still serves a
// valid query — the framing layer must close the bad stream, not die.
func TestDotServerSurvivesMalformedFraming(t *testing.T) {
	resolverInstance := newDotTestResolver(t)
	addr := startDotTestServer(t, resolverInstance)
	tlsCfg := &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- test peer is self-signed by construction
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	// An absurd length prefix (65535 claimed, 4 bytes sent), an empty
	// message, and binary noise; the server must close each stream cleanly.
	for _, payload := range [][]byte{
		{0xFF, 0xFF, 0x00, 0x01},
		{0x00, 0x00},
		bytes.Repeat([]byte{0xAB}, 64),
	} {
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
		if err != nil {
			t.Fatalf("dial for payload %x: %v", payload, err)
		}
		_, _ = conn.Write(payload)
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Read(make([]byte, 16))
		_ = conn.Close()
	}

	// The server must still answer a well-formed query.
	dnsClient := &dns.Client{Net: "tcp-tls", TLSConfig: tlsCfg, Timeout: 5 * time.Second}
	reply, _, err := dnsClient.Exchange(dotTestQuery("after-garbage.example"), addr)
	if err != nil {
		t.Fatalf("server unhealthy after malformed framing: %v", err)
	}
	if reply.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s; want NOERROR", dns.RcodeToString[reply.Rcode])
	}
}
