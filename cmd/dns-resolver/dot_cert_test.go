package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/config"
)

func TestResolveDotCertificateRejectsMissingKeyFilesInProduction(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "production")

	_, err := resolveDotCertificate("", "")
	if err == nil {
		t.Fatal("production without TLS key files must fail instead of serving a self-signed certificate")
	}
	if !strings.Contains(err.Error(), "SAFE_ZONE_DNS_DOT_ENABLED=false") {
		t.Fatalf("the error should tell the operator how to fix it, got %v", err)
	}
}

func TestResolveDotCertificateGeneratesSelfSignedOutsideProduction(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "local")

	cert, err := resolveDotCertificate("", "")
	if err != nil {
		t.Fatalf("a local run must not fail without TLS key files, got %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected a generated certificate")
	}
}

func TestResolveDotCertificateRejectsBrokenKeyPair(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "local")

	_, err := resolveDotCertificate("missing-cert.pem", "missing-key.pem")
	if err == nil {
		t.Fatal("a broken key pair must be an error")
	}
}

func TestResolveDotCertificateLoadsConfiguredPair(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "production")

	certFile, keyFile := writeTestKeyPair(t)
	cert, err := resolveDotCertificate(certFile, keyFile)
	if err != nil {
		t.Fatalf("expected the configured pair to load, got %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected a loaded certificate")
	}
}

func TestResolveDotCertificateAcceptsValidPairInProduction(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "production")

	certFile, keyFile := writeTestKeyPairWithValidity(t, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	if _, err := resolveDotCertificate(certFile, keyFile); err != nil {
		t.Fatalf("a certificate with 30 days left must load in production, got %v", err)
	}
}

func TestResolveDotCertificateRejectsExpiredPairInProduction(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "production")

	certFile, keyFile := writeTestKeyPairWithValidity(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	_, err := resolveDotCertificate(certFile, keyFile)
	if err == nil {
		t.Fatal("an expired certificate must fail startup in production")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("the error should name the failure, got %v", err)
	}
}

func TestResolveDotCertificateRejectsNotYetValidPairInProduction(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "production")

	certFile, keyFile := writeTestKeyPairWithValidity(t, time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))
	_, err := resolveDotCertificate(certFile, keyFile)
	if err == nil {
		t.Fatal("a not-yet-valid certificate must fail startup in production")
	}
	if !strings.Contains(err.Error(), "not valid") {
		t.Fatalf("the error should name the failure, got %v", err)
	}
}

func TestResolveDotCertificateWarnsButStartsWithExpiringPair(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "production")

	// Inside the 14-day renewal window, still valid: must not block startup.
	certFile, keyFile := writeTestKeyPairWithValidity(t, time.Now().Add(-time.Hour), time.Now().Add(5*24*time.Hour))
	if _, err := resolveDotCertificate(certFile, keyFile); err != nil {
		t.Fatalf("a certificate with 5 days left must still load, got %v", err)
	}
}

func TestResolveDotCertificateAllowsExpiredPairOutsideProduction(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "local")

	// Local runs keep working with throwaway certificates; the expiry is a
	// warning there, not a startup failure.
	certFile, keyFile := writeTestKeyPairWithValidity(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	cert, err := resolveDotCertificate(certFile, keyFile)
	if err != nil {
		t.Fatalf("an expired certificate must not fail startup outside production, got %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected the expired certificate to load")
	}
}

func TestResolveDotCertificateAllowsNotYetValidPairOutsideProduction(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "test")

	certFile, keyFile := writeTestKeyPairWithValidity(t, time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))
	if _, err := resolveDotCertificate(certFile, keyFile); err != nil {
		t.Fatalf("a not-yet-valid certificate must not fail startup outside production, got %v", err)
	}
}

// writeTestKeyPair writes a throwaway certificate/key pair to the test
// temporary directory and returns their paths.
func writeTestKeyPair(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	certPEM, keyPEM, err := generateSelfSignedCertPEM()
	if err != nil {
		t.Fatalf("generate test key pair: %v", err)
	}

	dir := t.TempDir()
	certFile = dir + "/fullchain.pem"
	keyFile = dir + "/privkey.pem"
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	return certFile, keyFile
}

// writeTestKeyPairWithValidity writes a throwaway pair whose validity window
// is fixed by the caller, so tests can produce expired and not-yet-valid
// certificates without clock tricks.
func writeTestKeyPairWithValidity(t *testing.T, notBefore, notAfter time.Time) (certFile, keyFile string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "safezone-test.local"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	dir := t.TempDir()
	certFile = dir + "/fullchain.pem"
	keyFile = dir + "/privkey.pem"
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	return certFile, keyFile
}

func TestProductionDetection(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "production")
	if !config.IsProduction() {
		t.Fatal("SAFE_ZONE_ENV=production must be detected as production")
	}
	t.Setenv("SAFE_ZONE_ENV", "local")
	if config.IsProduction() {
		t.Fatal("SAFE_ZONE_ENV=local must not be detected as production")
	}
}
