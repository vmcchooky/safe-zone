package main

import (
	"os"
	"strings"
	"testing"

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
