package main

import "testing"

func TestGenerateSelfSignedCert(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate self-signed cert: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected at least one certificate in the chain")
	}
	if cert.PrivateKey == nil {
		t.Fatal("expected private key to be set")
	}
}
