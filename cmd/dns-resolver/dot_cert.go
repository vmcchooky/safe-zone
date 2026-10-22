package main

import (
	"crypto/tls"
	"fmt"

	"safe-zone/internal/config"
	"safe-zone/internal/logjson"
)

// resolveDotCertificate prepares the certificate material for the DoT
// listener.
//
// Three outcomes, in order:
//
//   - A configured key pair loads. A broken pair is always an error: the
//     operator pointed at files, so silently serving something else would
//     hide the mistake.
//   - No key pair outside production: a temporary self-signed certificate is
//     generated so a local run needs no certificate plumbing.
//   - No key pair in production: an error. Every DoT client rejects a
//     self-signed certificate, so serving one turns "DoT is enabled" into
//     "DoT silently fails for every client". Refusing to start forces the
//     operator to either mount a trusted certificate or turn DoT off.
func resolveDotCertificate(certFile, keyFile string) (tls.Certificate, error) {
	if certFile != "" || keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("load configured TLS keys (cert=%q key=%q): %w", certFile, keyFile, err)
		}
		return cert, nil
	}

	if config.IsProduction() {
		return tls.Certificate{}, fmt.Errorf("DoT is enabled but no TLS key files are configured; mount a trusted certificate or set SAFE_ZONE_DNS_DOT_ENABLED=false")
	}

	logjson.Warn("TLS key files not configured; generating temporary self-signed cert", map[string]any{
		"service": "dns-resolver",
	})
	cert, err := generateSelfSignedCert()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate self-signed cert: %w", err)
	}
	return cert, nil
}
