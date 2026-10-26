package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"safe-zone/internal/config"
	"safe-zone/internal/logjson"
)

// dotCertWarnWindow is the fixed renew-early threshold. It is intentionally
// not an environment knob: a certificate that expires because an operator
// tuned the warning away is worse than a fixed value nobody can forget.
const dotCertWarnWindow = 14 * 24 * time.Hour

// resolveDotCertificate prepares the certificate material for the DoT
// listener.
//
// Three outcomes, in order:
//
//   - A configured key pair loads. A broken pair is always an error: the
//     operator pointed at files, so silently serving something else would
//     hide the mistake. Production additionally refuses a pair that is
//     expired or not yet valid; see checkDotCertificateValidity.
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
		if err := checkDotCertificateValidity(cert); err != nil {
			return tls.Certificate{}, err
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

// checkDotCertificateValidity guards the configured pair against the one
// failure mode LoadX509KeyPair cannot see: a syntactically perfect
// certificate whose validity window is wrong. Production fails on expired or
// not-yet-valid certificates because every DoT client would reject the
// handshake while the resolver reports itself healthy; outside production the
// same conditions only warn so local experiments with throwaway
// certificates keep working. A remaining lifetime under dotCertWarnWindow is
// a warning everywhere: it never blocks startup, it moves renewal into the
// operator's log monitor.
func checkDotCertificateValidity(cert tls.Certificate) error {
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("configured TLS key pair contains no certificate")
	}
	// tls.LoadX509KeyPair leaves Leaf unset; parse the DER directly.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse configured TLS certificate: %w", err)
	}

	notAfter := leaf.NotAfter.UTC().Format(time.RFC3339)
	now := time.Now()

	if now.Before(leaf.NotBefore) {
		err := fmt.Errorf("DoT certificate is not valid before %s; replace it with the current pair", leaf.NotBefore.UTC().Format(time.RFC3339))
		if config.IsProduction() {
			return err
		}
		logjson.Warn("DoT certificate is not yet valid", map[string]any{
			"service":    "dns-resolver",
			"not_before": leaf.NotBefore.UTC().Format(time.RFC3339),
		})
		return nil
	}

	if now.After(leaf.NotAfter) {
		err := fmt.Errorf("DoT certificate expired at %s; export a fresh pair with scripts/ops/export-dot-cert.sh", notAfter)
		if config.IsProduction() {
			return err
		}
		logjson.Warn("DoT certificate has expired", map[string]any{
			"service":   "dns-resolver",
			"not_after": notAfter,
		})
		return nil
	}

	if remaining := time.Until(leaf.NotAfter); remaining < dotCertWarnWindow {
		logjson.Warn("DoT certificate is within the renewal window", map[string]any{
			"service":     "dns-resolver",
			"not_after":   notAfter,
			"days_left":   int(remaining.Hours() / 24),
			"warn_window": dotCertWarnWindow.String(),
			"renew_with":  "scripts/ops/export-dot-cert.sh",
		})
	}
	return nil
}
