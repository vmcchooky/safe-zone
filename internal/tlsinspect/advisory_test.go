package tlsinspect_test

import (
	"testing"
	"time"

	"safe-zone/internal/tlsinspect"
)

// FP-guard 2026-09 (M5): weak TLS metadata (SAN mismatch, fresh
// certificate) must be separable from strong signals so callers can
// require corroboration before promoting a host.
func TestAdvisoryScoreMismatchAndFresh(t *testing.T) {
	certPEM, _ := newTestCert(t, certOptions{
		commonName: "other.test",
		dnsNames:   []string{"other.test"},
		// Fresh by default (notBefore = now-24h in the helper).
	})
	cert, err := parsePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	r := tlsinspect.InspectCert("mismatch.test", cert)
	// Helper certs are self-signed: 25 (strong) + 15 fresh + 30 mismatch.
	if r.Score != 70 {
		t.Errorf("Score = %d; want 70 (self-signed 25 + fresh 15 + mismatch 30)", r.Score)
	}
	if r.AdvisoryScore != 45 {
		t.Errorf("AdvisoryScore = %d; want 45", r.AdvisoryScore)
	}
}

func TestAdvisoryScoreExpiredIsStrong(t *testing.T) {
	certPEM, _ := newTestCert(t, certOptions{
		commonName: "expired.test",
		dnsNames:   []string{"expired.test"},
		notBefore:  time.Now().Add(-60 * 24 * time.Hour),
		notAfter:   time.Now().Add(-1 * time.Hour),
	})
	cert, err := parsePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	r := tlsinspect.InspectCert("expired.test", cert)
	// Helper certs are self-signed: 25 (strong) + 20 expired (strong).
	if r.Score != 45 {
		t.Errorf("Score = %d; want 45 (self-signed 25 + expired 20)", r.Score)
	}
	if r.AdvisoryScore != 0 {
		t.Errorf("AdvisoryScore = %d; want 0 (expired is strong, SAN matches)", r.AdvisoryScore)
	}
}

func TestAdvisoryScoreSelfSignedKeepsStrongPart(t *testing.T) {
	certPEM, _ := newTestCert(t, certOptions{
		commonName: "testhost",
		dnsNames:   []string{"testhost"},
	})
	cert, err := parsePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	r := tlsinspect.InspectCert("testhost", cert)
	if r.Score != 40 {
		t.Errorf("Score = %d; want 40 (self-signed 25 + fresh 15)", r.Score)
	}
	if r.AdvisoryScore != 15 {
		t.Errorf("AdvisoryScore = %d; want 15 (fresh part only)", r.AdvisoryScore)
	}
	if r.Score-r.AdvisoryScore != 25 {
		t.Errorf("strong part = %d; want 25 (self-signed)", r.Score-r.AdvisoryScore)
	}
}
