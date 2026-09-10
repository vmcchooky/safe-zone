package analysis

import (
	"strings"
	"testing"
)

// Infrastructure roots whose own names embed a trusted brand keyword must
// not fire the main-label keyword rule: amazonaws holds amazon,
// googleadservices holds google. Regression coverage for production
// MALICIOUS verdicts on AWS/Google infra hosts.
func TestAnalyzeInfraRootExemptFromBrandKeyword(t *testing.T) {
	clean := []struct {
		domain       string
		forbiddenSub string
	}{
		{"s3-w.us-east-1.amazonaws.com", "trusted brand keyword (amazon)"},
		{"qcc-omadmhandler-2121182090.us-west-2.elb.amazonaws.com", "trusted brand keyword (amazon)"},
		{"iqia6two1k.execute-api.ap-southeast-1.amazonaws.com", "trusted brand keyword (amazon)"},
		{"www.googleadservices.com", "trusted brand keyword (google)"},
	}
	for _, tt := range clean {
		t.Run(tt.domain, func(t *testing.T) {
			res := analyzeDefault(tt.domain)
			for _, r := range res.Reasons {
				if strings.Contains(r, tt.forbiddenSub) {
					t.Fatalf("infrastructure root %q must not carry %q, reasons=%v", tt.domain, tt.forbiddenSub, res.Reasons)
				}
			}
			if res.Verdict == VerdictMalicious {
				t.Fatalf("infrastructure root %q must not be MALICIOUS from brand substring, got score=%d reasons=%v",
					tt.domain, res.Score, res.Reasons)
			}
		})
	}
}

// The exemption is narrow: glued brand tokens off the exempt roots, token
// parts, typosquats and the protected public-service rule still fire.
func TestAnalyzeBrandKeywordStillFiresOffExemptRoots(t *testing.T) {
	t.Run("glued bucket-style token still fires", func(t *testing.T) {
		res := analyzeDefault("amazon-payments.evil.com")
		if !containsReasonSubstring(res.Reasons, "amazon") {
			t.Fatalf("bucket-style brand token must still fire, reasons=%v", res.Reasons)
		}
	})
	t.Run("glued subdomain still fires", func(t *testing.T) {
		ok, _, _ := CheckBrandSpoofingWithBrands("shopeepay.evil.com", 50, DefaultTrustedBrands())
		if !ok {
			t.Fatal("glued brand subdomain must still be detected off exempt roots")
		}
	})
	t.Run("classic campaign still malicious", func(t *testing.T) {
		res := analyzeDefault("vietcombank-secure-login-verify.top")
		if res.Verdict != VerdictMalicious {
			t.Fatalf("expected MALICIOUS, got %s reasons=%v", res.Verdict, res.Reasons)
		}
	})
	t.Run("protected public-service rule untouched", func(t *testing.T) {
		res := analyzeDefault("dichvucongvn.com")
		if res.Verdict != VerdictMalicious || res.Score < 75 {
			t.Fatalf("expected protected-rule MALICIOUS floor, got %s/%d reasons=%v", res.Verdict, res.Score, res.Reasons)
		}
	})
	t.Run("brand-in-subdomain of exempt root host still fires", func(t *testing.T) {
		// amazonaws as a SUBDOMAIN label (not the root's own name) keeps firing.
		ok, reason, _ := CheckBrandSpoofingWithBrands("login.amazonaws.evil.com", 50, DefaultTrustedBrands())
		if !ok {
			t.Fatal("expected subdomain brand usage to fire outside exempt roots")
		}
		if !strings.Contains(reason, "amazon") {
			t.Fatalf("expected amazon reason, got %q", reason)
		}
	})
}
