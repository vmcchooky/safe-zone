package analysis

import (
	"testing"

	"safe-zone/internal/config"
)

// FP-guard 2026-09: production telemetry showed 144 MALICIOUS hits over
// 7 days collapsing to 18 shared-infrastructure hosts. These tests pin the
// algorithmic fixes so the same hostnames never score MALICIOUS again.

func TestShortBrandTyposquatGuard(t *testing.T) {
	// Distance-2 collisions on 4-character names must not fire.
	for _, domain := range []string{
		"miui.com",
		"zoho.com",
		"update.intl.miui.com",
		"accounts.zoho.com",
	} {
		if spoof, reason, _ := CheckBrandSpoofing(domain, 50); spoof {
			t.Errorf("CheckBrandSpoofing(%q) = spoof (%q); want no spoof", domain, reason)
		}
	}
	// Official short-brand roots stay trusted.
	for _, domain := range []string{"tiki.vn", "momo.vn"} {
		if spoof, reason, _ := CheckBrandSpoofing(domain, 50); spoof {
			t.Errorf("CheckBrandSpoofing(%q) = spoof (%q); want no spoof", domain, reason)
		}
	}
	// Longer names keep full distance-2 sensitivity on ordinary roots.
	for _, domain := range []string{"googel.com", "mebank.com", "vietconbank.com.vn"} {
		if spoof, _, _ := CheckBrandSpoofing(domain, 50); !spoof {
			t.Errorf("CheckBrandSpoofing(%q) = no spoof; want spoof", domain)
		}
	}
}

func TestCDNInfraAdvisoryPenalty(t *testing.T) {
	// Delegated customer naming under shared CDN roots (exact or
	// containing label) is advisory (10).
	for _, domain := range []string{
		"dualstack.video.twitter.map.fastly.net",
		"dcg.microsoft.com.b-0005.b-msedge.net",
		"deo.shopeemobile.com.baishan-cloud.net",
		"zshopee.v.baishan-cloud.net",
	} {
		spoof, reason, penalty := CheckBrandSpoofing(domain, 50)
		if !spoof {
			t.Errorf("CheckBrandSpoofing(%q) = no spoof; want advisory spoof", domain)
			continue
		}
		if penalty != cdnInfraAdvisoryPenalty {
			t.Errorf("CheckBrandSpoofing(%q) penalty = %d; want advisory %d (%q)",
				domain, penalty, cdnInfraAdvisoryPenalty, reason)
		}
	}
	// Hyphen-composed labels keep full weight even on CDN roots
	// (attacker-style composition, not delegated naming).
	for _, tc := range []struct {
		domain  string
		penalty int
	}{
		{"paypal-login.fastly.net", 40},
		{"vietcombank-login.cloudfront.net", 40},
	} {
		spoof, reason, penalty := CheckBrandSpoofing(tc.domain, 50)
		if !spoof || penalty != tc.penalty {
			t.Errorf("CheckBrandSpoofing(%q) = %v/%d (%q); want true/%d",
				tc.domain, spoof, penalty, reason, tc.penalty)
		}
	}
	// Same patterns on ordinary roots keep full weight.
	spoof, _, penalty := CheckBrandSpoofing("paypal.secure-login-verify.com", 50)
	if !spoof || penalty != 40 {
		t.Errorf("CheckBrandSpoofing(paypal.secure-login-verify.com) = %v/%d; want true/40", spoof, penalty)
	}
	// Exact homoglyph visual spoofing keeps full weight even on CDN roots
	// (Cyrillic o U+043E / U+0435 below).
	homoglyph := "g" + "\u043e" + "\u043e" + "gle.fastly.net"
	spoof, _, penalty = CheckBrandSpoofing(homoglyph, 50)
	if !spoof || penalty != 50 {
		t.Errorf("homoglyph on CDN root = %v/%d; want true/50", spoof, penalty)
	}
}

func TestTrustedInfraBrands(t *testing.T) {
	// Developer/alibaba infra roots are trusted infrastructure suffixes
	// (kept out of the ML-frozen default brand seed on purpose).
	for _, domain := range []string{
		"api.github.com",
		"cafe.github.com",
		"github.com",
		"msgacs-lazada-sg.m.taobao.com",
		"acs-lazada-sg.m.taobao.com.gds.alibabadns.com",
		"taobao.com",
		"alibabadns.com",
	} {
		if !IsTrustedInfraSuffix(domain) {
			t.Errorf("IsTrustedInfraSuffix(%q) = false; want true", domain)
		}
		if spoof, reason, _ := CheckBrandSpoofing(domain, 50); spoof {
			t.Errorf("CheckBrandSpoofing(%q) = spoof (%q); want trusted", domain, reason)
		}
	}
	// github.io tenant pages deliberately keep full scrutiny (github.io is
	// NOT trusted infrastructure): an exact feed IOC there still blocks,
	// and brand-keyword tenant names still fire off-root.
	if IsTrustedInfraSuffix("evil-tenant.github.io") {
		t.Error("evil-tenant.github.io must NOT be trusted infrastructure")
	}
	// NOTE: github/taobao lookalike detection off-root (github-login.evil.com)
	// is deliberately NOT added here: those names were never detection
	// brands, and new lexical blocks need shadow evaluation first. Known
	// github.io tenant IOCs are still blocked via exact feed matches.
}

func TestProductionFPLexicalVerdicts(t *testing.T) {
	a := NewAnalyzerWithBrandStore(config.DefaultAnalysisConfig(), NewMemoryBrandStore(DefaultTrustedBrands()))
	fpHosts := []string{
		"update.intl.miui.com",
		"accounts.zoho.com",
		"dualstack.video.twitter.map.fastly.net",
		"dualstack.twimg.twitter.map.fastly.net",
		"dcg.microsoft.com.b-0005.b-msedge.net",
		"msgacs-lazada-sg.m.taobao.com",
		"edge-web-gae2.dual-gslb.spotify.com",
		"v45.gpm.byteoversea.net",
		"alb-9ccdn01d4epztcb2go.us-west-1.alb.aliyuncs.com",
		"sp-cdn-bfile-sg.susercontent.com",
		"zshopee.v.baishan-cloud.net",
		"deo.shopeemobile.com.baishan-cloud.net",
		"deo.shopeemobile.com-v1.edgesuite.net",
		"cf.shopee.vn.akamaized.net",
		"api.github.com",
		"cafe.github.com",
		"cdn.jsdelivr.net",
		"cdn.ampproject.org",
		"acs-m.lazada.sg",
		"img.lazcdn.com",
		"acs-lazada-sg.m.taobao.com.gds.alibabadns.com",
	}
	for _, h := range fpHosts {
		r := a.Analyze(h)
		if r.Verdict == VerdictMalicious {
			t.Errorf("Analyze(%q) = MALICIOUS %d %q; want at most SUSPICIOUS", h, r.Score, r.Reasons)
		}
	}
	// Lazada first-party (owner-confirmed 2026-09-20): no lazada-brand
	// fire on the regional domain, the CDN, or the Alibaba DNS chain.
	for _, h := range []string{"acs-m.lazada.sg", "img.lazcdn.com", "acs-lazada-sg.m.taobao.com.gds.alibabadns.com"} {
		if spoof, reason, _ := CheckBrandSpoofing(h, 50); spoof {
			t.Errorf("CheckBrandSpoofing(%q) = spoof (%q); want first-party clean", h, reason)
		}
	}
	// Alias boundary: the brand name composed off-root still fires.
	if spoof, _, _ := CheckBrandSpoofing("login-lazada.evil.com", 50); !spoof {
		t.Error("CheckBrandSpoofing(login-lazada.evil.com) = clean; want spoof (alias covers roots, not attacker composition)")
	}
	// Spot-check the exact scores behind the 7-day telemetry rows.
	spots := map[string]int{
		"update.intl.miui.com":                          25,
		"accounts.zoho.com":                             25,
		"dualstack.video.twitter.map.fastly.net":        25,
		"msgacs-lazada-sg.m.taobao.com":                 15,
		"zshopee.v.baishan-cloud.net":                   25,
		"v45.gpm.byteoversea.net":                       35,
		"acs-m.lazada.sg":                               0,
		"img.lazcdn.com":                                0,
		"acs-lazada-sg.m.taobao.com.gds.alibabadns.com": 15,
	}
	for h, want := range spots {
		if got := a.Analyze(h).Score; got != want {
			t.Errorf("Analyze(%q) score = %d; want %d", h, got, want)
		}
	}
}

func TestCDNRootAdditions(t *testing.T) {
	for _, root := range []string{
		"b-msedge.net", "msedge.net", "baishan-cloud.net",
		"jsdelivr.net", "ampproject.org", "susercontent.com",
	} {
		if !IsCDNRoot(root) {
			t.Errorf("IsCDNRoot(%q) = false; want true", root)
		}
	}
	for _, root := range []string{"github.com", "taobao.com", "sharepoint.com", "google.com"} {
		if IsCDNRoot(root) {
			t.Errorf("IsCDNRoot(%q) = true; want false (brand apex, not CDN)", root)
		}
	}
}
