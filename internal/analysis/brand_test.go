package analysis

import (
	"strings"
	"testing"
)

func TestLevenshteinDistance(t *testing.T) {
	tests := []struct {
		s1, s2   string
		expected int
	}{
		{"google", "googel", 2},
		{"paypal", "paypa1", 1},
		{"binance", "binancee", 1},
		{"binance", "biance", 1},
		{"apple", "apple", 0},
		{"", "abc", 3},
		{"abc", "", 3},
		{"apple", "banana", 5},
	}

	for _, tc := range tests {
		got := LevenshteinDistance(tc.s1, tc.s2)
		if got != tc.expected {
			t.Errorf("LevenshteinDistance(%q, %q) = %d; expected %d", tc.s1, tc.s2, got, tc.expected)
		}
	}
}

func TestWeightedLevenshteinDistance(t *testing.T) {
	tests := []struct {
		s1, s2   string
		expected float64
	}{
		{"google", "goofle", 0.5},           // f kề g
		{"google", "googel", 2.0},           // e và l không liền kề nhau trên QWERTY
		{"binance", "binamce", 0.5},         // m kề n
		{"vietcombank", "bietcombamk", 1.0}, // b kề v (0.5), m kề n (0.5)
		{"apple", "apple", 0.0},
	}

	for _, tc := range tests {
		got := WeightedLevenshteinDistance(tc.s1, tc.s2)
		if got != tc.expected {
			t.Errorf("WeightedLevenshteinDistance(%q, %q) = %f; expected %f", tc.s1, tc.s2, got, tc.expected)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	lowEntropy := ShannonEntropy("aaaa")
	if lowEntropy != 0.0 {
		t.Errorf("expected entropy of 'aaaa' to be 0.0, got %f", lowEntropy)
	}

	medEntropy := ShannonEntropy("google")
	highEntropy := ShannonEntropy("qweasdzxc123")

	if highEntropy <= medEntropy {
		t.Errorf("expected 'qweasdzxc123' entropy (%f) to be higher than 'google' (%f)", highEntropy, medEntropy)
	}
}

func TestGetRootDomain(t *testing.T) {
	tests := []struct {
		domain   string
		expected string
	}{
		{"google.com", "google.com"},
		{"sub.google.com", "google.com"},
		{"a.b.c.google.com", "google.com"},
		{"google.com.vn", "google.com.vn"},
		{"sub.google.com.vn", "google.com.vn"},
		{"binance.co.uk", "binance.co.uk"},
		{"sub.binance.co.uk", "binance.co.uk"},
		{"localhost", "localhost"},
		{"com.vn", "com.vn"},
	}

	for _, tc := range tests {
		got := getRootDomain(tc.domain)
		if got != tc.expected {
			t.Errorf("getRootDomain(%q) = %q; expected %q", tc.domain, got, tc.expected)
		}
	}
}

func TestCheckBrandSpoofing(t *testing.T) {
	tests := []struct {
		domain          string
		expectedSpoof   bool
		expectedReason  string
		expectedPenalty int
	}{
		// --- Phishing Cases (International) ---
		{"googel.com", true, "typosquatting of google", 50},
		{"paypa1.com", true, "typosquatting of paypal", 50},
		{"binancee.com", true, "typosquatting of binance", 50},
		{"binance-support.net", true, "suspicious usage of trusted brand keyword (binance)", 50},
		{"login-paypal-verify.com", true, "suspicious usage of trusted brand keyword (paypal)", 50},
		{"paypal.secure-login-verify.com", true, "suspicious brand subdomain usage (paypal)", 40},
		{"metamask-update.io", true, "suspicious usage of trusted brand keyword (metamask)", 50},

		// --- Phishing Cases (Vietnam Government & Banks) ---
		{"vietconbank.com.vn", true, "typosquatting of vietcombank", 50},
		{"chinhphuvn-gov.cc", true, "suspicious usage of trusted brand keyword (chinhphu)", 70}, // cc là high-risk TLD (+20)
		{"vietcombank.secure-login-verify.com", true, "suspicious brand subdomain usage (vietcombank)", 40},
		{"bocongan-verify.xyz", true, "suspicious usage of trusted brand keyword (bocongan)", 70}, // xyz là high-risk TLD (+20)

		// --- Homoglyph & IDN Visual Spoofing Cases ---
		{"g\u043e\u043egle.com", true, "homoglyph visual spoofing of google", 50},                          // o Cyrillic
		{"v\u0456\u0435t\u0441\u043emb\u0430nk.com", true, "homoglyph visual spoofing of vietcombank", 50}, // TLD .com, i, e, c, a Cyrillic.

		// --- Keyboard Typosquatting Cases ---
		{"goofle.com", true, "keyboard typosquatting of google", 50},
		{"bietcombamk.com.vn", true, "keyboard typosquatting of vietcombank", 50},

		// --- High-Risk TLD Penalty Cases ---
		{"vietcombank.xyz", true, "suspicious usage of trusted brand keyword (vietcombank)", 70}, // TLD .xyz (+20)
		{"chinhphu.top", true, "suspicious usage of trusted brand keyword (chinhphu)", 70},       // TLD .top (+20)

		// --- Safe / Official Cases ---
		{"google.com", false, "", 0},
		{"support.google.com.vn", false, "", 0},
		{"fb.com", false, "", 0},
		{"sub.messenger.com", false, "", 0},
		{"pine.com", false, "", 0}, // safe, unrelated generic word
		{"chinhphu.vn", false, "", 0},
		{"bocongan.gov.vn", false, "", 0},
		{"vietcombank.com.vn", false, "", 0},
		{"support.vietcombank.com.vn", false, "", 0},
		{"ebank.tpb.vn", false, "", 0},
	}

	for _, tc := range tests {
		gotSpoof, gotReason, gotPenalty := CheckBrandSpoofing(tc.domain, 50)
		if gotSpoof != tc.expectedSpoof {
			t.Fatalf("CheckBrandSpoofing(%q) spoof state = %v; expected %v", tc.domain, gotSpoof, tc.expectedSpoof)
		}
		if tc.expectedSpoof {
			if !strings.Contains(gotReason, tc.expectedReason) {
				t.Errorf("CheckBrandSpoofing(%q) reason = %q; expected containing %q", tc.domain, gotReason, tc.expectedReason)
			}
			if gotPenalty != tc.expectedPenalty {
				t.Errorf("CheckBrandSpoofing(%q) penalty = %d; expected %d", tc.domain, gotPenalty, tc.expectedPenalty)
			}
		}
	}
}

func TestAnalyzeBrandSpoofingIntegration(t *testing.T) {
	result := Analyze("googel.com")
	if result.Verdict != VerdictMalicious && result.Verdict != VerdictSuspicious {
		t.Errorf("expected googel.com to be malicious/suspicious, got %s", result.Verdict)
	}

	hasSpoofReason := false
	for _, r := range result.Reasons {
		if strings.Contains(r, "typosquatting of google") {
			hasSpoofReason = true
			break
		}
	}
	if !hasSpoofReason {
		t.Errorf("expected googel.com reasons to contain typosquatting, got %v", result.Reasons)
	}

	// High entropy test
	resultEntropy := Analyze("qweasdzxc123.biz")
	hasEntropyReason := false
	for _, r := range resultEntropy.Reasons {
		if r == highEntropyDGAReason {
			hasEntropyReason = true
			break
		}
	}
	if !hasEntropyReason {
		t.Errorf("expected high entropy DGA reason, got %v", resultEntropy.Reasons)
	}
}
