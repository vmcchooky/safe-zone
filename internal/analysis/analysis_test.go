package analysis

import (
	"strings"
	"testing"

	"safe-zone/internal/config"
)

func TestClassifyCategory(t *testing.T) {
	tests := []struct {
		domain   string
		expected string
	}{
		{"facebook.com", "social_media"},
		{"sub.facebook.com", "social_media"},
		{"tiktok.com", "social_media"},
		{"chat.whatsapp.com", "social_media"},
		{"google.com", "uncategorized"},

		{"doubleclick.net", "advertising"},
		{"ads.google.com", "advertising"},
		{"adserver.yahoo.com", "advertising"},
		{"my-tracker-analytics.com", "uncategorized"},
		{"ad.nl", "uncategorized"},
		{"ad.gov.vn", "uncategorized"},
		{"issue-tracker.moodle.org", "uncategorized"},
		{"data-analytics.edu", "uncategorized"},

		{"porn.com", "adult"},
		{"something.xxx", "adult"},
		{"xvideos.com", "adult"},
		{"onlyfans.com", "adult"},

		{"casino.com", "gambling"},
		{"w88vn.com", "gambling"},
		{"fun88.com", "gambling"},
		{"playpoker.net", "gambling"},

		{"roblox.com", "gaming"},
		{"minecraft.net", "gaming"},
		{"epicgames.com", "gaming"},
		{"twitch.tv", "gaming"},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := ClassifyCategory(tt.domain)
			if got != tt.expected {
				t.Errorf("ClassifyCategory(%q) = %q; want %q", tt.domain, got, tt.expected)
			}
		})
	}
}

func TestAnalyzeCategoryFallback(t *testing.T) {
	// If domain is clean but matches a category
	res := Analyze("facebook.com")
	if res.Category != "social_media" {
		t.Errorf("expected category social_media, got %s", res.Category)
	}

	// Test a suspicious/malicious domain fallback to malware/phishing
	res2 := Analyze("login-paypal-verify.com")
	if res2.Verdict != VerdictSafe {
		if res2.Verdict == VerdictMalicious && res2.Category != "phishing" && res2.Category != "malware" {
			t.Errorf("expected phishing or malware category for malicious domain, got %s", res2.Category)
		}
		if res2.Verdict == VerdictSuspicious && res2.Category != "suspicious" && res2.Category != "phishing" {
			t.Errorf("expected suspicious or phishing category for suspicious domain, got %s", res2.Category)
		}
	}
}

func TestAnalyzeVietnamPublicServiceAbuse(t *testing.T) {
	result := Analyze("dichvucong-vn.com")
	if result.Verdict != VerdictMalicious {
		t.Fatalf("expected dichvucong-vn.com to be malicious, got %s with score %d and reasons %v", result.Verdict, result.Score, result.Reasons)
	}
	if result.Score < 70 {
		t.Fatalf("expected malicious score >= 70, got %d", result.Score)
	}
	if result.Category != "phishing" {
		t.Fatalf("expected phishing category, got %s", result.Category)
	}
	if !containsReason(result.Reasons, protectedPublicServiceReason) {
		t.Fatalf("expected protected public-service reason, got %v", result.Reasons)
	}
}

func TestAnalyzeVietnamPublicServiceOfficialGovDomains(t *testing.T) {
	for _, domain := range []string{"dichvucong.gov.vn", "dichvucong.hanoi.gov.vn"} {
		t.Run(domain, func(t *testing.T) {
			result := Analyze(domain)
			if result.Verdict == VerdictMalicious {
				t.Fatalf("expected %s not to be escalated to malicious, got %s with reasons %v", domain, result.Verdict, result.Reasons)
			}
			if containsReason(result.Reasons, protectedPublicServiceReason) {
				t.Fatalf("expected no protected public-service reason for %s, got %v", domain, result.Reasons)
			}
		})
	}
}

func TestAnalyzeHighEntropyDGASuspected(t *testing.T) {
	result := Analyze("xjfjwqeoas.com")

	if !containsReason(result.Reasons, highEntropyDGAReason) {
		t.Fatalf("expected high entropy DGA reason, got %v", result.Reasons)
	}

	cfg := config.DefaultAnalysisConfig()
	if result.Score < cfg.EntropyScore {
		t.Fatalf("expected entropy score contribution >= %d, got %d", cfg.EntropyScore, result.Score)
	}

	mainLabel := getMainLabel(result.Domain)
	if mainLabel != "xjfjwqeoas" {
		t.Fatalf("expected entropy to use domain label without TLD, got %q", mainLabel)
	}
	if entropy := ShannonEntropy(mainLabel); entropy <= cfg.EntropyThreshold {
		t.Fatalf("expected entropy %f to exceed threshold %f", entropy, cfg.EntropyThreshold)
	}
}

func TestAnalyzeHighEntropySkipsTrustedBrandRoots(t *testing.T) {
	result := Analyze("vietcombank.com.vn")

	if containsReason(result.Reasons, highEntropyDGAReason) {
		t.Fatalf("expected trusted brand root to skip entropy DGA reason, got %v", result.Reasons)
	}
}

func TestAnalyzeHighEntropySkipsCDNRoots(t *testing.T) {
	result := Analyze("a1b2c3d4e5f6.cloudfront.net")

	if result.Verdict != VerdictSafe {
		t.Fatalf("expected random CDN subdomain to remain safe, got %s with score %d and reasons %v", result.Verdict, result.Score, result.Reasons)
	}
	if result.Score >= 40 {
		t.Fatalf("expected random CDN subdomain score below suspicious threshold, got %d with reasons %v", result.Score, result.Reasons)
	}
	if containsReason(result.Reasons, highEntropyDGAReason) {
		t.Fatalf("expected CDN root to skip entropy DGA reason, got %v", result.Reasons)
	}
}

func TestAnalyzeAllowsDisablingKeywordScoring(t *testing.T) {
	cfg := config.DefaultAnalysisConfig()
	cfg.Keywords = []string{}
	cfg.BrandSpoofingScore = 0
	cfg.EntropyScore = 0
	analyzer := NewAnalyzer(cfg)

	result := analyzer.Analyze("secure-login-wallet-example.com")
	if containsReason(result.Reasons, "phishing keyword pattern") {
		t.Fatalf("expected keyword scoring to be disabled, got %v", result.Reasons)
	}
}

func TestAnalyzeCDNBrandSpoofingStillRuns(t *testing.T) {
	result := Analyze("vietcombank-login.cloudfront.net")

	if result.Verdict != VerdictMalicious {
		t.Fatalf("expected brand spoofing on CDN subdomain to be malicious, got %s with score %d and reasons %v", result.Verdict, result.Score, result.Reasons)
	}
	if !containsReasonSubstring(result.Reasons, "suspicious brand subdomain usage (vietcombank)") {
		t.Fatalf("expected CDN phishing domain to retain brand spoofing reason, got %v", result.Reasons)
	}
	if containsReason(result.Reasons, highEntropyDGAReason) {
		t.Fatalf("expected CDN root to skip entropy DGA reason, got %v", result.Reasons)
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"https://ebank.tpb.vn/retail/vX/", "ebank.tpb.vn", false},
		{"https://ebank.tpb.vn", "ebank.tpb.vn", false},
		{"ebank.tpb.vn/retail/vX/", "ebank.tpb.vn", false},
		{"ebank.tpb.vn", "ebank.tpb.vn", false},
		{"http://Google.com/search?q=test", "google.com", false},
		{"google.com:80/path", "google.com", false},
		{"", "", true},
		{"/starting-with-slash", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := NormalizeDomain(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NormalizeDomain(%q) error = %v; wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.expected {
				t.Errorf("NormalizeDomain(%q) = %q; want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func containsReason(reasons []string, needle string) bool {
	for _, reason := range reasons {
		if reason == needle {
			return true
		}
	}
	return false
}

func containsReasonSubstring(reasons []string, needle string) bool {
	for _, reason := range reasons {
		if strings.Contains(reason, needle) {
			return true
		}
	}
	return false
}
