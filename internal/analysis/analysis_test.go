package analysis

import (
	"testing"
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
		{"my-tracker-analytics.com", "advertising"},

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

func containsReason(reasons []string, needle string) bool {
	for _, reason := range reasons {
		if reason == needle {
			return true
		}
	}
	return false
}
