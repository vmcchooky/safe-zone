package analysis

import (
	"context"
	"encoding/json"
	"math"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"safe-zone/internal/config"
)

type Verdict string

const (
	VerdictInvalid    Verdict = "INVALID"
	VerdictSafe       Verdict = "SAFE"
	VerdictSuspicious Verdict = "SUSPICIOUS"
	VerdictMalicious  Verdict = "MALICIOUS"
)

type Result struct {
	Domain     string   `json:"domain"`
	Verdict    Verdict  `json:"verdict"`
	Confidence float64  `json:"confidence"`
	Score      int      `json:"score"`
	Reasons    []string `json:"reasons"`
	Category   string   `json:"category,omitempty"` // e.g., "social_media", "adult", "gambling", "gaming", "advertising", "malware", "phishing", "uncategorized"
}

const (
	protectedPublicServiceReason = "protected Vietnamese public-service keyword abuse (dichvucong)"
	highEntropyDGAReason         = "high_entropy_dga_suspected"
)

type Analyzer struct {
	config     config.AnalysisConfig
	brandStore BrandStore
}

func NewAnalyzer(cfg config.AnalysisConfig) *Analyzer {
	return NewAnalyzerWithBrandStore(cfg, NewMemoryBrandStore(DefaultTrustedBrands()))
}

func NewAnalyzerWithBrandStore(cfg config.AnalysisConfig, brandStore BrandStore) *Analyzer {
	if brandStore == nil {
		brandStore = NewMemoryBrandStore(DefaultTrustedBrands())
	}
	return &Analyzer{
		config:     cfg,
		brandStore: brandStore,
	}
}

func Analyze(input string) Result {
	// Fallback function for compatibility, uses default config
	return NewAnalyzer(config.DefaultAnalysisConfig()).Analyze(input)
}

func ClassifyCategory(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return "uncategorized"
	}

	// Helper to check suffix
	hasSuffix := func(d, parent string) bool {
		return d == parent || strings.HasSuffix(d, "."+parent)
	}

	// 1. Social Media
	socialDomains := []string{
		"facebook.com", "fb.com", "messenger.com", "instagram.com", "tiktok.com",
		"twitter.com", "x.com", "youtube.com", "youtu.be", "reddit.com",
		"linkedin.com", "pinterest.com", "snapchat.com", "tumblr.com",
		"whatsapp.com", "telegram.org", "t.me", "discord.com", "discord.gg",
	}
	for _, sd := range socialDomains {
		if hasSuffix(domain, sd) {
			return "social_media"
		}
	}

	// 2. Advertising / Tracker
	adDomains := []string{
		"doubleclick.net", "adservice.google.com", "adnxs.com", "adsrvr.org",
		"rubiconproject.com", "adcolony.com", "unityads.com", "applovin.com",
		"criteo.com", "taboola.com", "outbrain.com", "google-analytics.com",
		"scorecardresearch.com", "hotjar.com", "mixpanel.com",
	}
	for _, ad := range adDomains {
		if hasSuffix(domain, ad) {
			return "advertising"
		}
	}
	// Check prefixes or contains for advertising
	if strings.HasPrefix(domain, "ads.") || strings.HasPrefix(domain, "ad.") ||
		strings.Contains(domain, "analytics.") || strings.Contains(domain, "tracker.") ||
		strings.Contains(domain, "telemetry.") || strings.Contains(domain, "-analytics") ||
		strings.Contains(domain, "adserver") {
		return "advertising"
	}

	// 3. Adult Content
	adultTLDs := []string{".xxx", ".adult", ".sexy", ".porn"}
	for _, tld := range adultTLDs {
		if strings.HasSuffix(domain, tld) {
			return "adult"
		}
	}
	adultKeywords := []string{"porn", "sex", "xvideos", "xnxx", "pornhub", "redtube", "onlyfans", "erotic", "hentai", "jav"}
	for _, kw := range adultKeywords {
		if strings.Contains(domain, kw) {
			return "adult"
		}
	}

	// 4. Gambling
	gamblingKeywords := []string{"casino", "gamble", "lottery", "poker", "slot", "w88", "fun88", "m88", "188bet", "kubet", "bet88", "blackjack", "roulette"}
	for _, kw := range gamblingKeywords {
		if strings.Contains(domain, kw) {
			return "gambling"
		}
	}

	// 5. Gaming
	gamingDomains := []string{
		"roblox.com", "minecraft.net", "twitch.tv", "steamcommunity.com",
		"steampowered.com", "playstation.com", "xbox.com", "nintendo.com",
		"pubg.com", "epicgames.com", "riotgames.com", "blizzard.com",
		"origin.com", "ubisoft.com", "ea.com",
	}
	for _, gd := range gamingDomains {
		if hasSuffix(domain, gd) {
			return "gaming"
		}
	}
	gamingKeywords := []string{"gaming", "arcade", "playgame"}
	for _, kw := range gamingKeywords {
		if strings.Contains(domain, kw) {
			return "gaming"
		}
	}

	return "uncategorized"
}

func (a *Analyzer) Analyze(input string) Result {
	domain, err := NormalizeDomain(input)
	if err != nil {
		return Result{
			Domain:     strings.TrimSpace(input),
			Verdict:    VerdictInvalid,
			Confidence: 1,
			Score:      100,
			Reasons:    []string{err.Error()},
			Category:   "uncategorized",
		}
	}

	score := 0
	reasons := make([]string, 0, 6)

	if strings.HasPrefix(domain, "xn--") || strings.Contains(domain, ".xn--") {
		score += a.config.PunycodeScore
		reasons = append(reasons, "punycode detected")
	}

	if len(domain) > a.config.LongDomainLength {
		score += a.config.LongDomainScore
		reasons = append(reasons, "domain is long")
	}

	if hyphenCount := strings.Count(domain, "-"); hyphenCount >= a.config.HyphenCountThreshold {
		score += a.config.HyphenScore
		reasons = append(reasons, "many hyphens")
	}

	if digitRatio(domain) > a.config.DigitRatioThreshold {
		score += a.config.DigitRatioScore
		reasons = append(reasons, "high digit ratio")
	}

	if mixedScripts(domain) {
		score += a.config.MixedScriptScore
		reasons = append(reasons, "mixed script characters")
	}

	hasSuspiciousKeyword := false
	if keywordCount, keywordScore := a.suspiciousKeywordStats(domain); keywordScore > 0 {
		hasSuspiciousKeyword = true
		score += keywordScore
		reasons = append(reasons, "phishing keyword pattern")
		if keywordCount >= 2 {
			reasons = append(reasons, "multiple phishing keywords")
		}
	}

	if isProtectedVietnamPublicServiceAbuse(domain) {
		if score < 75 {
			score = 75
		}
		reasons = append(reasons, protectedPublicServiceReason)
	}

	// 7. Advanced Brand Spoofing Detection
	brands := a.trustedBrands()
	if isSpoof, reason, penalty := CheckBrandSpoofingWithBrands(domain, a.config.BrandSpoofingScore, brands); isSpoof {
		score += penalty
		reasons = append(reasons, reason)
	}

	// 8. Shannon Entropy Analysis (DGA detection)
	mainLabel := getMainLabel(domain)
	if len(mainLabel) >= 10 &&
		!strings.Contains(mainLabel, "-") &&
		!hasSuspiciousKeyword &&
		!IsTrustedBrandSuffix(domain, brands) {
		entropy := ShannonEntropy(mainLabel)
		if entropy > a.config.EntropyThreshold {
			score += a.config.EntropyScore
			reasons = append(reasons, highEntropyDGAReason)
		}
	}

	if score > 100 {
		score = 100
	}

	verdict := VerdictSafe
	switch {
	case score >= 70:
		verdict = VerdictMalicious
	case score >= 40:
		verdict = VerdictSuspicious
	}

	category := ClassifyCategory(domain)
	if category == "uncategorized" {
		if verdict == VerdictMalicious {
			category = "malware"
			for _, r := range reasons {
				if strings.Contains(strings.ToLower(r), "phishing") {
					category = "phishing"
					break
				}
			}
		} else if verdict == VerdictSuspicious {
			category = "suspicious"
		}
	}

	return Result{
		Domain:     domain,
		Verdict:    verdict,
		Confidence: math.Min(1, 0.45+float64(score)/120),
		Score:      score,
		Reasons:    reasons,
		Category:   category,
	}
}

func (a *Analyzer) trustedBrands() []Brand {
	if a == nil || a.brandStore == nil {
		return DefaultTrustedBrands()
	}
	brands, err := a.brandStore.ListBrands(context.Background())
	if err != nil || len(brands) == 0 {
		return DefaultTrustedBrands()
	}
	return brands
}

func isProtectedVietnamPublicServiceAbuse(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || !strings.Contains(domain, "dichvucong") {
		return false
	}

	root := getRootDomain(domain)
	if root == "dichvucong.gov.vn" || strings.HasSuffix(root, ".gov.vn") || strings.HasSuffix(domain, ".gov.vn") {
		return false
	}

	return strings.Contains(root, "dichvucong")
}

func NormalizeDomain(input string) (string, error) {
	value := strings.TrimSpace(strings.ToLower(input))
	if value == "" {
		return "", errInvalidDomain("domain is empty")
	}

	// Support URLs without scheme but containing a path (e.g., ebank.tpb.vn/retail/vx/)
	if strings.Contains(value, "/") && !strings.Contains(value, "://") && !strings.HasPrefix(value, "/") {
		value = "http://" + value
	}

	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" {
			return "", errInvalidDomain("domain could not be parsed from url")
		}
		value = parsed.Hostname()
	}

	if strings.Count(value, ":") == 1 {
		parts := strings.SplitN(value, ":", 2)
		if parts[0] != "" {
			value = parts[0]
		}
	}

	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return "", errInvalidDomain("domain is empty")
	}

	for _, r := range value {
		if r == '.' || r == '-' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		if r > utf8.RuneSelf {
			continue
		}
		return "", errInvalidDomain("domain contains invalid characters")
	}

	return value, nil
}

func MarshalResult(result Result) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}

func digitRatio(value string) float64 {
	if value == "" {
		return 0
	}

	digitCount := 0
	for _, r := range value {
		if unicode.IsDigit(r) {
			digitCount++
		}
	}

	return float64(digitCount) / float64(len(value))
}

func mixedScripts(value string) bool {
	hasLatin := false
	hasNonLatin := false

	for _, r := range value {
		if r == '.' || r == '-' || unicode.IsDigit(r) {
			continue
		}
		if r <= utf8.RuneSelf {
			hasLatin = true
			continue
		}
		hasNonLatin = true
	}

	return hasLatin && hasNonLatin
}

func (a *Analyzer) suspiciousKeywordStats(value string) (int, int) {
	keywords := a.config.GetKeywords()
	keywordCount := 0
	for _, keyword := range keywords {
		if strings.Contains(value, keyword) {
			keywordCount++
		}
	}

	if keywordCount == 0 {
		return 0, 0
	}

	keywordScore := a.config.KeywordBaseScore + keywordCount*a.config.KeywordMatchScore
	if keywordCount >= 2 {
		keywordScore += a.config.KeywordMultipleBonus
	}

	return keywordCount, keywordScore
}

type invalidDomainError string

func (e invalidDomainError) Error() string {
	return string(e)
}

func errInvalidDomain(message string) error {
	return invalidDomainError(message)
}
