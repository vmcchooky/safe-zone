package analysis

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

const (
	featureManifestVersionV1 = "1.0.0"
	featureManifestVersionV2 = "2.0.0"
	featureManifestVersionV3 = "3.0.0"
	featureManifestVersionV4 = "4.0.0"
	handcraftedFeatureCount  = 22
	tfidfFeatureCount        = 512
	totalFeatureCount        = handcraftedFeatureCount + tfidfFeatureCount
	tfidfInputDomainASCII    = "domain_ascii"
	tfidfInputWithoutSuffix  = "domain_without_public_suffix"
)

var featureNames = []string{
	"fqdn_length", "num_dots", "num_hyphens", "num_digits", "digit_ratio",
	"entropy", "max_consecutive_consonants", "main_label_length",
	"registrable_domain_length", "subdomain_depth", "token_count", "is_punycode",
	"has_mixed_script", "is_ip_like", "tld_risk_score", "phishing_keyword_count",
	"is_shared_hosting", "min_brand_levenshtein", "min_brand_keyboard_distance",
	"has_brand_homoglyph", "has_brand_in_main_label", "has_brand_in_subdomain",
}

// FeatureManifest is the runtime portion of feature_manifest.v1.json.
type FeatureManifest struct {
	ContractVersion         string         `json:"contract_version"`
	HandcraftedFeatureCount int            `json:"handcrafted_feature_count"`
	TFIDFFeatureCount       int            `json:"tfidf_feature_count"`
	TotalFeatureCount       int            `json:"total_feature_count"`
	FeatureNames            []string       `json:"feature_names"`
	TFIDFConfig             TFIDFConfig    `json:"tfidf_config"`
	IDFByIndex              []float64      `json:"idf_by_index,omitempty"`
	SnapshotPolicy          SnapshotPolicy `json:"snapshot_policy,omitempty"`
}

type SnapshotPolicy struct {
	BaseFiles               map[string]string `json:"base_files,omitempty"`
	KeywordExtensions       []string          `json:"keyword_extensions,omitempty"`
	BrandExtensions         []Brand           `json:"brand_extensions,omitempty"`
	SharedHostingExtensions []string          `json:"shared_hosting_extensions,omitempty"`
	TLDStateEncoding        *TLDStateEncoding `json:"tld_state_encoding,omitempty"`
}

type TLDStateEncoding struct {
	Unknown      float64 `json:"unknown"`
	KnownNeutral float64 `json:"known_neutral"`
	Risky        float64 `json:"risky"`
}

type TFIDFConfig struct {
	NgramRange  []int  `json:"ngram_range"`
	MaxFeatures int    `json:"max_features"`
	Analyzer    string `json:"analyzer"`
	Lowercase   bool   `json:"lowercase"`
	SublinearTF bool   `json:"sublinear_tf"`
	Norm        string `json:"norm"`
	InputView   string `json:"input_view,omitempty"`
}

type canonicalDomain struct {
	ascii           string
	unicode         string
	valid           bool
	ipLike          bool
	suffix          string
	suffixKnown     bool
	registrable     string
	mainLabel       string
	subdomainLabels []string
	subdomainDepth  int
}

var mlIDNAProfile = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),
	idna.StrictDomainName(true),
	idna.VerifyDNSLength(true),
)

var ipLikePattern = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}$`)

var sharedHostingRoots = map[string]struct{}{
	"akamaihd.net": {}, "akamaized.net": {}, "amazonaws.com": {}, "azurecontainerapps.io": {},
	"azureedge.net": {}, "azurefd.net": {}, "azurestaticapps.net": {}, "azurewebsites.net": {},
	"b-cdn.net": {}, "cachefly.net": {}, "cdn77.org": {}, "cloudflare.net": {},
	"cloudfront.net": {}, "edgekey.net": {}, "edgesuite.net": {}, "fastly.net": {},
	"fastlylb.net": {}, "firebaseapp.com": {}, "fly.dev": {}, "github.io": {},
	"githubusercontent.com": {}, "glitch.me": {}, "herokuapp.com": {}, "hwcdn.net": {},
	"netlify.app": {}, "onrender.com": {}, "pages.dev": {}, "railway.app": {},
	"repl.co": {}, "replit.app": {}, "r2.dev": {}, "stackpathdns.com": {},
	"surge.sh": {}, "trafficmanager.net": {}, "vercel.app": {}, "workers.dev": {},
}

var mlPhishingKeywords = []string{
	"login", "secure", "verify", "account", "update", "support", "wallet",
	"dichvucong", "congan", "vneid", "phatnguoi", "xulyphat", "nganhang",
	"xacthuc", "cungcap",
}

// FeatureExtractor recreates the supported handcrafted and character n-gram
// feature contracts. It is immutable after construction and safe for
// concurrent use.
type FeatureExtractor struct {
	manifest      FeatureManifest
	vocab         []string
	index         map[string]int
	idf           []float64
	keywords      []string
	brands        []Brand
	sharedHosting map[string]struct{}
}

func NewFeatureExtractor(manifestPath string) (*FeatureExtractor, error) {
	data, err := os.ReadFile(manifestPath) // #nosec G304 -- the loader supplies the validated bundle manifest path.
	if err != nil {
		return nil, fmt.Errorf("read feature manifest: %w", err)
	}
	var manifest FeatureManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse feature manifest: %w", err)
	}
	if err := validateFeatureManifest(manifest); err != nil {
		return nil, err
	}

	vocab := make([]string, tfidfFeatureCount)
	index := make(map[string]int, tfidfFeatureCount)
	for i, name := range manifest.FeatureNames[handcraftedFeatureCount:] {
		const prefix = "char_2_3_"
		if !strings.HasPrefix(name, prefix) {
			return nil, fmt.Errorf("feature manifest: feature %d has invalid name %q", i+handcraftedFeatureCount, name)
		}
		term := strings.TrimPrefix(name, prefix)
		if term == "" {
			return nil, fmt.Errorf("feature manifest: empty n-gram at index %d", i)
		}
		if _, exists := index[term]; exists {
			return nil, fmt.Errorf("feature manifest: duplicate n-gram %q", term)
		}
		vocab[i] = term
		index[term] = i
	}

	idf := make([]float64, tfidfFeatureCount)
	for i := range idf {
		idf[i] = 1
	}
	if len(manifest.IDFByIndex) != tfidfFeatureCount {
		return nil, fmt.Errorf("feature manifest: idf length %d, expected %d", len(manifest.IDFByIndex), tfidfFeatureCount)
	}
	copy(idf, manifest.IDFByIndex)
	for i, value := range idf {
		if math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 {
			return nil, fmt.Errorf("feature manifest: invalid idf at index %d", i)
		}
	}

	keywords := append([]string(nil), mlPhishingKeywords...)
	brands := DefaultTrustedBrands()
	sharedHosting := make(map[string]struct{}, len(sharedHostingRoots)+len(manifest.SnapshotPolicy.SharedHostingExtensions))
	for root := range sharedHostingRoots {
		sharedHosting[root] = struct{}{}
	}
	if manifest.ContractVersion == featureManifestVersionV3 || manifest.ContractVersion == featureManifestVersionV4 {
		keywords = append(keywords, manifest.SnapshotPolicy.KeywordExtensions...)
		brands = append(brands, cloneBrands(manifest.SnapshotPolicy.BrandExtensions)...)
		for _, root := range manifest.SnapshotPolicy.SharedHostingExtensions {
			sharedHosting[root] = struct{}{}
		}
	}

	return &FeatureExtractor{
		manifest:      manifest,
		vocab:         vocab,
		index:         index,
		idf:           idf,
		keywords:      keywords,
		brands:        brands,
		sharedHosting: sharedHosting,
	}, nil
}

func validateFeatureManifest(manifest FeatureManifest) error {
	if manifest.ContractVersion != featureManifestVersionV1 && manifest.ContractVersion != featureManifestVersionV2 && manifest.ContractVersion != featureManifestVersionV3 && manifest.ContractVersion != featureManifestVersionV4 {
		return fmt.Errorf("unsupported feature manifest version %q", manifest.ContractVersion)
	}
	if manifest.HandcraftedFeatureCount != handcraftedFeatureCount ||
		manifest.TFIDFFeatureCount != tfidfFeatureCount ||
		manifest.TotalFeatureCount != totalFeatureCount {
		return fmt.Errorf("feature manifest count mismatch: handcrafted=%d tfidf=%d total=%d", manifest.HandcraftedFeatureCount, manifest.TFIDFFeatureCount, manifest.TotalFeatureCount)
	}
	if len(manifest.FeatureNames) != totalFeatureCount {
		return fmt.Errorf("feature manifest name count %d, expected %d", len(manifest.FeatureNames), totalFeatureCount)
	}
	for i, name := range featureNames {
		if manifest.FeatureNames[i] != name {
			return fmt.Errorf("feature manifest order mismatch at %d: got %q, expected %q", i, manifest.FeatureNames[i], name)
		}
	}
	if len(manifest.TFIDFConfig.NgramRange) != 2 || manifest.TFIDFConfig.NgramRange[0] != 2 || manifest.TFIDFConfig.NgramRange[1] != 3 ||
		manifest.TFIDFConfig.MaxFeatures != tfidfFeatureCount || manifest.TFIDFConfig.Analyzer != "char" ||
		!manifest.TFIDFConfig.Lowercase || !manifest.TFIDFConfig.SublinearTF || manifest.TFIDFConfig.Norm != "l2" {
		return errors.New("unsupported TF-IDF configuration in feature manifest")
	}
	switch manifest.ContractVersion {
	case featureManifestVersionV1:
		if manifest.TFIDFConfig.InputView != "" && manifest.TFIDFConfig.InputView != tfidfInputDomainASCII {
			return fmt.Errorf("v1 feature manifest has unsupported TF-IDF input view %q", manifest.TFIDFConfig.InputView)
		}
	case featureManifestVersionV2:
		if manifest.TFIDFConfig.InputView != tfidfInputWithoutSuffix {
			return fmt.Errorf("v2 feature manifest requires TF-IDF input view %q", tfidfInputWithoutSuffix)
		}
	case featureManifestVersionV3:
		if manifest.TFIDFConfig.InputView != tfidfInputWithoutSuffix {
			return fmt.Errorf("v3 feature manifest requires TF-IDF input view %q", tfidfInputWithoutSuffix)
		}
		if err := validateV3SnapshotPolicy(manifest.SnapshotPolicy); err != nil {
			return err
		}
	case featureManifestVersionV4:
		if manifest.TFIDFConfig.InputView != tfidfInputWithoutSuffix {
			return fmt.Errorf("v4 feature manifest requires TF-IDF input view %q", tfidfInputWithoutSuffix)
		}
		if err := validateV4SnapshotPolicy(manifest.SnapshotPolicy); err != nil {
			return err
		}
	}
	return nil
}

func validateV3SnapshotPolicy(policy SnapshotPolicy) error {
	expectedFiles := map[string]string{
		"brands":             "brands.v1.json",
		"keywords":           "keywords.v1.json",
		"tld_risk":           "tld_risk.v1.json",
		"shared_hosting":     "shared_hosting.v1.json",
		"homoglyphs":         "homoglyphs.v1.json",
		"keyboard_adjacency": "keyboard_adjacency.v1.json",
	}
	if len(policy.BaseFiles) != len(expectedFiles) {
		return errors.New("v3 feature manifest has an unsupported snapshot base-file set")
	}
	for name, expected := range expectedFiles {
		if policy.BaseFiles[name] != expected {
			return fmt.Errorf("v3 feature manifest snapshot %s must be %q", name, expected)
		}
	}
	expectedKeywords := []string{"xbet", "casino", "slot"}
	if len(policy.KeywordExtensions) != len(expectedKeywords) {
		return errors.New("v3 feature manifest has unsupported keyword extensions")
	}
	for index, expected := range expectedKeywords {
		if policy.KeywordExtensions[index] != expected {
			return errors.New("v3 feature manifest has unsupported keyword extensions")
		}
	}
	if len(policy.BrandExtensions) != 1 {
		return errors.New("v3 feature manifest has unsupported brand extensions")
	}
	brand := normalizeBrandRecord(policy.BrandExtensions[0])
	if brand.Name != "spotify" || brand.OfficialDomain != "spotify.com" ||
		len(brand.AltDomains) != 1 || brand.AltDomains[0] != "spotifycdn.com" {
		return errors.New("v3 feature manifest has unsupported brand extensions")
	}
	expectedSharedHosting := []string{"weebly.com", "weeblysite.com", "godaddysites.com"}
	if len(policy.SharedHostingExtensions) != len(expectedSharedHosting) {
		return errors.New("v3 feature manifest has unsupported shared-hosting extensions")
	}
	for index, expected := range expectedSharedHosting {
		if policy.SharedHostingExtensions[index] != expected {
			return errors.New("v3 feature manifest has unsupported shared-hosting extensions")
		}
	}
	return nil
}

func validateV4SnapshotPolicy(policy SnapshotPolicy) error {
	basePolicy := policy
	basePolicy.TLDStateEncoding = nil
	if err := validateV3SnapshotPolicy(basePolicy); err != nil {
		return err
	}
	encoding := policy.TLDStateEncoding
	if encoding == nil || encoding.Unknown != 0 || encoding.KnownNeutral != 0.5 || encoding.Risky != 1 {
		return errors.New("v4 feature manifest has unsupported TLD state encoding")
	}
	return nil
}

func (e *FeatureExtractor) Manifest() FeatureManifest {
	if e == nil {
		return FeatureManifest{}
	}
	manifest := e.manifest
	manifest.FeatureNames = append([]string(nil), manifest.FeatureNames...)
	manifest.TFIDFConfig.NgramRange = append([]int(nil), manifest.TFIDFConfig.NgramRange...)
	manifest.IDFByIndex = append([]float64(nil), manifest.IDFByIndex...)
	manifest.SnapshotPolicy.KeywordExtensions = append([]string(nil), manifest.SnapshotPolicy.KeywordExtensions...)
	manifest.SnapshotPolicy.BrandExtensions = cloneBrands(manifest.SnapshotPolicy.BrandExtensions)
	manifest.SnapshotPolicy.SharedHostingExtensions = append([]string(nil), manifest.SnapshotPolicy.SharedHostingExtensions...)
	if manifest.SnapshotPolicy.TLDStateEncoding != nil {
		encoding := *manifest.SnapshotPolicy.TLDStateEncoding
		manifest.SnapshotPolicy.TLDStateEncoding = &encoding
	}
	if manifest.SnapshotPolicy.BaseFiles != nil {
		manifest.SnapshotPolicy.BaseFiles = make(map[string]string, len(manifest.SnapshotPolicy.BaseFiles))
		for name, path := range e.manifest.SnapshotPolicy.BaseFiles {
			manifest.SnapshotPolicy.BaseFiles[name] = path
		}
	}
	return manifest
}

func canonicalizeMLDomain(input string) (canonicalDomain, error) {
	value := strings.ToLower(strings.TrimSpace(input))
	if value == "" {
		return canonicalDomain{}, errors.New("empty_input")
	}
	if strings.Contains(value, "/") && !strings.Contains(value, "://") && !strings.HasPrefix(value, "/") {
		value = "http://" + value
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" {
			return canonicalDomain{}, errors.New("parse_error")
		}
		value = parsed.Hostname()
	}
	if strings.Contains(value, ":") && !strings.HasPrefix(value, "[") {
		parts := strings.Split(value, ":")
		if len(parts) == 2 && parts[0] != "" {
			value = parts[0]
		}
	}
	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return canonicalDomain{}, errors.New("empty_input")
	}
	if isIPLike(value) {
		return canonicalDomain{ascii: value, unicode: value, ipLike: true}, errors.New("bare_ip")
	}
	value = strings.TrimPrefix(value, "www.")
	if value == "" {
		return canonicalDomain{}, errors.New("empty_input")
	}
	if len(value) > 253 {
		return canonicalDomain{ascii: value}, errors.New("fqdn_length_exceeded")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" {
			return canonicalDomain{ascii: value}, errors.New("empty_label")
		}
		if len(label) > 63 {
			return canonicalDomain{ascii: value}, errors.New("label_length_exceeded")
		}
	}
	ascii, err := mlIDNAProfile.ToASCII(value)
	if err != nil {
		return canonicalDomain{ascii: value}, fmt.Errorf("idna_error: %w", err)
	}
	unicodeValue, err := mlIDNAProfile.ToUnicode(ascii)
	if err != nil {
		return canonicalDomain{ascii: ascii}, fmt.Errorf("idna_error: %w", err)
	}
	ascii = strings.ToLower(ascii)
	suffix, icann := publicsuffix.PublicSuffix(ascii)
	registrable, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil {
		registrable = ""
	}
	mainLabel := ""
	subdomainLabels := []string(nil)
	if registrable != "" {
		regParts := strings.Split(registrable, ".")
		mainLabel = regParts[0]
		allParts := strings.Split(ascii, ".")
		if len(allParts) > len(regParts) {
			subdomainLabels = append([]string(nil), allParts[:len(allParts)-len(regParts)]...)
		}
	}
	return canonicalDomain{
		ascii:           ascii,
		unicode:         unicodeValue,
		valid:           true,
		suffix:          suffix,
		suffixKnown:     icann || strings.Contains(suffix, "."),
		registrable:     registrable,
		mainLabel:       mainLabel,
		subdomainLabels: subdomainLabels,
		subdomainDepth:  len(subdomainLabels),
	}, nil
}

func isIPLike(value string) bool {
	clean := strings.Trim(value, "[]")
	return net.ParseIP(clean) != nil || ipLikePattern.MatchString(clean)
}

func (e *FeatureExtractor) Extract(domain string) ([]float64, error) {
	if e == nil {
		return nil, errors.New("feature extractor is nil")
	}
	canonical, err := canonicalizeMLDomain(domain)
	if err != nil || !canonical.valid {
		return nil, fmt.Errorf("unsupported domain input: %w", err)
	}
	return e.ExtractCanonical(canonical), nil
}

func (e *FeatureExtractor) ExtractCanonical(canonical canonicalDomain) []float64 {
	features := make([]float64, totalFeatureCount)
	if !canonical.valid {
		return features
	}
	ascii := canonical.ascii
	features[0] = float64(len(ascii))
	features[1] = float64(strings.Count(ascii, "."))
	features[2] = float64(strings.Count(ascii, "-"))
	for _, r := range ascii {
		if r >= '0' && r <= '9' {
			features[3]++
		}
	}
	if len(ascii) > 0 {
		features[4] = features[3] / float64(len(ascii))
	}
	features[5] = ShannonEntropy(canonical.mainLabel)
	features[6] = float64(maxConsecutiveConsonants(ascii))
	features[7] = float64(len(canonical.mainLabel))
	features[8] = float64(len(canonical.registrable))
	features[9] = float64(canonical.subdomainDepth)
	tokens := 0
	for _, token := range strings.FieldsFunc(ascii, func(r rune) bool { return r == '.' || r == '-' }) {
		if token != "" {
			tokens++
		}
	}
	features[10] = float64(tokens)
	if strings.HasPrefix(ascii, "xn--") || strings.Contains(ascii, ".xn--") {
		features[11] = 1
	}
	if hasMixedScript(canonical.unicode) {
		features[12] = 1
	}
	if canonical.ipLike {
		features[13] = 1
	}
	if _, ok := suspiciousTLDs[canonical.suffix]; ok {
		features[14] = 1
	} else if e.manifest.ContractVersion == featureManifestVersionV4 && canonical.suffixKnown {
		features[14] = 0.5
	}
	for _, keyword := range e.keywords {
		if strings.Contains(ascii, keyword) {
			features[15]++
		}
	}
	for root := range e.sharedHosting {
		if canonical.registrable == root || ascii == root || strings.HasSuffix(ascii, "."+root) {
			features[16] = 1
			break
		}
	}
	e.extractBrandFeatures(features, canonical)
	e.extractTFIDF(features, tfidfInput(canonical, e.manifest.TFIDFConfig.InputView))
	return features
}

func tfidfInput(canonical canonicalDomain, inputView string) string {
	if inputView == "" || inputView == tfidfInputDomainASCII {
		return canonical.ascii
	}
	if inputView != tfidfInputWithoutSuffix || canonical.suffix == "" {
		return ""
	}
	marker := "." + canonical.suffix
	if !strings.HasSuffix(canonical.ascii, marker) {
		return ""
	}
	return strings.TrimSuffix(canonical.ascii, marker)
}

func (e *FeatureExtractor) extractBrandFeatures(features []float64, canonical canonicalDomain) {
	features[17] = 99
	features[18] = 99
	labels := strings.Split(canonical.ascii, ".")
	nonTLDCount := len(labels)
	if len(labels) > 1 {
		nonTLDCount--
		if len(labels) > 2 && isDoubleCountrySuffix(labels[len(labels)-2], labels[len(labels)-1]) {
			nonTLDCount--
		}
	}
	nonTLDLabels := labels[:max(0, nonTLDCount)]
	skeletonDomain := ToSkeleton(canonical.unicode)
	skeletonLabels := strings.Split(skeletonDomain, ".")
	nonTLDSkeletonLabels := skeletonLabels[:max(0, min(nonTLDCount, len(skeletonLabels)))]
	isTrusted := IsTrustedBrandSuffix(canonical.ascii, e.brands)
	if isTrusted {
		features[17], features[18] = 0, 0
		return
	}
	isHomoglyph := skeletonDomain != canonical.unicode
	for _, brand := range e.brands {
		brandName := strings.ToLower(brand.Name)
		if brandName == "" || brand.OfficialDomain == "" {
			continue
		}
		if canonical.registrable == strings.ToLower(brand.OfficialDomain) || containsFold(brand.AltDomains, canonical.registrable) {
			continue
		}
		for i, label := range nonTLDLabels {
			skLabel := label
			if i < len(nonTLDSkeletonLabels) {
				skLabel = nonTLDSkeletonLabels[i]
			}
			if min(len(brandName), len(skLabel)) < 4 || absInt(len(skLabel)-len(brandName)) > 2 {
				continue
			}
			if distance := float64(LevenshteinDistance(skLabel, brandName)); distance < features[17] {
				features[17] = distance
			}
			if distance := WeightedLevenshteinDistance(skLabel, brandName); distance < features[18] {
				features[18] = distance
			}
			if skLabel == brandName && label != brandName && isHomoglyph {
				features[19] = 1
			}
		}
		if isSuspiciousFeatureLabel(canonical.mainLabel, brandName) || isSuspiciousFeatureLabel(ToSkeleton(canonical.mainLabel), brandName) {
			features[20] = 1
		}
		for _, sub := range canonical.subdomainLabels {
			if isSuspiciousFeatureLabel(sub, brandName) || isSuspiciousFeatureLabel(ToSkeleton(sub), brandName) {
				features[21] = 1
			}
		}
	}
}

func (e *FeatureExtractor) extractTFIDF(features []float64, ascii string) {
	counts := make(map[string]int)
	for n := 2; n <= 3; n++ {
		for i := 0; i+n <= len(ascii); i++ {
			counts[ascii[i:i+n]]++
		}
	}
	norm := 0.0
	values := make([]float64, len(e.vocab))
	for i, term := range e.vocab {
		count := counts[term]
		if count == 0 {
			continue
		}
		tf := float64(count)
		if e.manifest.TFIDFConfig.SublinearTF {
			tf = 1 + math.Log(tf)
		}
		values[i] = tf * e.idf[i]
		norm += values[i] * values[i]
	}
	if norm == 0 {
		return
	}
	norm = math.Sqrt(norm)
	tfidfFeatures := features[handcraftedFeatureCount:]
	for i := 0; i < len(values) && i < len(tfidfFeatures); i++ {
		tfidfFeatures[i] = values[i] / norm
	}
}

func maxConsecutiveConsonants(value string) int {
	const consonants = "bcdfghjklmnpqrstvwxyz"
	maxRun, run := 0, 0
	for _, r := range strings.ToLower(value) {
		if strings.ContainsRune(consonants, r) {
			run++
			if run > maxRun {
				maxRun = run
			}
		} else {
			run = 0
		}
	}
	return maxRun
}

func hasMixedScript(value string) bool {
	latin, nonLatin := false, false
	for _, r := range value {
		if r == '.' || r == '-' || unicode.IsDigit(r) {
			continue
		}
		if r <= unicode.MaxASCII {
			latin = true
		} else {
			nonLatin = true
		}
	}
	return latin && nonLatin
}

func isDoubleCountrySuffix(secondLast, last string) bool {
	switch secondLast {
	case "com", "co", "net", "org", "gov", "edu", "ac":
		return len(last) == 2
	default:
		return false
	}
}

func isSuspiciousFeatureLabel(label, brand string) bool {
	label, brand = strings.ToLower(label), strings.ToLower(brand)
	if label == brand {
		return true
	}
	for _, part := range strings.Split(label, "-") {
		if part == brand {
			return true
		}
	}
	return len(brand) >= 6 && strings.Contains(label, brand)
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
