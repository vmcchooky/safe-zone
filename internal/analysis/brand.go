package analysis

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/net/idna"
)

// Brand represents a trusted brand and its official domains.
type Brand struct {
	ID             int64    `json:"id,omitempty"`
	Name           string   `json:"name"`            // e.g. "google"
	OfficialDomain string   `json:"official_domain"` // e.g. "google.com"
	AltDomains     []string `json:"alt_domains"`     // e.g. ["google.com.vn", "google.co.uk"]
	CreatedAt      string   `json:"created_at,omitempty"`
	UpdatedAt      string   `json:"updated_at,omitempty"`
}

// BrandStore provides runtime-managed trusted brand configuration.
type BrandStore interface {
	ListBrands(ctx context.Context) ([]Brand, error)
	GetBrand(ctx context.Context, id int64) (Brand, error)
	CreateBrand(ctx context.Context, brand Brand) (Brand, error)
	UpdateBrand(ctx context.Context, id int64, brand Brand) (Brand, error)
	DeleteBrand(ctx context.Context, id int64) error
}

// DefaultTrustedBrands returns the built-in brand seed used when persistence is unavailable.
func DefaultTrustedBrands() []Brand {
	return cloneBrands([]Brand{
		{Name: "google", OfficialDomain: "google.com", AltDomains: []string{"google.com.vn", "google.co.uk", "google.com.sg"}},
		{Name: "binance", OfficialDomain: "binance.com", AltDomains: []string{"binance.us", "binance.info"}},
		{Name: "paypal", OfficialDomain: "paypal.com", AltDomains: []string{"paypal.me"}},
		{Name: "facebook", OfficialDomain: "facebook.com", AltDomains: []string{"fb.com", "messenger.com"}},
		{Name: "apple", OfficialDomain: "apple.com", AltDomains: []string{"icloud.com"}},
		{Name: "microsoft", OfficialDomain: "microsoft.com", AltDomains: []string{"live.com", "outlook.com", "office.com"}},
		{Name: "amazon", OfficialDomain: "amazon.com"},
		{Name: "netflix", OfficialDomain: "netflix.com"},
		{Name: "instagram", OfficialDomain: "instagram.com"},
		{Name: "twitter", OfficialDomain: "twitter.com", AltDomains: []string{"x.com"}},
		{Name: "metamask", OfficialDomain: "metamask.io"},
		{Name: "coinbase", OfficialDomain: "coinbase.com"},
		{Name: "trustwallet", OfficialDomain: "trustwallet.com"},
		{Name: "yahoo", OfficialDomain: "yahoo.com"},
		{Name: "linkedin", OfficialDomain: "linkedin.com"},

		{Name: "chinhphu", OfficialDomain: "chinhphu.vn", AltDomains: []string{"chinhphu.gov.vn"}},
		{Name: "bocongan", OfficialDomain: "bocongan.gov.vn", AltDomains: []string{"mps.gov.vn"}},
		{Name: "baohiemxahoi", OfficialDomain: "baohiemxahoi.gov.vn", AltDomains: []string{"bhxh.gov.vn"}},
		{Name: "vtv", OfficialDomain: "vtv.vn"},

		{Name: "vietcombank", OfficialDomain: "vietcombank.com.vn", AltDomains: []string{"vietcombank.com"}},
		{Name: "techcombank", OfficialDomain: "techcombank.com.vn", AltDomains: []string{"techcombank.com"}},
		{Name: "bidv", OfficialDomain: "bidv.com.vn", AltDomains: []string{"bidv.com"}},
		{Name: "vietinbank", OfficialDomain: "vietinbank.vn", AltDomains: []string{"vietinbank.co.vn"}},
		{Name: "mbbank", OfficialDomain: "mbbank.com.vn", AltDomains: []string{"mbbank.com"}},
		{Name: "agribank", OfficialDomain: "agribank.com.vn", AltDomains: []string{"agribank.com"}},
		{Name: "vpbank", OfficialDomain: "vpbank.com.vn", AltDomains: []string{"vpbank.com"}},
		{Name: "acb", OfficialDomain: "acb.com.vn", AltDomains: []string{"acb.com"}},
		{Name: "sacombank", OfficialDomain: "sacombank.com.vn", AltDomains: []string{"sacombank.com"}},
		{Name: "tpbank", OfficialDomain: "tpb.vn", AltDomains: []string{"tpbank.com.vn"}},
		{Name: "vib", OfficialDomain: "vib.com.vn"},
		{Name: "hdbank", OfficialDomain: "hdbank.com.vn"},
		{Name: "shb", OfficialDomain: "shb.com.vn"},
		{Name: "scb", OfficialDomain: "scb.com.vn"},
	})
}

type MemoryBrandStore struct {
	mu     sync.RWMutex
	nextID int64
	items  []Brand
}

func NewMemoryBrandStore(brands []Brand) *MemoryBrandStore {
	store := &MemoryBrandStore{nextID: 1}
	for _, brand := range brands {
		brand = normalizeBrandRecord(brand)
		if brand.ID == 0 {
			brand.ID = store.nextID
			store.nextID++
		} else if brand.ID >= store.nextID {
			store.nextID = brand.ID + 1
		}
		store.items = append(store.items, brand)
	}
	return store
}

func (s *MemoryBrandStore) ListBrands(_ context.Context) ([]Brand, error) {
	if s == nil {
		return DefaultTrustedBrands(), nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneBrands(s.items), nil
}

func (s *MemoryBrandStore) GetBrand(_ context.Context, id int64) (Brand, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, brand := range s.items {
		if brand.ID == id {
			return cloneBrand(brand), nil
		}
	}
	return Brand{}, errors.New("brand not found")
}

func (s *MemoryBrandStore) CreateBrand(_ context.Context, brand Brand) (Brand, error) {
	if s == nil {
		return Brand{}, errors.New("brand store disabled")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	brand = normalizeBrandRecord(brand)
	brand.ID = s.nextID
	s.nextID++
	now := time.Now().UTC().Format(time.RFC3339Nano)
	brand.CreatedAt = now
	brand.UpdatedAt = now
	s.items = append(s.items, brand)
	return cloneBrand(brand), nil
}

func (s *MemoryBrandStore) UpdateBrand(_ context.Context, id int64, brand Brand) (Brand, error) {
	if s == nil {
		return Brand{}, errors.New("brand store disabled")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.items {
		if s.items[i].ID == id {
			updated := normalizeBrandRecord(brand)
			updated.ID = id
			updated.CreatedAt = s.items[i].CreatedAt
			updated.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
			s.items[i] = updated
			return cloneBrand(updated), nil
		}
	}
	return Brand{}, errors.New("brand not found")
}

func (s *MemoryBrandStore) DeleteBrand(_ context.Context, id int64) error {
	if s == nil {
		return errors.New("brand store disabled")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.items {
		if s.items[i].ID == id {
			s.items = append(s.items[:i], s.items[i+1:]...)
			return nil
		}
	}
	return errors.New("brand not found")
}

// LevenshteinDistance calculates the minimum edit distance between two strings using runes.
func LevenshteinDistance(s1, s2 string) int {
	r1, r2 := []rune(s1), []rune(s2)
	len1, len2 := len(r1), len(r2)

	if len1 == 0 {
		return len2
	}
	if len2 == 0 {
		return len1
	}

	column := make([]int, len1+1)
	for y := 1; y <= len1; y++ {
		column[y] = y
	}

	for x := 1; x <= len2; x++ {
		column[0] = x
		lastkey := x - 1
		for y := 1; y <= len1; y++ {
			oldkey := column[y]
			incr := 0
			if r1[y-1] != r2[x-1] {
				incr = 1
			}
			column[y] = minInt(column[y]+1, column[y-1]+1, lastkey+incr)
			lastkey = oldkey
		}
	}
	return column[len1]
}

func minInt(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// ShannonEntropy calculates the Shannon Entropy of a string to detect randomized DGA domains.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	frequencies := make(map[rune]int)
	for _, r := range s {
		frequencies[r]++
	}
	entropy := 0.0
	length := float64(len(s))
	for _, count := range frequencies {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// getRootDomain extracts the root domain (effective TLD+1) supporting ccTLDs.
func getRootDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	parts := strings.Split(domain, ".")
	n := len(parts)
	if n <= 2 {
		return domain
	}

	last := parts[n-1]
	secondLast := parts[n-2]

	isDoubleCC := false
	doubleTLDs := []string{"com", "co", "net", "org", "gov", "edu", "ac"}
	for _, tld := range doubleTLDs {
		if secondLast == tld {
			isDoubleCC = true
			break
		}
	}

	// For double extension TLDs like com.vn, co.uk, net.vn, etc.
	if isDoubleCC && n >= 3 {
		// Only check if the last part is indeed a short country code (like vn, uk, jp, cn)
		if len(last) == 2 {
			return parts[n-3] + "." + parts[n-2] + "." + parts[n-1]
		}
	}

	return parts[n-2] + "." + parts[n-1]
}

// getMainLabel extracts the main registrable label of a domain (e.g., "google" from "sub.google.com.vn").
func getMainLabel(domain string) string {
	root := getRootDomain(domain)
	parts := strings.Split(root, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return domain
}

// --- Homoglyph & Keyboard Adjacency Data Maps ---

var homoglyphMap = map[rune]rune{
	// Cyrillic lookalikes
	'а': 'a', 'б': 'b', 'с': 'c', 'ԁ': 'd', 'е': 'e', 'f': 'f', 'g': 'g', 'һ': 'h',
	'і': 'i', 'ј': 'j', 'k': 'k', 'l': 'l', 'm': 'm', 'п': 'n', 'о': 'o', 'р': 'p',
	'q': 'q', 'г': 'r', 'ѕ': 's', 'т': 't', 'υ': 'u', 'ѵ': 'v', 'ԝ': 'w', 'х': 'x',
	'у': 'y', 'z': 'z',
	// Uppercase & extensions
	'А': 'a', 'В': 'b', 'С': 'c', 'Е': 'e', 'Н': 'h', 'І': 'i', 'Ј': 'j', 'К': 'k',
	'М': 'm', 'О': 'o', 'Р': 'p', 'Ѕ': 's', 'Т': 't', 'Х': 'x', 'Ү': 'y',
	// Greek lookalikes
	'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ο': 'o', 'ρ': 'p', 'τ': 't',
	'χ': 'x',
}

var keyboardAdjacency = map[rune]string{
	'a': "qwsz", 'b': "vghn", 'c': "xdfv", 'd': "ersfxc",
	'e': "wsdr34", 'f': "rtgvcd", 'g': "tyhbvf", 'h': "yujnbg",
	'i': "ujko89", 'j': "uikmnh", 'k': "ijlm09", 'l': "okp",
	'm': "njk", 'n': "bhjm", 'o': "iklp90", 'p': "ol0",
	'q': "w12a", 'r': "edft45", 's': "wedxza", 't': "rfgy56",
	'u': "yhji78", 'v': "cfgb", 'w': "qase23", 'x': "zsdc",
	'y': "tghu67", 'z': "asx",
}

var suspiciousTLDs = map[string]bool{
	"xyz":  true,
	"top":  true,
	"cc":   true,
	"info": true,
	"work": true,
	"club": true,
	"fit":  true,
	"vip":  true,
	"cf":   true,
	"gq":   true,
	"ga":   true,
	"ml":   true,
	"tk":   true,
	"icu":  true,
	"asia": true,
	"buzz": true,
	"bid":  true,
}

// ToSkeleton normalizes homoglyphs in a string into Latin equivalents.
func ToSkeleton(s string) string {
	runes := []rune(s)
	skeleton := make([]rune, len(runes))
	for i, r := range runes {
		if mapped, ok := homoglyphMap[r]; ok {
			skeleton[i] = mapped
		} else {
			skeleton[i] = r
		}
	}
	return string(skeleton)
}

// WeightedLevenshteinDistance calculates edit distance where keyboard adjacent errors cost 0.5.
func WeightedLevenshteinDistance(s1, s2 string) float64 {
	r1, r2 := []rune(s1), []rune(s2)
	len1, len2 := len(r1), len(r2)

	if len1 == 0 {
		return float64(len2)
	}
	if len2 == 0 {
		return float64(len1)
	}

	dp := make([]float64, len1+1)
	for y := 1; y <= len1; y++ {
		dp[y] = float64(y)
	}

	for x := 1; x <= len2; x++ {
		dp[0] = float64(x)
		lastkey := float64(x - 1)
		for y := 1; y <= len1; y++ {
			oldkey := dp[y]
			var incr float64 = 1.0
			if r1[y-1] == r2[x-1] {
				incr = 0.0
			} else {
				c1 := r1[y-1]
				c2 := r2[x-1]
				c1Low := unicode.ToLower(c1)
				c2Low := unicode.ToLower(c2)
				if adj, ok := keyboardAdjacency[c1Low]; ok && strings.ContainsRune(adj, c2Low) {
					incr = 0.5
				} else if adj2, ok2 := keyboardAdjacency[c2Low]; ok2 && strings.ContainsRune(adj2, c1Low) {
					incr = 0.5
				}
			}
			dp[y] = minFloat(dp[y]+1.0, dp[y-1]+1.0, lastkey+incr)
			lastkey = oldkey
		}
	}
	return dp[len1]
}

func minFloat(a, b, c float64) float64 {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

func normalizeBrandRecord(brand Brand) Brand {
	brand.Name = strings.ToLower(strings.TrimSpace(brand.Name))
	brand.OfficialDomain = strings.ToLower(strings.TrimSpace(brand.OfficialDomain))
	alts := make([]string, 0, len(brand.AltDomains))
	seen := make(map[string]struct{}, len(brand.AltDomains))
	for _, alt := range brand.AltDomains {
		alt = strings.ToLower(strings.TrimSpace(alt))
		if alt == "" {
			continue
		}
		if _, ok := seen[alt]; ok {
			continue
		}
		seen[alt] = struct{}{}
		alts = append(alts, alt)
	}
	brand.AltDomains = alts
	return brand
}

func cloneBrand(brand Brand) Brand {
	brand.AltDomains = append([]string(nil), brand.AltDomains...)
	return brand
}

func cloneBrands(brands []Brand) []Brand {
	if len(brands) == 0 {
		return nil
	}
	cloned := make([]Brand, len(brands))
	for i, brand := range brands {
		cloned[i] = cloneBrand(brand)
	}
	return cloned
}

// isTrustedBrandRoot checks if the root domain belongs to any official or alternative domains of trusted brands.
func isTrustedBrandRoot(rootDomain string, brands []Brand) bool {
	for _, brand := range brands {
		if rootDomain == brand.OfficialDomain {
			return true
		}
		for _, alt := range brand.AltDomains {
			if rootDomain == alt {
				return true
			}
		}
	}
	return false
}

// CheckBrandSpoofing analyzes a domain to detect typosquatting, brand keyword mentions, or subdomain abuse.
// Trả về: (isSpoof, reason, penaltyScore)
func CheckBrandSpoofing(domain string, brandSpoofingScore int) (bool, string, int) {
	return CheckBrandSpoofingWithBrands(domain, brandSpoofingScore, DefaultTrustedBrands())
}

func CheckBrandSpoofingWithBrands(domain string, brandSpoofingScore int, brands []Brand) (bool, string, int) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false, "", 0
	}
	if len(brands) == 0 {
		brands = DefaultTrustedBrands()
	}

	// 0. Decode Punycode (IDN) to Unicode to handle homoglyphs
	unicodeDomain, err := idna.ToUnicode(domain)
	if err != nil {
		unicodeDomain = domain
	}

	rootDomain := getRootDomain(domain)
	if isVietnamGovernmentRoot(rootDomain) {
		return false, "", 0
	}

	// If the root domain belongs to a trusted brand, subdomains under it are owned by that brand
	// and are exempt from spoofing checks of other brands.
	if isTrustedBrandRoot(rootDomain, brands) {
		return false, "", 0
	}

	labels := strings.Split(domain, ".")

	rootParts := strings.Split(rootDomain, ".")
	var tld string
	if len(rootParts) > 1 {
		tld = rootParts[len(rootParts)-1]
	}

	skeletonDomain := ToSkeleton(unicodeDomain)
	skeletonRootDomain := ToSkeleton(getRootDomain(unicodeDomain))
	skeletonLabels := strings.Split(skeletonDomain, ".")

	isHomoglyphSpoof := skeletonDomain != unicodeDomain

	for _, brand := range brands {
		brand = normalizeBrandRecord(brand)
		if brand.Name == "" || brand.OfficialDomain == "" {
			continue
		}
		// 1. Check if it's the official domain or official alternatives
		isOfficial := rootDomain == brand.OfficialDomain
		if !isOfficial {
			for _, alt := range brand.AltDomains {
				if rootDomain == alt {
					isOfficial = true
					break
				}
			}
		}

		if isOfficial {
			continue
		}

		// 2. Typosquatting Check
		for i, label := range labels {
			if len(labels) > 1 && label == labels[len(labels)-1] {
				continue
			}
			if len(labels) > 2 && label == labels[len(labels)-2] && (label == "com" || label == "co" || label == "net" || label == "org" || label == "gov" || label == "edu" || label == "ac") {
				continue
			}

			var skLabel string
			if i < len(skeletonLabels) {
				skLabel = skeletonLabels[i]
			} else {
				skLabel = label
			}

			minLen := len(brand.Name)
			if len(skLabel) < minLen {
				minLen = len(skLabel)
			}
			if minLen < 4 {
				continue
			}

			// A. Homoglyph Visual Spoofing
			if skLabel == brand.Name && label != brand.Name && isHomoglyphSpoof {
				penalty := brandSpoofingScore
				if suspiciousTLDs[tld] {
					penalty += 20
				}
				return true, "homoglyph visual spoofing of " + brand.Name + " brand (" + label + ")", penalty
			}

			// B. Keyboard Weighted Typosquatting
			wDist := WeightedLevenshteinDistance(skLabel, brand.Name)
			if wDist > 0 && wDist <= 1.5 {
				penalty := brandSpoofingScore
				if suspiciousTLDs[tld] {
					penalty += 20
				}
				reason := "keyboard typosquatting of " + brand.Name + " brand (" + label + ")"
				if skLabel != label {
					reason = "homoglyph keyboard typosquatting of " + brand.Name + " brand (" + label + ")"
				}
				return true, reason, penalty
			}

			// C. Classic Levenshtein Distance
			dist := LevenshteinDistance(skLabel, brand.Name)
			if dist > 0 && dist <= 2 {
				penalty := brandSpoofingScore
				if suspiciousTLDs[tld] {
					penalty += 20
				}
				return true, "typosquatting of " + brand.Name + " brand (" + label + ")", penalty
			}
		}

		// 3. Suspicious Brand Keyword Mention
		if strings.Contains(rootDomain, brand.Name) || strings.Contains(skeletonRootDomain, brand.Name) {
			penalty := brandSpoofingScore
			if suspiciousTLDs[tld] {
				penalty += 20
			}
			return true, "suspicious usage of trusted brand keyword (" + brand.Name + ")", penalty
		}

		// 4. Subdomain Abuse Check
		for i, label := range labels {
			var skLabel string
			if i < len(skeletonLabels) {
				skLabel = skeletonLabels[i]
			} else {
				skLabel = label
			}

			rootPartsCount := 2
			rootParts := strings.Split(rootDomain, ".")
			if len(rootParts) > 0 {
				rootPartsCount = len(rootParts)
			}

			if i < len(labels)-rootPartsCount {
				if label == brand.Name || strings.Contains(label, brand.Name) ||
					skLabel == brand.Name || strings.Contains(skLabel, brand.Name) {
					penalty := brandSpoofingScore - 10
					if suspiciousTLDs[tld] {
						penalty += 20
					}
					return true, "suspicious brand subdomain usage (" + brand.Name + ")", penalty
				}
			}
		}
	}

	return false, "", 0
}

func isVietnamGovernmentRoot(rootDomain string) bool {
	rootDomain = strings.ToLower(strings.TrimSpace(rootDomain))
	return rootDomain == "gov.vn" || strings.HasSuffix(rootDomain, ".gov.vn")
}
