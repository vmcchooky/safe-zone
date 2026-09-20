package analysis

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"sync/atomic"
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
		{Name: "google", OfficialDomain: "google.com", AltDomains: []string{
			"google.com.vn", "google.co.uk", "google.com.sg", "googleusercontent.com",
			"googlesyndication.com", "googletagservices.com", "googletagmanager.com",
			"google-analytics.com", "googleapis.com", "gstatic.com", "googlevideo.com",
			"youtube.com", "youtu.be", "ytimg.com", "ggpht.com", "gvt1.com", "doubleclick.net",
		}},
		{Name: "binance", OfficialDomain: "binance.com", AltDomains: []string{"binance.us", "binance.info"}},
		{Name: "paypal", OfficialDomain: "paypal.com", AltDomains: []string{"paypal.me"}},
		{Name: "facebook", OfficialDomain: "facebook.com", AltDomains: []string{
			"fb.com", "messenger.com", "fbcdn.net", "fbsbx.com",
		}},
		{Name: "apple", OfficialDomain: "apple.com", AltDomains: []string{"icloud.com"}},
		{Name: "microsoft", OfficialDomain: "microsoft.com", AltDomains: []string{
			"live.com", "outlook.com", "office.com", "microsoftonline.com", "sharepoint.com",
			"office365.com", "windows.net", "windows.com", "azure.com", "visualstudio.com",
			"aspnetcdn.com", "msn.com", "bing.com",
		}},
		{Name: "amazon", OfficialDomain: "amazon.com"},
		{Name: "netflix", OfficialDomain: "netflix.com"},
		{Name: "instagram", OfficialDomain: "instagram.com", AltDomains: []string{"cdninstagram.com"}},
		{Name: "twitter", OfficialDomain: "twitter.com", AltDomains: []string{"x.com"}},
		{Name: "metamask", OfficialDomain: "metamask.io"},
		{Name: "coinbase", OfficialDomain: "coinbase.com"},
		{Name: "trustwallet", OfficialDomain: "trustwallet.com"},
		{Name: "yahoo", OfficialDomain: "yahoo.com", AltDomains: []string{"yimg.com"}},
		{Name: "linkedin", OfficialDomain: "linkedin.com"},

		{Name: "chinhphu", OfficialDomain: "chinhphu.vn", AltDomains: []string{"chinhphu.gov.vn"}},
		{Name: "bocongan", OfficialDomain: "bocongan.gov.vn", AltDomains: []string{"mps.gov.vn"}},
		{Name: "baohiemxahoi", OfficialDomain: "baohiemxahoi.gov.vn", AltDomains: []string{"bhxh.gov.vn"}},
		{Name: "vneid", OfficialDomain: "vneid.gov.vn"},
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

		{Name: "momo", OfficialDomain: "momo.vn"},
		{Name: "zalopay", OfficialDomain: "zalopay.vn"},
		{Name: "vnpay", OfficialDomain: "vnpay.vn"},
		{Name: "shopee", OfficialDomain: "shopee.vn", AltDomains: []string{"shopee.com", "shopeemobile.com"}},
		{Name: "tiki", OfficialDomain: "tiki.vn"},
		{Name: "lazada", OfficialDomain: "lazada.vn", AltDomains: []string{"lazada.com"}},
	})
}

// detectionBrandExtras are evidence-backed detection brands that extend
// lexical spoof detection WITHOUT entering DefaultTrustedBrands. The
// default seed is frozen by the ML feature contract (brands.v1.json,
// golden vectors): adding names there would shift model inputs for every
// domain. Detection extras apply to spoof checking and suffix trust only.
//
// Each entry needs in-repo or independently verified abuse evidence:
//   - allegro (allegro.pl): Allegro Lokalnie phishing-kit campaign —
//     screenshot-confirmed sibling replay-0072, PhishStats campaign
//     reports on same-kit siblings.
//   - spotify (spotify.com): vendor-impersonation hostnames such as
//     pl.spotify-original.com (main-label keyword pattern).
func detectionBrandExtras() []Brand {
	return []Brand{
		{Name: "allegro", OfficialDomain: "allegro.pl"},
		{Name: "spotify", OfficialDomain: "spotify.com"},
	}
}

// DetectionBrands returns base plus the evidence-backed detection extras,
// skipping any name the operator already manages (operator intent wins).
// The result is freshly built per call; treat it as read-only.
func DetectionBrands(base []Brand) []Brand {
	seen := make(map[string]struct{}, len(base)+2)
	out := make([]Brand, 0, len(base)+2)
	for _, brand := range base {
		brand = normalizeBrandRecord(brand)
		key := strings.ToLower(strings.TrimSpace(brand.Name))
		if _, dup := seen[key]; dup || key == "" {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, brand)
	}
	for _, extra := range detectionBrandExtras() {
		extra = normalizeBrandRecord(extra)
		key := strings.ToLower(strings.TrimSpace(extra.Name))
		if _, dup := seen[key]; dup || key == "" {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, extra)
	}
	return out
}

type MemoryBrandStore struct {
	mu       sync.RWMutex
	nextID   int64
	items    []Brand
	snapshot atomic.Pointer[memoryBrandSnapshot]
}

// memoryBrandSnapshot is one immutable publication of the brand list.
// Readers share it without cloning and without locks; writers rebuild and
// swap. Callers MUST treat the returned slice as read-only.
type memoryBrandSnapshot struct {
	items []Brand
}

func NewMemoryBrandStore(brands []Brand) *MemoryBrandStore {
	store := &MemoryBrandStore{nextID: 1}
	for _, brand := range brands {
		brand = normalizeBrandRecord(brand)
		// Own the array: the fast path above may alias the caller's
		// slice, and snapshots published below are shared read-only.
		brand.AltDomains = append([]string(nil), brand.AltDomains...)
		if brand.ID == 0 {
			brand.ID = store.nextID
			store.nextID++
		} else if brand.ID >= store.nextID {
			store.nextID = brand.ID + 1
		}
		store.items = append(store.items, brand)
	}
	store.publishLocked()
	return store
}

// publishLocked swaps in a fresh immutable snapshot. Callers must hold mu
// (writers) or call it from construction where no readers exist yet.
func (s *MemoryBrandStore) publishLocked() {
	s.snapshot.Store(&memoryBrandSnapshot{items: cloneBrands(s.items)})
}

// detachLocked gives writers a private backing array so published
// snapshots (which share the old array) are never mutated in place.
func (s *MemoryBrandStore) detachLocked() {
	s.items = append([]Brand(nil), s.items...)
}

func (s *MemoryBrandStore) ListBrands(_ context.Context) ([]Brand, error) {
	if s == nil {
		return DefaultTrustedBrands(), nil
	}
	if snap := s.snapshot.Load(); snap != nil {
		return snap.items, nil
	}
	return DefaultTrustedBrands(), nil
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
	brand.AltDomains = append([]string(nil), brand.AltDomains...)
	s.detachLocked()
	s.items = append(s.items, brand)
	s.publishLocked()
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
			updated.AltDomains = append([]string(nil), updated.AltDomains...)
			s.detachLocked()
			s.items[i] = updated
			s.publishLocked()
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
			s.detachLocked()
			s.items = append(s.items[:i], s.items[i+1:]...)
			s.publishLocked()
			return nil
		}
	}
	return errors.New("brand not found")
}

var intSlicePool = sync.Pool{
	New: func() any {
		s := make([]int, 0, 64)
		return &s
	},
}

var floatSlicePool = sync.Pool{
	New: func() any {
		s := make([]float64, 0, 64)
		return &s
	},
}

var runeSlicePool = sync.Pool{
	New: func() any {
		s := make([]rune, 0, 64)
		return &s
	},
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

	ptr := intSlicePool.Get().(*[]int)
	column := *ptr
	if cap(column) < len1+1 {
		column = make([]int, len1+1)
	} else {
		column = column[:len1+1]
	}
	defer func() {
		*ptr = column
		intSlicePool.Put(ptr)
	}()
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

// LevenshteinDistanceCapped computes the edit distance but stops early:
// it returns the exact distance when it does not exceed cap, otherwise
// cap+1. Any path through the DP grid crosses every row with non-negative
// edge costs, so a row whose minimum already exceeds cap proves the final
// distance does too. Callers comparing against a threshold maxDist must
// pass cap >= maxDist; the result is then interchangeable with
// LevenshteinDistance for that comparison.
func LevenshteinDistanceCapped(s1, s2 string, limit int) int {
	r1, r2 := []rune(s1), []rune(s2)
	len1, len2 := len(r1), len(r2)

	if len1 == 0 {
		return len2
	}
	if len2 == 0 {
		return len1
	}

	ptr := intSlicePool.Get().(*[]int)
	column := *ptr
	if cap(column) < len1+1 {
		column = make([]int, len1+1)
	} else {
		column = column[:len1+1]
	}
	defer func() {
		*ptr = column
		intSlicePool.Put(ptr)
	}()
	for y := 1; y <= len1; y++ {
		column[y] = y
	}

	for x := 1; x <= len2; x++ {
		column[0] = x
		lastkey := x - 1
		rowMin := x
		for y := 1; y <= len1; y++ {
			oldkey := column[y]
			incr := 0
			if r1[y-1] != r2[x-1] {
				incr = 1
			}
			column[y] = minInt(column[y]+1, column[y-1]+1, lastkey+incr)
			if column[y] < rowMin {
				rowMin = column[y]
			}
			lastkey = oldkey
		}
		if rowMin > limit {
			return limit + 1
		}
	}
	if column[len1] > limit {
		return limit + 1
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

// cdnInfraAdvisoryPenalty caps fuzzy brand-similarity signals observed on
// labels delegated beneath a shared CDN/cloud root (FP-guard 2026-09).
// Tenant namespaces under shared infrastructure legitimately embed customer
// brand names (e.g. twitter under map.fastly.net, delegated Shopee hosts
// under baishan-cloud.net), so typosquat and subdomain-usage matches there
// are advisory only: they can contribute to SUSPICIOUS but never alone
// promote to MALICIOUS. Exact homoglyph visual spoofing keeps full weight,
// and exact threat-feed IOCs still win over everything (PR-08a/H2).
const cdnInfraAdvisoryPenalty = 10

// shortBrandTyposquatMaxLen bounds the length-scaled typosquat rule below:
// brands and labels at or below this length only match on edit distance 1.
// Distance-2 matches on 4-character names (miui~tiki, zoho~momo) are
// chance collisions, not typosquats.
const shortBrandTyposquatMaxLen = 4

// trustedInfraSuffixes lists shared developer/corporate infrastructure
// roots that are trusted as a suffix (FP-guard 2026-09). They are kept
// OUT of DefaultTrustedBrands on purpose: the default brand seed is
// frozen by the ML feature contract (brands.v1.json, golden vectors), so
// brand-shaped detection (typosquat distances, ML brand features) must not
// shift. Infrastructure trust only gates the suffix bypass in lexical
// spoof checks and the threat-feed parent walk; exact feed IOCs beneath
// these roots still block (PR-08a/H2). github.io stays OUT: tenant pages
// there keep full scrutiny. Additions need code review.
var trustedInfraSuffixes = map[string]bool{
	"github.com": true,
	"taobao.com": true,
}

// IsTrustedInfraSuffix reports whether domain is one of the trusted
// infrastructure roots above or a subdomain beneath one.
func IsTrustedInfraSuffix(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	for root := range trustedInfraSuffixes {
		if domain == root || strings.HasSuffix(domain, "."+root) {
			return true
		}
	}
	return false
}

// brandLabelMatchKind classifies HOW a domain label references a brand.
type brandLabelMatchKind int

const (
	brandLabelNoMatch brandLabelMatchKind = iota
	brandLabelExact
	brandLabelContains
	// brandLabelHyphenPart marks attacker-style composition
	// (paypal-login): unlike wholesale delegated naming (an exact or
	// containing customer label under shared infra), hyphen composition
	// keeps full weight everywhere.
	brandLabelHyphenPart
)

func classifyBrandLabel(label, brandName string) brandLabelMatchKind {
	label = strings.ToLower(label)
	brandName = strings.ToLower(brandName)
	if label == "" || brandName == "" {
		return brandLabelNoMatch
	}
	if label == brandName {
		return brandLabelExact
	}
	for _, part := range strings.Split(label, "-") {
		if part == brandName {
			return brandLabelHyphenPart
		}
	}
	if len(brandName) >= 6 && strings.Contains(label, brandName) {
		return brandLabelContains
	}
	return brandLabelNoMatch
}

// brandKeywordExemptRoots lists roots whose own names legitimately embed a
// trusted brand keyword (amazonaws holds amazon, googleadservices holds
// google). Only the main-label keyword rule skips these roots; typosquat,
// subdomain-abuse, feed, OSINT and override paths are unaffected, and the
// same token as a subdomain label elsewhere still fires. Additions need
// code review: each entry narrows phishing detection on that root.
var brandKeywordExemptRoots = map[string]bool{
	"amazonaws.com":        true,
	"googleadservices.com": true,
}

// isBrandKeywordExemptRoot reports whether rootDomain is a known
// infrastructure root exempt from the main-label brand-keyword rule.
func isBrandKeywordExemptRoot(rootDomain string) bool {
	rootDomain = strings.ToLower(strings.TrimSpace(rootDomain))
	if rootDomain == "" {
		return false
	}
	return brandKeywordExemptRoots[rootDomain]
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

var cdnRoots = map[string]bool{
	"akamaihd.net":          true,
	"akamaized.net":         true,
	"amazonaws.com":         true,
	"ampproject.org":        true,
	"azurecontainerapps.io": true,
	"azureedge.net":         true,
	"azurefd.net":           true,
	"azurestaticapps.net":   true,
	"azurewebsites.net":     true,
	"b-cdn.net":             true,
	"b-msedge.net":          true,
	"baishan-cloud.net":     true,
	"cachefly.net":          true,
	"cdn77.org":             true,
	"cloudflare.net":        true,
	"cloudfront.net":        true,
	"edgekey.net":           true,
	"edgesuite.net":         true,
	"fastly.net":            true,
	"fastlylb.net":          true,
	"firebaseapp.com":       true,
	"fly.dev":               true,
	"github.io":             true,
	"githubusercontent.com": true,
	"glitch.me":             true,
	"herokuapp.com":         true,
	"hwcdn.net":             true,
	"jsdelivr.net":          true,
	"msedge.net":            true,
	"netlify.app":           true,
	"onrender.com":          true,
	"pages.dev":             true,
	"railway.app":           true,
	"repl.co":               true,
	"replit.app":            true,
	"r2.dev":                true,
	"susercontent.com":      true,
	"stackpathdns.com":      true,
	"surge.sh":              true,
	"trafficmanager.net":    true,
	"vercel.app":            true,
	"workers.dev":           true,
}

// IsCDNRoot reports whether rootDomain is a shared CDN/cloud hosting root.
func IsCDNRoot(rootDomain string) bool {
	rootDomain = strings.ToLower(strings.TrimSpace(rootDomain))
	if rootDomain == "" {
		return false
	}
	return cdnRoots[rootDomain]
}

// ToSkeleton normalizes homoglyphs in a string into Latin equivalents.
func ToSkeleton(s string) string {
	runes := []rune(s)
	n := len(runes)

	ptr := runeSlicePool.Get().(*[]rune)
	skeleton := *ptr
	if cap(skeleton) < n {
		skeleton = make([]rune, n)
	} else {
		skeleton = skeleton[:n]
	}
	defer func() {
		*ptr = skeleton
		runeSlicePool.Put(ptr)
	}()
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

	ptr := floatSlicePool.Get().(*[]float64)
	dp := *ptr
	if cap(dp) < len1+1 {
		dp = make([]float64, len1+1)
	} else {
		dp = dp[:len1+1]
	}
	defer func() {
		*ptr = dp
		floatSlicePool.Put(ptr)
	}()
	for y := 1; y <= len1; y++ {
		dp[y] = float64(y)
	}

	for x := 1; x <= len2; x++ {
		dp[0] = float64(x)
		lastkey := float64(x - 1)
		for y := 1; y <= len1; y++ {
			oldkey := dp[y]
			incr := 1.0
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

// WeightedLevenshteinDistanceCapped is the early-exit variant of
// WeightedLevenshteinDistance with the same row-minimum argument as
// LevenshteinDistanceCapped: exact result at or below cap, cap+1.0 above.
// Callers comparing against a threshold must pass cap >= that threshold.
func WeightedLevenshteinDistanceCapped(s1, s2 string, limit float64) float64 {
	r1, r2 := []rune(s1), []rune(s2)
	len1, len2 := len(r1), len(r2)

	if len1 == 0 {
		return float64(len2)
	}
	if len2 == 0 {
		return float64(len1)
	}

	ptr := floatSlicePool.Get().(*[]float64)
	dp := *ptr
	if cap(dp) < len1+1 {
		dp = make([]float64, len1+1)
	} else {
		dp = dp[:len1+1]
	}
	defer func() {
		*ptr = dp
		floatSlicePool.Put(ptr)
	}()
	for y := 1; y <= len1; y++ {
		dp[y] = float64(y)
	}

	for x := 1; x <= len2; x++ {
		dp[0] = float64(x)
		lastkey := float64(x - 1)
		rowMin := float64(x)
		for y := 1; y <= len1; y++ {
			oldkey := dp[y]
			incr := 1.0
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
			if dp[y] < rowMin {
				rowMin = dp[y]
			}
			lastkey = oldkey
		}
		if rowMin > limit {
			return limit + 1.0
		}
	}
	if dp[len1] > limit {
		return limit + 1.0
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
	// Fast path: records already at rest are normalized (lowercase,
	// trimmed, deduped). Detecting that is a zero-alloc scan, while the
	// slow path rebuilds slices and a dedup map per call — and this runs
	// once per brand per analyzed domain on the hot path. Mutation paths
	// (store inserts/updates) copy on write separately, so sharing the
	// input array here is safe: all readers below only read.
	if isNormalizedBrandRecord(brand) {
		return brand
	}
	return normalizeBrandRecordSlow(brand)
}

func normalizeBrandRecordSlow(brand Brand) Brand {
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

// isNormalizedBrandRecord reports whether normalizeBrandRecord would
// return its input unchanged: fields already lowercase and trimmed, alts
// non-empty, trimmed, lowercase and unique. It must evolve together with
// normalizeBrandRecord — the equivalence test below pins them.
func isNormalizedBrandRecord(brand Brand) bool {
	if !isNormalizedToken(brand.Name) || !isNormalizedToken(brand.OfficialDomain) {
		return false
	}
	// A nil AltDomains must take the slow path: it always materializes a
	// non-nil empty slice, which marshals differently (null vs []).
	if brand.AltDomains == nil {
		return false
	}
	alts := brand.AltDomains
	for i, alt := range alts {
		if alt == "" || !isNormalizedToken(alt) {
			return false
		}
		for _, other := range alts[:i] {
			if other == alt {
				return false
			}
		}
	}
	return true
}

func isNormalizedToken(s string) bool {
	if s == "" {
		return true
	}
	for _, r := range s {
		// Conservative: any whitespace anywhere (edge or interior)
		// sends the record down the slow path. Interior spaces would
		// still be fixpoints, but brand tokens never legitimately
		// contain them — and the slow path returns identical output.
		if unicode.IsSpace(r) || unicode.ToLower(r) != r {
			return false
		}
	}
	return true
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

// IsTrustedBrandSuffix reports whether a domain is an official trusted brand
// domain or a subdomain beneath one of its official or alternative domains.
func IsTrustedBrandSuffix(domain string, brands []Brand) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	for _, brand := range brands {
		brand = normalizeBrandRecord(brand)
		official := brand.OfficialDomain
		if official != "" && (domain == official || strings.HasSuffix(domain, "."+official)) {
			return true
		}
		for _, alt := range brand.AltDomains {
			if domain == alt || strings.HasSuffix(domain, "."+alt) {
				return true
			}
		}
	}
	return false
}

// CheckBrandSpoofing analyzes a domain to detect typosquatting, brand keyword mentions, or subdomain abuse.
// Trả về: (isSpoof, reason, penaltyScore)
func CheckBrandSpoofing(domain string, brandSpoofingScore int) (bool, string, int) {
	return CheckBrandSpoofingWithBrands(domain, brandSpoofingScore, DetectionBrands(DefaultTrustedBrands()))
}

func CheckBrandSpoofingWithBrands(domain string, brandSpoofingScore int, brands []Brand) (bool, string, int) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false, "", 0
	}
	if len(brands) == 0 {
		brands = DetectionBrands(DefaultTrustedBrands())
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

	// If the domain already belongs to a trusted brand suffix or to
	// trusted shared infrastructure, bypass spoofing checks.
	if IsTrustedBrandSuffix(domain, brands) || IsTrustedInfraSuffix(domain) {
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

	// cdnInfra marks delegations beneath shared infrastructure: fuzzy
	// brand similarity there is advisory (see cdnInfraAdvisoryPenalty).
	cdnInfra := IsCDNRoot(rootDomain)

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

			// B. Keyboard Weighted Typosquatting. Short names need a
			// near-exact match: distance-1.5 on 4-character names is a
			// chance collision (miui~tiki), not a typosquat.
			maxWDist := 1.5
			maxDist := 2
			if minLen <= shortBrandTyposquatMaxLen {
				maxWDist = 1.0
				maxDist = 1
			}
			wDist := WeightedLevenshteinDistanceCapped(skLabel, brand.Name, maxWDist)
			if wDist > 0 && wDist <= maxWDist {
				penalty := brandSpoofingScore
				if cdnInfra {
					penalty = cdnInfraAdvisoryPenalty
				}
				if suspiciousTLDs[tld] {
					penalty += 20
				}
				reason := "keyboard typosquatting of " + brand.Name + " brand (" + label + ")"
				if skLabel != label {
					reason = "homoglyph keyboard typosquatting of " + brand.Name + " brand (" + label + ")"
				}
				return true, reason, penalty
			}

			// C. Classic Levenshtein Distance (length-scaled as above).
			dist := LevenshteinDistanceCapped(skLabel, brand.Name, maxDist)
			if dist > 0 && dist <= maxDist {
				penalty := brandSpoofingScore
				if cdnInfra {
					penalty = cdnInfraAdvisoryPenalty
				}
				if suspiciousTLDs[tld] {
					penalty += 20
				}
				return true, "typosquatting of " + brand.Name + " brand (" + label + ")", penalty
			}
		}

		// 3. Suspicious Brand Keyword Mention. Skipped when the root itself
		// is known infrastructure whose name embeds the brand
		// (amazonaws.com, googleadservices.com).
		if !isBrandKeywordExemptRoot(rootDomain) &&
			(isSuspiciousLabel(getMainLabel(rootDomain), brand.Name) || isSuspiciousLabel(getMainLabel(skeletonRootDomain), brand.Name)) {
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
				// Delegated customer naming under shared infrastructure
				// (exact or containing label) is advisory; hyphen-composed
				// labels keep full weight as attacker-style composition.
				kind := classifyBrandLabel(label, brand.Name)
				if skKind := classifyBrandLabel(skLabel, brand.Name); skKind > kind {
					kind = skKind
				}
				if kind != brandLabelNoMatch {
					penalty := brandSpoofingScore - 10
					if cdnInfra && kind != brandLabelHyphenPart {
						penalty = cdnInfraAdvisoryPenalty
					}
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

// isSuspiciousLabel checks if a label suspiciously uses a brand name,
// preventing false positives for short brand names like "shb" matching "dashboard".
func isSuspiciousLabel(label, brandName string) bool {
	label = strings.ToLower(label)
	brandName = strings.ToLower(brandName)
	if label == brandName {
		return true
	}
	parts := strings.Split(label, "-")
	for _, p := range parts {
		if p == brandName {
			return true
		}
	}
	if len(brandName) < 6 {
		return false
	}
	return strings.Contains(label, brandName)
}
