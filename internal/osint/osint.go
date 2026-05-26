package osint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
)

const (
	TypeOfficialWarning    = "official_warning"
	TypeTrustedNewsWarning = "trusted_news_warning"
	TypeSearchSnippet      = "search_snippet"
	TypeSafeBrowsingMatch  = "safe_browsing_match"
	TypeDomainAge          = "domain_age"
	TypeTLSSuspicious      = "tls_suspicious"
)

const (
	defaultMaxBytes = 512 * 1024
	strongEvidence  = 0.85
)

var warningTerms = []string{
	"gia mao", "giả mạo", "lua dao", "lừa đảo", "phishing", "scam",
	"mao danh", "mạo danh", "canh bao", "cảnh báo", "khong truy cap", "không truy cập",
}

var sensitiveDomainTerms = []string{
	"dichvucong", "congdichvu", "nganhang", "bank", "thuethunhap", "thue",
	"baohiem", "bhxh", "congan", "police", "dvc", "vneid", "govvn",
}

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>\s*(.*?)\s*</title>`)

type Evidence struct {
	Domain       string   `json:"domain"`
	SourceURL    string   `json:"source_url"`
	SourceTitle  string   `json:"source_title,omitempty"`
	SourceType   string   `json:"source_type"`
	Confidence   float64  `json:"confidence"`
	MatchedTerms []string `json:"matched_terms,omitempty"`
	RetrievedAt  string   `json:"retrieved_at"`
}

type Report struct {
	Domain         string     `json:"domain"`
	Enabled        bool       `json:"enabled"`
	CacheHit       bool       `json:"cache_hit"`
	CheckedAt      string     `json:"checked_at,omitempty"`
	ExpiresAt      string     `json:"expires_at,omitempty"`
	ShouldBlock    bool       `json:"should_block"`
	VerdictImpact  string     `json:"verdict_impact,omitempty"`
	Evidence       []Evidence `json:"evidence,omitempty"`
	Error          string     `json:"error,omitempty"`
	SourcesChecked int        `json:"sources_checked"`
}

type Options struct {
	Enabled             bool
	Mode                string
	Timeout             time.Duration
	CacheTTL            time.Duration
	TrustedDomains      []string
	Sources             []string
	Redis               *cache.Redis
	RedisTimeout        time.Duration
	HTTPClient          *http.Client
	MaxBytes            int64
	AllowPrivateSources bool
}

type Service struct {
	enabled             bool
	mode                string
	timeout             time.Duration
	cacheTTL            time.Duration
	trustedDomains      []string
	sources             []string
	redis               *cache.Redis
	redisTimeout        time.Duration
	httpClient          *http.Client
	maxBytes            int64
	allowPrivateSources bool
	mu                  sync.Mutex
	memory              map[string]Report
}

func NewService(options Options) *Service {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	cacheTTL := options.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = 6 * time.Hour
	}
	redisTimeout := options.RedisTimeout
	if redisTimeout <= 0 {
		redisTimeout = 250 * time.Millisecond
	}
	maxBytes := options.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	trusted := normalizeList(options.TrustedDomains)
	if len(trusted) == 0 {
		trusted = DefaultTrustedDomains()
	}

	return &Service{
		enabled:             options.Enabled,
		mode:                strings.TrimSpace(options.Mode),
		timeout:             timeout,
		cacheTTL:            cacheTTL,
		trustedDomains:      trusted,
		sources:             normalizeList(options.Sources),
		redis:               options.Redis,
		redisTimeout:        redisTimeout,
		httpClient:          client,
		maxBytes:            maxBytes,
		allowPrivateSources: options.AllowPrivateSources,
		memory:              make(map[string]Report),
	}
}

func DefaultTrustedDomains() []string {
	return []string{
		"gov.vn",
		"bocongan.gov.vn",
		"mps.gov.vn",
		"baochinhphu.vn",
		"thanhnien.vn",
		"tuoitre.vn",
		"vnexpress.net",
		"vietnamnet.vn",
		"nhandan.vn",
		"vtv.vn",
		"vov.vn",
	}
}

func SplitList(value string) []string {
	return normalizeList(strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t'
	}))
}

func (s *Service) Enabled() bool {
	return s != nil && s.enabled
}

func (s *Service) Lookup(ctx context.Context, domain string, force bool) (Report, error) {
	if s == nil || !s.enabled {
		return Report{Domain: domain, Enabled: false}, nil
	}
	normalized, err := analysis.NormalizeDomain(domain)
	if err != nil {
		return Report{Domain: strings.TrimSpace(domain), Enabled: true, Error: err.Error()}, err
	}
	if !force {
		if report, ok := s.Cached(ctx, normalized); ok {
			report.CacheHit = true
			return report, nil
		}
	}

	lookupCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	report := Report{
		Domain:    normalized,
		Enabled:   true,
		CheckedAt: time.Now().UTC().Format(time.RFC3339Nano),
		ExpiresAt: time.Now().Add(s.cacheTTL).UTC().Format(time.RFC3339Nano),
	}
	for _, source := range s.sources {
		select {
		case <-lookupCtx.Done():
			report.Error = lookupCtx.Err().Error()
			s.store(ctx, normalized, report)
			return report, lookupCtx.Err()
		default:
		}
		evidence, err := s.fetchSource(lookupCtx, normalized, source)
		report.SourcesChecked++
		if err != nil {
			logjson.Warn("osint source lookup failed", correlation.Fields(ctx, map[string]any{
				"service": "osint",
				"domain":  normalized,
				"source":  source,
				"error":   err.Error(),
			}))
			continue
		}
		if evidence.SourceURL != "" {
			report.Evidence = append(report.Evidence, evidence)
		}
	}
	sort.SliceStable(report.Evidence, func(i, j int) bool {
		return report.Evidence[i].Confidence > report.Evidence[j].Confidence
	})
	report.ShouldBlock = HasStrongWarning(report.Evidence)
	if report.ShouldBlock {
		report.VerdictImpact = "escalate_malicious"
	}
	s.store(ctx, normalized, report)
	return report, nil
}

func (s *Service) Cached(ctx context.Context, domain string) (Report, bool) {
	if s == nil || !s.enabled {
		return Report{}, false
	}
	normalized, err := analysis.NormalizeDomain(domain)
	if err != nil {
		return Report{}, false
	}

	if s.redis != nil && s.redis.Enabled() {
		var report Report
		err := s.withRedis(ctx, func(redisCtx context.Context) error {
			found, err := s.redis.GetJSON(redisCtx, cacheKey(normalized), &report)
			if err != nil || !found {
				return err
			}
			return nil
		})
		if err == nil && report.Domain != "" && !expired(report) {
			return report, true
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	report, ok := s.memory[normalized]
	if !ok || expired(report) {
		return Report{}, false
	}
	return report, true
}

func (s *Service) Apply(result analysis.Result, report Report) analysis.Result {
	if !report.ShouldBlock {
		return result
	}
	if result.Score < 90 {
		result.Score = 90
	}
	result.Verdict = analysis.VerdictMalicious
	if result.Confidence < 0.92 {
		result.Confidence = 0.92
	}
	result.Category = "phishing"
	if !containsReason(result.Reasons, "public warning evidence") {
		result.Reasons = append(result.Reasons, "public warning evidence: official/trusted source reports phishing")
	}
	return result
}

func ShouldLookup(domain string, result analysis.Result) bool {
	normalized, err := analysis.NormalizeDomain(domain)
	if err != nil {
		return false
	}
	if isGovVN(normalized) {
		return false
	}
	for _, term := range sensitiveDomainTerms {
		if strings.Contains(normalized, term) {
			return true
		}
	}
	if result.Verdict == analysis.VerdictSuspicious || result.Score >= 35 {
		return true
	}
	return false
}

func HasStrongWarning(evidence []Evidence) bool {
	for _, item := range evidence {
		if item.Confidence >= strongEvidence &&
			(item.SourceType == TypeOfficialWarning || item.SourceType == TypeTrustedNewsWarning || item.SourceType == TypeSafeBrowsingMatch) {
			return true
		}
	}
	return false
}

func (s *Service) fetchSource(ctx context.Context, domain, source string) (Evidence, error) {
	parsed, err := url.Parse(strings.TrimSpace(source))
	if err != nil || parsed.Hostname() == "" {
		return Evidence{}, fmt.Errorf("invalid source url")
	}
	if err := s.validateSource(ctx, parsed); err != nil {
		return Evidence{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return Evidence{}, err
	}
	req.Header.Set("User-Agent", "SafeRoad-OSINT/1.0")
	client := *s.httpClient
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("too many redirects")
		}
		return s.validateSource(req.Context(), req.URL)
	}

	resp, err := client.Do(req)
	if err != nil {
		return Evidence{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Evidence{}, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var body bytes.Buffer
	if _, err := io.Copy(&body, io.LimitReader(resp.Body, s.maxBytes)); err != nil {
		return Evidence{}, err
	}
	content := body.String()
	matches := warningMatches(content)
	if !strings.Contains(strings.ToLower(content), strings.ToLower(domain)) || len(matches) == 0 {
		return Evidence{}, nil
	}

	sourceType, confidence := s.sourceTrust(parsed.Hostname())
	return Evidence{
		Domain:       domain,
		SourceURL:    parsed.String(),
		SourceTitle:  extractTitle(content),
		SourceType:   sourceType,
		Confidence:   confidence,
		MatchedTerms: matches,
		RetrievedAt:  time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func (s *Service) validateSource(ctx context.Context, parsed *url.URL) error {
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("unsupported source scheme")
	}
	host := strings.ToLower(parsed.Hostname())
	if !s.isTrustedHost(host) {
		return fmt.Errorf("untrusted source host %q", host)
	}
	if s.allowPrivateSources {
		return nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("resolve source host: %w", err)
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return fmt.Errorf("blocked private source address")
		}
	}
	return nil
}

func (s *Service) sourceTrust(host string) (string, float64) {
	host = strings.ToLower(strings.TrimSpace(host))
	if isOfficialHost(host) {
		return TypeOfficialWarning, 0.95
	}
	return TypeTrustedNewsWarning, 0.88
}

func (s *Service) isTrustedHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, trusted := range s.trustedDomains {
		trusted = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(trusted)), "*.")
		if parsed, err := url.Parse(trusted); err == nil && parsed.Hostname() != "" {
			trusted = parsed.Hostname()
		}
		if h, _, err := net.SplitHostPort(trusted); err == nil {
			trusted = h
		}
		if host == trusted || strings.HasSuffix(host, "."+trusted) {
			return true
		}
	}
	return false
}

func (s *Service) store(ctx context.Context, domain string, report Report) {
	if report.Domain == "" {
		report.Domain = domain
	}
	s.mu.Lock()
	s.memory[domain] = report
	s.mu.Unlock()

	if s.redis == nil || !s.redis.Enabled() {
		return
	}
	if err := s.withRedis(ctx, func(redisCtx context.Context) error {
		return s.redis.SetJSON(redisCtx, cacheKey(domain), report, s.cacheTTL)
	}); err != nil && !errors.Is(err, cache.ErrDisabled) {
		logjson.Warn("osint cache write failed", correlation.Fields(ctx, map[string]any{
			"service": "osint",
			"domain":  domain,
			"error":   err.Error(),
		}))
	}
}

func (s *Service) withRedis(parent context.Context, fn func(context.Context) error) error {
	if s.redis == nil || !s.redis.Enabled() {
		return cache.ErrDisabled
	}
	ctx, cancel := context.WithTimeout(parent, s.redisTimeout)
	defer cancel()
	return fn(ctx)
}

func cacheKey(domain string) string {
	return "safe-zone:osint:evidence:" + domain
}

func expired(report Report) bool {
	if report.ExpiresAt == "" {
		return false
	}
	expires, err := time.Parse(time.RFC3339Nano, report.ExpiresAt)
	if err != nil {
		return true
	}
	return time.Now().After(expires)
}

func warningMatches(content string) []string {
	lower := strings.ToLower(content)
	matches := make([]string, 0, 4)
	seen := map[string]bool{}
	for _, term := range warningTerms {
		if strings.Contains(lower, term) && !seen[term] {
			matches = append(matches, term)
			seen[term] = true
		}
	}
	return matches
}

func extractTitle(content string) string {
	match := titlePattern.FindStringSubmatch(content)
	if len(match) < 2 {
		return ""
	}
	title := strings.Join(strings.Fields(match[1]), " ")
	title = strings.ReplaceAll(title, "&amp;", "&")
	if len(title) > 180 {
		title = title[:180]
	}
	return title
}

func normalizeList(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func isGovVN(domain string) bool {
	return domain == "gov.vn" || strings.HasSuffix(domain, ".gov.vn")
}

func isOfficialHost(host string) bool {
	return isGovVN(host) || strings.Contains(host, "bocongan") || strings.Contains(host, "congan")
}

func isBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

func containsReason(reasons []string, needle string) bool {
	for _, reason := range reasons {
		if strings.Contains(reason, needle) {
			return true
		}
	}
	return false
}

func (r Report) MarshalJSON() ([]byte, error) {
	type alias Report
	if r.Evidence == nil {
		r.Evidence = []Evidence{}
	}
	return json.Marshal(alias(r))
}
