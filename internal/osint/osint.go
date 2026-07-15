package osint

import (
	"bytes"
	"context"
	"crypto/tls"
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
	"unicode/utf8"

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
	roleAttacker    = "attacker"
	roleVictim      = "victim"
	roleUnclear     = "unclear"
	contextRadius   = 220
	maxRoleContexts = 4
	cacheRevision   = "v2"
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

type DomainRoleClassifier interface {
	Enabled() bool
	ClassifyDomainRole(ctx context.Context, domain string, contexts []string) (string, error)
}

type hostResolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

type validatedSource struct {
	host string
	port string
	ips  []net.IP
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
	RoleClassifier      DomainRoleClassifier
	Resolver            hostResolver
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
	roleClassifier      DomainRoleClassifier
	resolver            hostResolver
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
	resolver := options.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
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
		roleClassifier:      options.RoleClassifier,
		resolver:            resolver,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return Evidence{}, err
	}
	req.Header.Set("User-Agent", "SafeRoad-OSINT/1.0")
	client := *s.httpClient
	client.Transport = s.validatedSourceTransport(client.Transport)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("too many redirects")
		}
		return nil
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

	role := s.classifyDomainRole(ctx, domain, content)
	if role == roleVictim {
		return Evidence{}, nil
	}

	sourceType, confidence := s.sourceTrust(parsed.Hostname())
	if role == roleUnclear {
		confidence *= 0.6
	}
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

func (s *Service) classifyDomainRole(ctx context.Context, domain, content string) string {
	contexts := extractContext(content, domain)
	if len(contexts) == 0 {
		return roleUnclear
	}

	if role := heuristicDomainRole(domain, contexts); role != roleUnclear {
		return role
	}
	if s == nil || s.roleClassifier == nil || !s.roleClassifier.Enabled() {
		return roleUnclear
	}

	role, err := s.roleClassifier.ClassifyDomainRole(ctx, domain, contexts)
	if err != nil {
		logjson.Warn("osint ai context classification failed; using heuristic fallback", correlation.Fields(ctx, map[string]any{
			"service": "osint",
			"domain":  domain,
			"error":   err.Error(),
		}))
		return roleUnclear
	}
	switch strings.ToLower(strings.TrimSpace(role)) {
	case roleAttacker:
		return roleAttacker
	case roleVictim:
		return roleVictim
	default:
		return roleUnclear
	}
}

func extractContext(content, domain string) []string {
	lower := strings.ToLower(content)
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || len(domain) > len(lower) {
		return nil
	}

	contexts := make([]string, 0, 2)
	for start := 0; start+len(domain) <= len(lower); {
		index := strings.Index(lower[start:], domain)
		if index < 0 {
			break
		}
		index += start
		left := index - contextRadius
		if left < 0 {
			left = 0
		}
		for left < index && !utf8.RuneStart(lower[left]) {
			left++
		}
		right := index + len(domain) + contextRadius
		if right > len(lower) {
			right = len(lower)
		}
		for right < len(lower) && !utf8.RuneStart(lower[right]) {
			right--
		}
		contexts = append(contexts, strings.Join(strings.Fields(lower[left:right]), " "))
		if len(contexts) >= maxRoleContexts {
			break
		}
		start = index + len(domain)
	}
	return normalizeList(contexts)
}

func heuristicDomainRole(domain string, contexts []string) string {
	quotedDomain := regexp.QuoteMeta(strings.ToLower(strings.TrimSpace(domain)))
	attackerPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\b` + quotedDomain + `\b\s*(?:là|la|:|-)?[^.\n<>]{0,100}(?:giả mạo|gia mao|lừa đảo|lua dao|phishing|scam|mạo danh|mao danh)`),
		regexp.MustCompile(`\b(?:cảnh báo|canh bao)[^.\n<>]{0,100}\b` + quotedDomain + `\b`),
	}
	victimPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?:giả mạo|gia mao|mạo danh|mao danh)[^.\n<>]{0,100}\b` + quotedDomain + `\b`),
		regexp.MustCompile(`\b` + quotedDomain + `\b[^.\n<>]{0,100}(?:chính thức|chinh thuc|hợp pháp|hop phap|bị giả mạo|bi gia mao)`),
		regexp.MustCompile(`\b` + quotedDomain + `\b[^.\n<>]{0,60}(?:không phải|khong phai)[^.\n<>]{0,60}(?:giả mạo|gia mao|lừa đảo|lua dao|phishing|scam)`),
		regexp.MustCompile(`(?:chính thức|chinh thuc|hợp pháp|hop phap)[^.\n<>]{0,60}\b` + quotedDomain + `\b`),
	}

	var attackerScore, victimScore int
	for _, context := range contexts {
		lower := strings.ToLower(context)
		for _, pattern := range attackerPatterns {
			if pattern.MatchString(lower) {
				attackerScore++
			}
		}
		for _, pattern := range victimPatterns {
			if pattern.MatchString(lower) {
				// An explicit "giả mạo <domain>" or legitimate-site marker is
				// stronger than a broad warning term elsewhere in the excerpt.
				victimScore += 3
			}
		}
	}

	switch {
	case attackerScore > victimScore:
		return roleAttacker
	case victimScore > attackerScore:
		return roleVictim
	default:
		return roleUnclear
	}
}

func (s *Service) validatedSourceTransport(base http.RoundTripper) http.RoundTripper {
	return &validatedSourceTransport{
		service: s,
		base:    base,
	}
}

type validatedSourceTransport struct {
	service *Service
	base    http.RoundTripper
}

func (t *validatedSourceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	validated, err := t.service.validateSource(req.Context(), req.URL)
	if err != nil {
		return nil, err
	}
	originalHost := req.URL.Host
	var lastErr error
	for _, ip := range validated.ips {
		pinnedReq := req.Clone(req.Context())
		pinnedURL := *req.URL
		pinnedURL.Host = net.JoinHostPort(ip.String(), validated.port)
		pinnedReq.URL = &pinnedURL
		pinnedReq.Host = originalHost

		transport := cloneValidatedTransport(t.base, validated.host, req.URL.Scheme)
		resp, err := transport.RoundTrip(pinnedReq)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("resolve source host: no usable addresses")
	}
	return nil, lastErr
}

func cloneValidatedTransport(base http.RoundTripper, serverName, scheme string) *http.Transport {
	var transport *http.Transport
	if existing, ok := base.(*http.Transport); ok && existing != nil {
		transport = existing.Clone()
	} else {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	transport.DisableKeepAlives = true
	//nolint:staticcheck // Clear the legacy hook too so a cloned transport cannot bypass validated IP pinning.
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	if scheme == "https" {
		tlsConfig := transport.TLSClientConfig
		if tlsConfig != nil {
			tlsConfig = tlsConfig.Clone()
		} else {
			tlsConfig = &tls.Config{}
		}
		tlsConfig.ServerName = serverName
		transport.TLSClientConfig = tlsConfig
	}
	return transport
}

func (s *Service) validateSource(ctx context.Context, parsed *url.URL) (validatedSource, error) {
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return validatedSource{}, fmt.Errorf("unsupported source scheme")
	}
	host := strings.ToLower(parsed.Hostname())
	if !s.isTrustedHost(host) {
		return validatedSource{}, fmt.Errorf("untrusted source host %q", host)
	}
	port := parsed.Port()
	if port == "" {
		switch parsed.Scheme {
		case "https":
			port = "443"
		default:
			port = "80"
		}
	}

	if ip := net.ParseIP(host); ip != nil {
		if !s.allowPrivateSources && isBlockedIP(ip) {
			return validatedSource{}, fmt.Errorf("blocked private source address")
		}
		return validatedSource{host: host, port: port, ips: []net.IP{ip}}, nil
	}

	ips, err := s.resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return validatedSource{}, fmt.Errorf("resolve source host: %w", err)
	}
	if len(ips) == 0 {
		return validatedSource{}, fmt.Errorf("resolve source host: no addresses")
	}
	for _, ip := range ips {
		if !s.allowPrivateSources && isBlockedIP(ip) {
			return validatedSource{}, fmt.Errorf("blocked private source address")
		}
	}
	return validatedSource{
		host: host,
		port: port,
		ips:  append([]net.IP(nil), ips...),
	}, nil
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
	return "safe-zone:osint:evidence:" + cacheRevision + ":" + domain
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
