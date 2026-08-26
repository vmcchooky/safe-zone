package analysis

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const urlFeatureCount = 18

var percentEscapePattern = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
var ipv4PathPattern = regexp.MustCompile(`(?:^|[^0-9a-fA-F:.])((?:\d{1,3}\.){3}\d{1,3})(?:$|[^0-9])`)
var repeatedWhitespacePattern = regexp.MustCompile(`\s\s+`)

type URLContext struct {
	RequestedURL  string
	ExpectedHost  string
	RedirectChain []string
}

type URLClassifier interface {
	Enabled() bool
	Revision() string
	ClassifyURL(URLContext) (MLDecision, error)
}

type URLClassifierMetadata interface {
	ModelVersion() string
	URLThreshold() float64
}

type URLMonitoringReference struct {
	ReferenceKind           string
	ReferenceRows           int
	Operational             bool
	ProbabilityBuckets      []string
	ProbabilityDistribution []float64
	MinimumLiveSamples      int
	PSIWatchThreshold       float64
	PSIAlertThreshold       float64
}

type URLMonitoringReferenceProvider interface {
	URLMonitoringReference() URLMonitoringReference
}

type urlModelBundle struct {
	SchemaVersion int    `json:"schema_version"`
	ModelVersion  string `json:"model_version"`
	Product       struct {
		AllowedSchemes                         []string `json:"allowed_schemes"`
		MaximumURLBytes                        int      `json:"maximum_url_bytes"`
		MaximumRedirects                       int      `json:"maximum_redirects"`
		RejectCredentials                      bool     `json:"reject_credentials"`
		RequireRequestedURLHostEqualsCanonical bool     `json:"require_requested_url_host_equals_canonical_domain"`
		ServerSideFetch                        bool     `json:"server_side_fetch"`
		RawURLLogging                          bool     `json:"raw_url_logging"`
		RawQueryLogging                        bool     `json:"raw_query_logging"`
	} `json:"product_contract"`
	Feature struct {
		HandcraftedFeatures  []string `json:"handcrafted_features"`
		SuspiciousTokens     []string `json:"suspicious_tokens"`
		BrandTokens          []string `json:"brand_tokens"`
		ExecutableExtensions []string `json:"executable_extensions"`
	} `json:"feature_contract"`
	Vectorizer struct {
		Analyzer    string    `json:"analyzer"`
		Lowercase   bool      `json:"lowercase"`
		NgramMin    int       `json:"ngram_min"`
		NgramMax    int       `json:"ngram_max"`
		SublinearTF bool      `json:"sublinear_tf"`
		Norm        string    `json:"norm"`
		Vocabulary  []string  `json:"vocabulary"`
		IDF         []float64 `json:"idf"`
	} `json:"vectorizer"`
	Scaler struct {
		Mean  []float64 `json:"mean"`
		Scale []float64 `json:"scale"`
	} `json:"scaler"`
	Linear struct {
		Loss         string    `json:"loss"`
		Coefficients []float64 `json:"coefficients"`
		Intercept    float64   `json:"intercept"`
	} `json:"linear_model"`
	Calibration struct {
		Method      string  `json:"method"`
		Coefficient float64 `json:"coefficient"`
		Intercept   float64 `json:"intercept"`
	} `json:"calibration"`
	Policy struct {
		ModeDefault           string   `json:"mode_default"`
		SupportedRuntimeModes []string `json:"supported_runtime_modes"`
		URLThreshold          float64  `json:"url_threshold"`
		FailurePolicy         string   `json:"failure_policy"`
	} `json:"policy"`
	Monitoring struct {
		ReferenceKind                 string    `json:"reference_kind"`
		ReferenceRows                 int       `json:"reference_rows"`
		ReferenceOperational          bool      `json:"reference_operational"`
		ProbabilityBuckets            []string  `json:"probability_buckets"`
		ProbabilityDistributionSmooth []float64 `json:"probability_distribution_smoothed"`
		PSI                           struct {
			MinimumLiveSamples int     `json:"minimum_live_samples"`
			WatchThreshold     float64 `json:"watch_threshold"`
			AlertThreshold     float64 `json:"alert_threshold"`
		} `json:"psi"`
	} `json:"monitoring"`
}

type URLBundleClassifier struct {
	bundle     urlModelBundle
	vocabulary map[string]int
	revision   string
}

type parsedURLContext struct {
	scheme     string
	host       string
	path       string
	rawQuery   string
	queryPairs [][2]string
}

type sparseURLValue struct {
	index int
	value float64
}

func NewURLBundleClassifier(bundleDir string) (*URLBundleClassifier, error) {
	bundleDir = strings.TrimSpace(bundleDir)
	if bundleDir == "" {
		return nil, errors.New("URL ML bundle directory is empty")
	}
	modelPath := filepath.Join(bundleDir, "url_model.v1.json")
	goldenPath := filepath.Join(bundleDir, "golden_vectors.v1.json")
	sumsPath := filepath.Join(bundleDir, "SHA256SUMS")
	for _, path := range []string{modelPath, goldenPath, sumsPath} {
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			return nil, fmt.Errorf("URL bundle file missing: %s", filepath.Base(path))
		}
	}
	expected, err := readURLChecksums(sumsPath)
	if err != nil {
		return nil, err
	}
	for name, path := range map[string]string{
		"url_model.v1.json":      modelPath,
		"golden_vectors.v1.json": goldenPath,
	} {
		want, ok := expected[name]
		if !ok {
			return nil, fmt.Errorf("URL SHA256SUMS missing entry for %s", name)
		}
		got, err := hashFile(path)
		if err != nil {
			return nil, err
		}
		if !strings.EqualFold(got, want) {
			return nil, fmt.Errorf("URL bundle SHA256 mismatch for %s", name)
		}
	}
	data, err := os.ReadFile(modelPath) // #nosec G304 -- explicit validated bundle path.
	if err != nil {
		return nil, fmt.Errorf("read URL model bundle: %w", err)
	}
	var bundle urlModelBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("parse URL model bundle: %w", err)
	}
	if err := validateURLModelBundle(bundle); err != nil {
		return nil, err
	}
	vocabulary := make(map[string]int, len(bundle.Vectorizer.Vocabulary))
	for index, token := range bundle.Vectorizer.Vocabulary {
		if token == "" {
			return nil, errors.New("URL model vocabulary contains empty token")
		}
		if _, duplicate := vocabulary[token]; duplicate {
			return nil, errors.New("URL model vocabulary contains duplicate token")
		}
		vocabulary[token] = index
	}
	revisionMaterial := expected["url_model.v1.json"] + ":" + expected["golden_vectors.v1.json"]
	revision := sha256.Sum256([]byte(revisionMaterial))
	return &URLBundleClassifier{
		bundle:     bundle,
		vocabulary: vocabulary,
		revision:   hex.EncodeToString(revision[:]),
	}, nil
}

func validateURLModelBundle(bundle urlModelBundle) error {
	if bundle.SchemaVersion != 1 || strings.TrimSpace(bundle.ModelVersion) == "" {
		return errors.New("unsupported URL model bundle schema")
	}
	if bundle.Product.ServerSideFetch || bundle.Product.RawURLLogging || bundle.Product.RawQueryLogging {
		return errors.New("unsafe URL model product contract")
	}
	if bundle.Product.MaximumURLBytes <= 0 || bundle.Product.MaximumURLBytes > 16384 ||
		bundle.Product.MaximumRedirects < 0 || bundle.Product.MaximumRedirects > 10 {
		return errors.New("invalid URL model input bounds")
	}
	if len(bundle.Feature.HandcraftedFeatures) != urlFeatureCount ||
		len(bundle.Scaler.Mean) != urlFeatureCount || len(bundle.Scaler.Scale) != urlFeatureCount {
		return errors.New("URL handcrafted feature contract mismatch")
	}
	if bundle.Vectorizer.Analyzer != "char" || !bundle.Vectorizer.Lowercase ||
		bundle.Vectorizer.NgramMin < 1 || bundle.Vectorizer.NgramMax < bundle.Vectorizer.NgramMin ||
		!bundle.Vectorizer.SublinearTF || bundle.Vectorizer.Norm != "l2" {
		return errors.New("unsupported URL vectorizer contract")
	}
	if len(bundle.Vectorizer.Vocabulary) == 0 ||
		len(bundle.Vectorizer.Vocabulary) != len(bundle.Vectorizer.IDF) {
		return errors.New("URL vectorizer vocabulary/IDF mismatch")
	}
	if len(bundle.Linear.Coefficients) != urlFeatureCount+len(bundle.Vectorizer.Vocabulary) ||
		bundle.Linear.Loss != "log_loss" {
		return errors.New("URL linear model shape mismatch")
	}
	if bundle.Calibration.Method != "sklearn_logistic_sigmoid" ||
		bundle.Policy.URLThreshold <= 0 || bundle.Policy.URLThreshold >= 1 ||
		bundle.Policy.ModeDefault != "disabled" ||
		bundle.Policy.FailurePolicy != "fail_open_to_domain_only" {
		return errors.New("unsupported URL calibration or policy contract")
	}
	if bundle.Monitoring.ReferenceRows <= 0 ||
		len(bundle.Monitoring.ProbabilityBuckets) != 10 ||
		len(bundle.Monitoring.ProbabilityDistributionSmooth) != 10 ||
		bundle.Monitoring.PSI.MinimumLiveSamples <= 0 ||
		bundle.Monitoring.PSI.WatchThreshold <= 0 ||
		bundle.Monitoring.PSI.AlertThreshold <= bundle.Monitoring.PSI.WatchThreshold {
		return errors.New("invalid URL monitoring reference")
	}
	distributionSum := 0.0
	for _, value := range bundle.Monitoring.ProbabilityDistributionSmooth {
		if value <= 0 || math.IsNaN(value) || math.IsInf(value, 0) {
			return errors.New("invalid URL monitoring probability distribution")
		}
		distributionSum += value
	}
	if math.Abs(distributionSum-1) > 1e-9 {
		return errors.New("URL monitoring probability distribution does not sum to one")
	}
	for _, value := range append(append(append([]float64{}, bundle.Vectorizer.IDF...), bundle.Scaler.Mean...), bundle.Scaler.Scale...) {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return errors.New("URL model contains non-finite value")
		}
	}
	for _, scale := range bundle.Scaler.Scale {
		if scale <= 0 {
			return errors.New("URL model contains non-positive scale")
		}
	}
	return nil
}

func readURLChecksums(path string) (map[string]string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- explicit validated bundle path.
	if err != nil {
		return nil, fmt.Errorf("read URL SHA256SUMS: %w", err)
	}
	result := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || len(fields[0]) != sha256.Size*2 {
			return nil, errors.New("malformed URL SHA256SUMS entry")
		}
		result[fields[1]] = strings.ToLower(fields[0])
	}
	return result, scanner.Err()
}

func (c *URLBundleClassifier) Enabled() bool {
	return c != nil && len(c.vocabulary) > 0
}

func (c *URLBundleClassifier) Revision() string {
	if c == nil {
		return ""
	}
	return c.revision
}

func (c *URLBundleClassifier) ModelVersion() string {
	if c == nil {
		return ""
	}
	return c.bundle.ModelVersion
}

func (c *URLBundleClassifier) URLThreshold() float64 {
	if c == nil {
		return 0
	}
	return c.bundle.Policy.URLThreshold
}

func (c *URLBundleClassifier) URLMonitoringReference() URLMonitoringReference {
	if c == nil {
		return URLMonitoringReference{}
	}
	return URLMonitoringReference{
		ReferenceKind:           c.bundle.Monitoring.ReferenceKind,
		ReferenceRows:           c.bundle.Monitoring.ReferenceRows,
		Operational:             c.bundle.Monitoring.ReferenceOperational,
		ProbabilityBuckets:      append([]string(nil), c.bundle.Monitoring.ProbabilityBuckets...),
		ProbabilityDistribution: append([]float64(nil), c.bundle.Monitoring.ProbabilityDistributionSmooth...),
		MinimumLiveSamples:      c.bundle.Monitoring.PSI.MinimumLiveSamples,
		PSIWatchThreshold:       c.bundle.Monitoring.PSI.WatchThreshold,
		PSIAlertThreshold:       c.bundle.Monitoring.PSI.AlertThreshold,
	}
}

func (c *URLBundleClassifier) ClassifyURL(context URLContext) (MLDecision, error) {
	decision := MLDecision{Action: MLActionAbstain}
	if !c.Enabled() {
		return decision, errors.New("URL classifier is disabled")
	}
	decision.ModelVersion = c.bundle.ModelVersion
	decision.Revision = c.revision
	text, handcrafted, err := c.extract(context)
	if err != nil {
		return decision, err
	}
	margin := c.bundle.Linear.Intercept
	for index, value := range handcrafted {
		scaled := (value - c.bundle.Scaler.Mean[index]) / c.bundle.Scaler.Scale[index]
		margin += scaled * c.bundle.Linear.Coefficients[index]
	}
	for _, item := range c.tfidf(text) {
		margin += item.value * c.bundle.Linear.Coefficients[urlFeatureCount+item.index]
	}
	if math.IsNaN(margin) || math.IsInf(margin, 0) {
		return decision, errors.New("URL model margin is not finite")
	}
	decision.RawMargin = margin
	decision.Probability = logisticProbability(
		c.bundle.Calibration.Coefficient*margin + c.bundle.Calibration.Intercept,
	)
	if decision.Probability >= c.bundle.Policy.URLThreshold {
		decision.Action = MLActionPromoteMalicious
	}
	return decision, nil
}

func logisticProbability(value float64) float64 {
	if value >= 0 {
		return 1 / (1 + math.Exp(-value))
	}
	expValue := math.Exp(value)
	return expValue / (1 + expValue)
}

func (c *URLBundleClassifier) extract(context URLContext) (string, []float64, error) {
	requested, err := c.parseURL(context.RequestedURL)
	if err != nil {
		return "", nil, err
	}
	if c.bundle.Product.RequireRequestedURLHostEqualsCanonical {
		expected, err := canonicalizeMLDomain(context.ExpectedHost)
		if err != nil || !expected.valid || expected.ascii != requested.host {
			return "", nil, errors.New("invalid_url_context: host_mismatch")
		}
	}
	if len(context.RedirectChain) > c.bundle.Product.MaximumRedirects {
		return "", nil, errors.New("invalid_url_context: redirect_limit")
	}
	chain := make([]parsedURLContext, 0, len(context.RedirectChain)+1)
	chain = append(chain, requested)
	for _, raw := range context.RedirectChain {
		parsed, err := c.parseURL(raw)
		if err != nil {
			return "", nil, err
		}
		chain = append(chain, parsed)
	}
	crossHost, downgrade := 0, 0
	for index := 0; index+1 < len(chain); index++ {
		if chain[index].host != chain[index+1].host {
			crossHost++
		}
		if chain[index].scheme == "https" && chain[index+1].scheme == "http" {
			downgrade++
		}
	}
	queryTokens := make([]string, 0, len(requested.queryPairs))
	for _, pair := range requested.queryPairs {
		queryTokens = append(queryTokens, strings.ToLower(pair[0])+"="+redactURLValueShape(pair[1]))
	}
	featureText := strings.ToLower(requested.path)
	if len(queryTokens) > 0 {
		featureText += "?" + strings.Join(queryTokens, "&")
	}
	rawComponent := requested.path
	if requested.rawQuery != "" {
		rawComponent += "?" + requested.rawQuery
	}
	pathRunes := []rune(requested.path)
	rawRunes := []rune(rawComponent)
	digitCount, specialCount := 0, 0
	for _, value := range rawRunes {
		if unicode.IsDigit(value) {
			digitCount++
		}
		if !unicode.IsLetter(value) && !unicode.IsDigit(value) {
			specialCount++
		}
	}
	visibleLength := len(rawRunes)
	if visibleLength == 0 {
		visibleLength = 1
	}
	pathDepth := 0
	for _, segment := range strings.Split(requested.path, "/") {
		if segment != "" {
			pathDepth++
		}
	}
	features := []float64{
		float64(len(pathRunes)),
		float64(pathDepth),
		float64(len([]rune(requested.rawQuery))),
		float64(len(requested.queryPairs)),
		float64(len(percentEscapePattern.FindAllString(rawComponent, -1))),
		float64(digitCount),
		float64(digitCount) / float64(visibleLength),
		float64(specialCount),
		runeEntropy(pathRunes),
		float64(countTokens(featureText, c.bundle.Feature.SuspiciousTokens)),
		float64(countTokens(featureText, c.bundle.Feature.BrandTokens)),
		float64(hasIPInURLPath(requested.path)),
		boolFloat(strings.Contains(requested.path, "//")),
		boolFloat(strings.Contains(rawComponent, "@")),
		boolFloat(hasURLSuffix(strings.ToLower(requested.path), c.bundle.Feature.ExecutableExtensions)),
		float64(len(context.RedirectChain)),
		float64(crossHost),
		float64(downgrade),
	}
	return featureText, features, nil
}

func (c *URLBundleClassifier) parseURL(raw string) (parsedURLContext, error) {
	value := strings.TrimSpace(raw)
	if value == "" || len([]byte(value)) > c.bundle.Product.MaximumURLBytes {
		return parsedURLContext{}, errors.New("invalid_url_context: url_length")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" || !parsed.IsAbs() {
		return parsedURLContext{}, errors.New("invalid_url_context: parse")
	}
	scheme := strings.ToLower(parsed.Scheme)
	allowed := false
	for _, candidate := range c.bundle.Product.AllowedSchemes {
		if scheme == strings.ToLower(candidate) {
			allowed = true
			break
		}
	}
	if !allowed {
		return parsedURLContext{}, errors.New("invalid_url_context: scheme")
	}
	if c.bundle.Product.RejectCredentials && parsed.User != nil {
		return parsedURLContext{}, errors.New("invalid_url_context: credentials")
	}
	canonical, err := canonicalizeMLDomain(parsed.Hostname())
	if err != nil || !canonical.valid {
		return parsedURLContext{}, errors.New("invalid_url_context: host")
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	pairs := make([][2]string, 0)
	if parsed.RawQuery != "" {
		for _, field := range strings.Split(parsed.RawQuery, "&") {
			parts := strings.SplitN(field, "=", 2)
			key, err := url.QueryUnescape(parts[0])
			if err != nil {
				continue
			}
			queryValue := ""
			if len(parts) == 2 {
				queryValue, err = url.QueryUnescape(parts[1])
				if err != nil {
					continue
				}
			}
			pairs = append(pairs, [2]string{key, queryValue})
		}
	}
	sort.Slice(pairs, func(left, right int) bool {
		leftKey, rightKey := strings.ToLower(pairs[left][0]), strings.ToLower(pairs[right][0])
		if leftKey != rightKey {
			return leftKey < rightKey
		}
		return pairs[left][1] < pairs[right][1]
	})
	return parsedURLContext{
		scheme:     scheme,
		host:       canonical.ascii,
		path:       path,
		rawQuery:   parsed.RawQuery,
		queryPairs: pairs,
	}, nil
}

func redactURLValueShape(value string) string {
	if value == "" {
		return "empty"
	}
	tokens := make([]string, 0)
	lastType := byte(0)
	runLength := 0
	flush := func() {
		if runLength > 0 {
			tokens = append(tokens, fmt.Sprintf("%c%d", lastType, base2LengthBucket(runLength)))
		}
	}
	for _, value := range value {
		valueType := byte('s')
		if unicode.IsLetter(value) {
			valueType = 'a'
		} else if unicode.IsDigit(value) {
			valueType = 'd'
		}
		if valueType == lastType {
			runLength++
			continue
		}
		flush()
		lastType = valueType
		runLength = 1
	}
	flush()
	return strings.Join(tokens, "-")
}

func base2LengthBucket(length int) int {
	if length <= 0 {
		return 0
	}
	bucket := 1
	for bucket*2 <= length && bucket < 64 {
		bucket *= 2
	}
	if bucket > 64 {
		return 64
	}
	return bucket
}

func runeEntropy(values []rune) float64 {
	if len(values) == 0 {
		return 0
	}
	counts := make(map[rune]int)
	for _, value := range values {
		counts[value]++
	}
	length := float64(len(values))
	result := 0.0
	for _, count := range counts {
		probability := float64(count) / length
		result -= probability * math.Log2(probability)
	}
	return result
}

func countTokens(value string, tokens []string) int {
	lowered := strings.ToLower(value)
	total := 0
	for _, token := range tokens {
		if token != "" {
			total += strings.Count(lowered, strings.ToLower(token))
		}
	}
	return total
}

func hasIPInURLPath(path string) int {
	for _, match := range ipv4PathPattern.FindAllStringSubmatch(path, -1) {
		if len(match) > 1 && net.ParseIP(match[1]) != nil {
			return 1
		}
	}
	return 0
}

func boolFloat(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func hasURLSuffix(value string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(value, strings.ToLower(suffix)) {
			return true
		}
	}
	return false
}

func (c *URLBundleClassifier) tfidf(text string) []sparseURLValue {
	if c.bundle.Vectorizer.Lowercase {
		text = strings.ToLower(text)
	}
	text = repeatedWhitespacePattern.ReplaceAllString(text, " ")
	values := []rune(text)
	counts := make(map[int]int)
	for size := c.bundle.Vectorizer.NgramMin; size <= c.bundle.Vectorizer.NgramMax; size++ {
		for start := 0; start+size <= len(values); start++ {
			token := string(values[start : start+size])
			if index, ok := c.vocabulary[token]; ok {
				counts[index]++
			}
		}
	}
	indexes := make([]int, 0, len(counts))
	for index := range counts {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	result := make([]sparseURLValue, 0, len(indexes))
	normSquared := 0.0
	for _, index := range indexes {
		count := counts[index]
		tf := float64(count)
		if c.bundle.Vectorizer.SublinearTF {
			tf = 1 + math.Log(tf)
		}
		value := tf * c.bundle.Vectorizer.IDF[index]
		result = append(result, sparseURLValue{index: index, value: value})
		normSquared += value * value
	}
	if normSquared > 0 {
		norm := math.Sqrt(normSquared)
		for index := range result {
			result[index].value /= norm
		}
	}
	return result
}

var _ URLClassifier = (*URLBundleClassifier)(nil)
var _ URLClassifierMetadata = (*URLBundleClassifier)(nil)
var _ URLMonitoringReferenceProvider = (*URLBundleClassifier)(nil)
