package feed

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
	"safe-zone/internal/logjson"
)

type ParseStats struct {
	Valid               int `json:"valid"`
	Invalid             int `json:"invalid"`
	Duplicates          int `json:"duplicates"`
	Skipped             int `json:"skipped"`
	SkippedPublicSuffix int `json:"skipped_public_suffix"`
	SkippedSharedHost   int `json:"skipped_shared_host"`
	// ChurnProneTenants counts admitted members whose label sits under a
	// recycled-label root and therefore received the shortened expiry
	// window. They are still admitted and still block: the counter exists
	// so feed composition is visible instead of inferred.
	ChurnProneTenants int `json:"churn_prone_tenants"`
	// TruncatedDomains counts distinct domains that arrived after the
	// deduplication set hit maxDistinctFeedDomains. They were still passed to
	// the caller and are not lost, but they are classified as duplicates, so
	// the count is how an operator tells a healthy feed from one whose
	// distinct-domain count exceeded what the process is willing to track.
	TruncatedDomains int `json:"truncated_domains"`
}

type IndicatorKind string

const (
	IndicatorDomain IndicatorKind = "domain"
	IndicatorURL    IndicatorKind = "url"
)

// Indicator preserves whether a feed entry described a whole domain or only a
// URL resource. The resource fingerprint stays private because it can contain
// sensitive path/query material from a threat feed.
type Indicator struct {
	Domain              string        `json:"domain"`
	Kind                IndicatorKind `json:"kind"`
	PathScoped          bool          `json:"path_scoped"`
	resourceFingerprint [sha256.Size]byte
}

// ParseEach streams domain names from the reader and invokes the handler callback
// for each successfully parsed domain. Caps parsing at 100MB to avoid OOM crashes.
func ParseEach(r io.Reader, onDomain func(domain string) error, stats *ParseStats) error {
	if onDomain == nil {
		return errors.New("domain handler is required")
	}
	if stats == nil {
		stats = &ParseStats{}
	}

	return ParseEachIndicator(r, func(indicator Indicator, duplicate bool) error {
		if duplicate {
			return nil
		}
		return onDomain(indicator.Domain)
	}, stats)
}

// ParseEachIndicator invokes the handler for every valid feed candidate. The
// duplicate flag reports whether the normalized domain was already observed;
// callers that need URL corroboration can therefore distinguish repeated
// resources without changing the legacy ParseEach deduplication contract.
//
// The deduplication set is bounded by maxDistinctFeedDomains. A 100MB feed of
// short hostnames holds millions of distinct entries, and the set retains one of
// them all: at roughly 15 bytes per hostname that is several hundred megabytes
// before the caller retains anything of its own, on a service sized for a small
// VPS. Past the cap an unseen domain is treated as already seen, which costs a
// duplicate classification and nothing else — the handler still runs for every
// indicator, so no IOC is lost. The overflow is reported through
// ParseStats.TruncatedDomains rather than being invisible.
func ParseEachIndicator(r io.Reader, onIndicator func(indicator Indicator, duplicate bool) error, stats *ParseStats) error {
	return parseIndicatorsWithLimit(r, newBoundedSeenSet(resolvedFeedDomainLimit()), stats, onIndicator)
}

// parseIndicatorsWithLimit is ParseEachIndicator with an explicit dedup-set
// limit, so tests can exercise the cap without building a multi-million-entry
// feed. Production callers get the default via ParseEachIndicator.
func parseIndicatorsWithLimit(r io.Reader, seen *boundedSeenSet, stats *ParseStats, onIndicator func(Indicator, bool) error) error {
	if onIndicator == nil {
		return errors.New("indicator handler is required")
	}
	if stats == nil {
		stats = &ParseStats{}
	}

	limited := io.LimitReader(r, 100*1024*1024)
	br := bufio.NewReader(limited)
	peekBytes, _ := br.Peek(4096)

	var parseErr error
	if isProbablyCSV(peekBytes) {
		parseErr = parseCSVStream(br, seen, stats, onIndicator)
	} else {
		parseErr = parseTextStream(br, seen, stats, onIndicator)
	}
	stats.TruncatedDomains = seen.overflowed
	if stats.TruncatedDomains > 0 {
		// Logged rather than latched: the sync report carries the number, and
		// this is a per-sync occurrence rather than a startup condition, so a
		// one-shot warning would hide a feed that keeps exceeding the cap.
		logjson.Warn("threat feed exceeded the distinct-domain cap; later distinct domains were classified as duplicates", map[string]any{
			"service":   "feed",
			"limit":     seen.limit,
			"truncated": seen.overflowed,
		})
	}
	return parseErr
}

// maxDistinctFeedDomains bounds the deduplication set, and the admission state
// map. Sized well above a real threat feed (URLhaus recent is O(10^4), OpenPhish
// O(10^5)) and far below what would exhaust a small host, so ordinary feeds are
// unaffected and a hostile one is degraded rather than fatal.
//
// Overridable because the right value depends on the host: a larger deployment
// importing a very large list may need more headroom, and a small one may want
// less. Set it to 0 to restore the previous unbounded behaviour.
const defaultMaxDistinctFeedDomains = 2_000_000

// unboundedFeedDomains is the resolved cap when an operator asks for no cap.
//
// The documented meaning of SAFE_ZONE_FEED_MAX_DISTINCT_DOMAINS=0 is "restore the
// previous unbounded behaviour", and a literal 0 cannot express that to a
// `len(m) >= limit` capacity check, because zero is both "no room left" and "no
// limit". Both ingestion call sites therefore treated an explicit 0 as a full set:
// the dedup set reported every unseen domain as already seen, and the admission
// planner marked every domain unclassifiable. The result was a sync that exited 0,
// reported success, and ingested nothing at all.
//
// The cap is stored separately from the set so the two readings cannot collide.
const unboundedFeedDomains = -1

// envMaxDistinctFeedDomains names the cap override.
const envMaxDistinctFeedDomains = "SAFE_ZONE_FEED_MAX_DISTINCT_DOMAINS"

// resolvedFeedDomainLimit returns the effective cap for this run, or
// unboundedFeedDomains when the operator asked for no cap.
func resolvedFeedDomainLimit() int {
	if limit := maxDistinctFeedDomains(); limit > 0 {
		return limit
	}
	return unboundedFeedDomains
}

func maxDistinctFeedDomains() int {
	value := config.Int(envMaxDistinctFeedDomains, defaultMaxDistinctFeedDomains)
	if value < 0 {
		return 0
	}
	return value
}

// boundedSeenSet is the deduplication set with a hard entry limit.
type boundedSeenSet struct {
	entries    map[string]struct{}
	limit      int
	overflowed int
}

// newBoundedSeenSet returns a deduplication set with the given cap. Any
// non-positive cap means unbounded, which is the documented meaning of
// SAFE_ZONE_FEED_MAX_DISTINCT_DOMAINS=0. Normalising here rather than only at the
// environment reader keeps every caller correct, including the ones that pass a
// resolved value straight through: a raw 0 previously re-read the environment,
// resolved to 0 again, and reported every unseen domain as a duplicate, so a sync
// exited 0, reported success, and ingested nothing.
func newBoundedSeenSet(limit int) *boundedSeenSet {
	if limit <= 0 {
		limit = unboundedFeedDomains
	}
	return &boundedSeenSet{entries: make(map[string]struct{}, 1024), limit: limit}
}

// mark reports whether the domain was already recorded, recording it otherwise.
// Once the limit is reached, an unseen domain is reported as already seen: the
// indicator still reaches the caller, only the duplicate flag differs.
//
// An unbounded set never reports a duplicate for capacity reasons.
func (s *boundedSeenSet) mark(domain string) (duplicate bool) {
	if _, ok := s.entries[domain]; ok {
		return true
	}
	if s.limit >= 0 && len(s.entries) >= s.limit {
		s.overflowed++
		return true
	}
	s.entries[domain] = struct{}{}
	return false
}

func parseCSVStream(r io.Reader, seen *boundedSeenSet, stats *ParseStats, onIndicator func(Indicator, bool) error) error {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1 // Allow variable fields per row to prevent drift crashes

	for {
		row, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			stats.Invalid++
			continue
		}

		if len(row) == 0 {
			stats.Skipped++
			continue
		}

		indicator, ok := firstIndicator(row)
		if !ok {
			stats.Invalid++
			continue
		}

		if err := addIndicator(stats, seen, indicator, onIndicator); err != nil {
			return err
		}
	}

	return nil
}

func parseTextStream(r io.Reader, seen *boundedSeenSet, stats *ParseStats, onIndicator func(Indicator, bool) error) error {
	scanner := bufio.NewScanner(r)
	// Enforce maximum line size of 1MB (1024*1024 bytes) as asserted by tests
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			stats.Skipped++
			continue
		}
		if strings.HasPrefix(line, "#") {
			stats.Skipped++
			continue
		}

		parsedAny := false
		lineHadValid := false
		lineInvalid := 0
		for _, field := range strings.Fields(line) {
			if strings.HasPrefix(field, "#") {
				break
			}
			field = stripComment(strings.TrimSpace(field))
			if field == "" {
				continue
			}
			// Hosts-format feeds start with a sinkhole IP such as 0.0.0.0 or
			// 127.0.0.1. It is metadata, not an invalid domain candidate.
			if net.ParseIP(strings.Trim(field, "[]")) != nil {
				continue
			}
			parsedAny = true

			indicator, err := normalizeIndicator(field)
			if err != nil {
				lineInvalid++
				continue
			}

			lineHadValid = true
			if err := addIndicator(stats, seen, indicator, onIndicator); err != nil {
				return err
			}
		}
		if !parsedAny {
			stats.Skipped++
			continue
		}
		if lineHadValid {
			stats.Invalid += lineInvalid
			continue
		}
		if lineInvalid > 0 {
			stats.Invalid++
		}
	}

	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return fmt.Errorf("feed line exceeds 1048576 bytes: %w", err)
		}
		return err
	}

	return nil
}

func firstIndicator(fields []string) (Indicator, bool) {
	for _, field := range fields {
		field = stripComment(strings.TrimSpace(field))
		if field == "" {
			continue
		}

		indicator, err := normalizeIndicator(field)
		if err == nil {
			return indicator, true
		}
	}

	return Indicator{}, false
}

func addIndicator(stats *ParseStats, seen *boundedSeenSet, indicator Indicator, onIndicator func(Indicator, bool) error) error {
	duplicate := seen.mark(indicator.Domain)
	if duplicate {
		stats.Duplicates++
		return onIndicator(indicator, true)
	}

	stats.Valid++
	return onIndicator(indicator, false)
}

func stripComment(value string) string {
	if strings.HasPrefix(value, "#") {
		return ""
	}
	if strings.Contains(value, "://") {
		return value
	}
	if index := strings.Index(value, "#"); index >= 0 {
		return strings.TrimSpace(value[:index])
	}

	return value
}

func normalizeIndicator(value string) (Indicator, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return Indicator{}, errors.New("empty feed candidate")
	}

	indicator := Indicator{Kind: IndicatorDomain}
	isURL := strings.Contains(value, "://") || (strings.Contains(value, "/") && !strings.HasPrefix(value, "/"))
	if isURL {
		parseValue := value
		if !strings.Contains(parseValue, "://") {
			parseValue = "http://" + parseValue
		}
		parsed, err := url.Parse(parseValue)
		if err != nil || parsed.Hostname() == "" {
			return Indicator{}, errors.New("invalid feed url candidate")
		}
		value = parsed.Hostname()
		indicator.Kind = IndicatorURL
		indicator.PathScoped = (parsed.EscapedPath() != "" && parsed.EscapedPath() != "/") || parsed.RawQuery != "" || parsed.Fragment != ""
		resourceKey := parsed.EscapedPath() + "?" + parsed.RawQuery + "#" + parsed.Fragment
		indicator.resourceFingerprint = sha256.Sum256([]byte(resourceKey))
	}

	domain, err := analysis.NormalizeDomain(value)
	if err != nil {
		return Indicator{}, err
	}
	if !strings.Contains(domain, ".") {
		return Indicator{}, errors.New("feed candidate must be a domain, not a single label")
	}

	indicator.Domain = domain
	return indicator, nil
}

func isProbablyCSV(peek []byte) bool {
	if len(peek) == 0 {
		return false
	}
	lines := strings.Split(string(peek), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return strings.Contains(line, ",")
	}

	return false
}
