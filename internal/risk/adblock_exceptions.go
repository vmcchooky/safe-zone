package risk

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"safe-zone/internal/config"
	"safe-zone/internal/domaintrie"
	"safe-zone/internal/logjson"
	"safe-zone/internal/safefile"
)

// Scoped adblock/content exceptions (PR3A).
//
// A content exception suppresses exactly one adblock/content-policy match so
// the request continues through the normal security pipeline. It is not a
// whitelist: it never returns allow early, never rewrites the security
// Result, and never bypasses admin overrides, threat feed, lexical, ML, AI,
// OSINT or dynamic group enforcement.

const (
	// envAdblockExceptionsFile names the JSON exception config. Empty/unset
	// means the feature is disabled.
	envAdblockExceptionsFile = "SAFE_ZONE_ADBLOCK_EXCEPTIONS_FILE"

	// Bounded config limits (fail-closed). Length limits are bytes, keeping
	// the in-memory representation bounded without rune decoding.
	adblockExceptionsMaxBytes   = 256 * 1024
	adblockExceptionsMaxEntries = 1024
	adblockExceptionsMaxIDLen   = 64
	adblockExceptionsMaxReason  = 256
)

// Bounded reload error classes for logs and status. Raw file content, paths
// and decoder errors are never logged or exposed.
const (
	adblockExcErrMissing        = "missing"
	adblockExcErrOversize       = "oversize"
	adblockExcErrTooManyEntries = "too_many_entries"
	adblockExcErrInvalidJSON    = "invalid_json"
	adblockExcErrInvalidVersion = "invalid_version"
	adblockExcErrInvalidEntry   = "invalid_entry"
)

// adblockException is one validated exception entry. Category "" means the
// entry does not constrain the rule category (wildcard). Reason is the
// trimmed operator note: it feeds the revision/audit identity only and is
// never exposed in decisions, status, metrics or logs.
type adblockException struct {
	ID          string
	Domain      string // normalized queried-domain selector
	Scope       domaintrie.RuleScope
	MatchedRule string // normalized rule domain, must equal Rule.Domain
	SourceID    string // canonical source ID, must equal Rule.SourceID
	MatchType   domaintrie.RuleScope
	Category    string // "" = wildcard
	Reason      string // trimmed, bytes-bounded
}

// adblockExceptionKey is the composite rule-provenance index inside one
// queried-domain bucket. Category "" addresses the wildcard class; any other
// value addresses the category-specific class.
type adblockExceptionKey struct {
	MatchedRule string
	SourceID    string
	MatchType   domaintrie.RuleScope
	Category    string
}

// adblockExceptionBucket holds one queried-domain selector's entries split by
// specificity class, so each bucket resolves with at most two map lookups
// regardless of entry count. Buckets are never mutated after publication.
type adblockExceptionBucket struct {
	specific map[adblockExceptionKey]string // full provenance -> exception ID
	wildcard map[adblockExceptionKey]string // provenance with Category "" -> exception ID
}

// adblockExceptionSnapshot is the immutable published exception set. Maps are
// never mutated after publication; readers only need an atomic Load.
type adblockExceptionSnapshot struct {
	revision string
	count    int
	exact    map[string]adblockExceptionBucket
	suffix   map[string]adblockExceptionBucket
}

func newEmptyAdblockExceptionSnapshot() *adblockExceptionSnapshot {
	return &adblockExceptionSnapshot{
		exact:  make(map[string]adblockExceptionBucket),
		suffix: make(map[string]adblockExceptionBucket),
	}
}

// revisionDomainSeparator prefixes the canonical revision encoding so the
// digest domain-separates this schema from any other hash use.
const revisionDomainSeparator = "safe-zone/adblock-exceptions/revision/v1"

// writeFramedString appends a fixed-width big-endian byte length followed by
// the raw bytes. Length-prefix framing keeps embedded NUL bytes, newlines or
// separator-like content inside fields (notably reason) unambiguous, unlike
// delimiter-joined concatenation.
func writeFramedString(h hash.Hash, s string) {
	var prefix [8]byte
	binary.BigEndian.PutUint64(prefix[:], uint64(len(s)))
	h.Write(prefix[:])
	h.Write([]byte(s))
}

func writeFramedUint64(h hash.Hash, v uint64) {
	var prefix [8]byte
	binary.BigEndian.PutUint64(prefix[:], v)
	h.Write(prefix[:])
}

// AdblockExceptionStatus aggregates content-exception state for status
// endpoints. It carries counts, a snapshot digest and bounded error classes
// only — never raw domains, source IDs, rule names or exception IDs.
type AdblockExceptionStatus struct {
	Configured      bool   `json:"configured"`
	Count           int    `json:"count"`
	Revision        string `json:"revision,omitempty"`
	LastReloadAt    string `json:"last_reload_at,omitempty"`
	LastReloadOK    bool   `json:"last_reload_ok"`
	LastErrorClass  string `json:"last_error_class,omitempty"`
	ReloadSuccesses uint64 `json:"reload_successes"`
	ReloadFailures  uint64 `json:"reload_failures"`
	Matches         uint64 `json:"matches"`
}

// rawAdblockExceptions is the v1 file schema. Unknown fields are rejected by
// the decoder; there is no action/enabled/expiry in PR3A.
type rawAdblockExceptions struct {
	Version    int `json:"version"`
	Exceptions []struct {
		ID          string `json:"id"`
		Domain      string `json:"domain"`
		Scope       string `json:"scope"`
		MatchedRule string `json:"matched_rule"`
		SourceID    string `json:"source_id"`
		MatchType   string `json:"match_type"`
		Category    string `json:"category"`
		Reason      string `json:"reason"`
	} `json:"exceptions"`
}

// normalizeExceptionDomain lowercases, punycodes and validates a hostname used
// either as a queried-domain selector or as a matched_rule value. It rejects
// URLs, ports, wildcards, empty labels and invalid hostnames instead of
// silently normalizing them into something broader.
func normalizeExceptionDomain(raw string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return "", errors.New("domain is empty")
	}
	if strings.Contains(trimmed, "://") || strings.ContainsAny(trimmed, "/?#@:") ||
		strings.Contains(trimmed, "*") || strings.ContainsAny(trimmed, " \t\n\r") {
		return "", fmt.Errorf("domain %q is not a bare hostname", raw)
	}
	ascii, err := idna.Lookup.ToASCII(trimmed)
	if err != nil {
		return "", fmt.Errorf("domain %q is not valid", raw)
	}
	ascii = strings.TrimSpace(ascii)
	if ascii == "" || len(ascii) > 253 {
		return "", fmt.Errorf("domain %q is not valid", raw)
	}
	labels := strings.Split(ascii, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return "", fmt.Errorf("domain %q has an empty or oversized label", raw)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			lower := c >= 'a' && c <= 'z'
			digit := c >= '0' && c <= '9'
			if !lower && !digit && c != '-' {
				return "", fmt.Errorf("domain %q has invalid characters", raw)
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("domain %q has a malformed label", raw)
		}
	}
	return ascii, nil
}

// selectorsIntersect reports whether a queried-domain selector and a
// matched_rule value can ever cover a common queried domain, compared on DNS
// label boundaries. Suffix matches never cross a label boundary, so
// "evil-example.com" never intersects "example.com".
func selectorsIntersect(queryDomain string, queryScope domaintrie.RuleScope, ruleDomain string, ruleScope domaintrie.RuleScope) bool {
	if queryDomain == ruleDomain {
		return true
	}
	isSub := func(child, parent string) bool {
		return strings.HasSuffix(child, "."+parent)
	}
	switch {
	case queryScope == domaintrie.RuleScopeExact && ruleScope == domaintrie.RuleScopeExact:
		return false
	case queryScope == domaintrie.RuleScopeExact:
		return isSub(queryDomain, ruleDomain)
	case ruleScope == domaintrie.RuleScopeExact:
		return isSub(ruleDomain, queryDomain)
	default:
		return isSub(queryDomain, ruleDomain) || isSub(ruleDomain, queryDomain)
	}
}

func isValidExceptionID(id string) bool {
	if len(id) == 0 || len(id) > adblockExceptionsMaxIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}

// canonicalExceptionSourceID validates a configured source ID and returns
// its canonical form: the reserved "legacy"/"legacy-cache" labels match
// exactly (never case-folded), while a 32-character hex digest is lowercased
// to the form canonicalSourceID produces for real Rule.SourceID values. An
// uppercase digest therefore loads and matches instead of silently never
// matching.
func canonicalExceptionSourceID(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == domaintrie.LegacyRuleSourceID || trimmed == domaintrie.CacheV2LegacySourceID {
		return trimmed, nil
	}
	if len(trimmed) != 32 {
		return "", fmt.Errorf("source_id %q is not a 32-character hex digest", raw)
	}
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' {
			continue
		}
		return "", fmt.Errorf("source_id %q is not hex", raw)
	}
	return strings.ToLower(trimmed), nil
}

// validateAdblockExceptions decodes, normalizes and validates a config body,
// returning the entries in file order. Any failure rejects the whole file;
// nothing is defaulted to a broader scope or category.
func validateAdblockExceptions(body []byte) ([]adblockException, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var raw rawAdblockExceptions
	if err := dec.Decode(&raw); err != nil {
		return nil, errors.New(adblockExcErrInvalidJSON)
	}
	// Strict trailing-content check: only io.EOF is accepted after the
	// top-level object, so a second value, a stray delimiter or any other
	// garbage fails closed. Decoder.More is not used here: it reports on
	// array/object iteration and can miss a malformed trailing delimiter
	// such as ] or } at the top level. Trailing whitespace stays valid.
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, errors.New(adblockExcErrInvalidJSON)
	}
	if raw.Version != 1 {
		return nil, errors.New(adblockExcErrInvalidVersion)
	}
	if len(raw.Exceptions) > adblockExceptionsMaxEntries {
		return nil, errors.New(adblockExcErrTooManyEntries)
	}
	entries := make([]adblockException, 0, len(raw.Exceptions))
	seenIDs := make(map[string]struct{}, len(raw.Exceptions))
	seenSelectors := make(map[string]struct{}, len(raw.Exceptions))
	for i := range raw.Exceptions {
		re := raw.Exceptions[i]
		if !isValidExceptionID(re.ID) {
			return nil, fmt.Errorf("%s: entry %d has an invalid id", adblockExcErrInvalidEntry, i)
		}
		if _, dup := seenIDs[re.ID]; dup {
			return nil, fmt.Errorf("%s: duplicate id", adblockExcErrInvalidEntry)
		}
		seenIDs[re.ID] = struct{}{}
		reason := strings.TrimSpace(re.Reason)
		if reason == "" || len(reason) > adblockExceptionsMaxReason {
			return nil, fmt.Errorf("%s: entry %d has an invalid reason", adblockExcErrInvalidEntry, i)
		}
		domain, err := normalizeExceptionDomain(re.Domain)
		if err != nil {
			return nil, fmt.Errorf("%s: entry %d: %v", adblockExcErrInvalidEntry, i, err)
		}
		matchedRule, err := normalizeExceptionDomain(re.MatchedRule)
		if err != nil {
			return nil, fmt.Errorf("%s: entry %d: %v", adblockExcErrInvalidEntry, i, err)
		}
		scope := domaintrie.RuleScope(strings.ToLower(strings.TrimSpace(re.Scope)))
		if scope != domaintrie.RuleScopeExact && scope != domaintrie.RuleScopeSuffix {
			return nil, fmt.Errorf("%s: entry %d has an unknown scope", adblockExcErrInvalidEntry, i)
		}
		matchType := domaintrie.RuleScope(strings.ToLower(strings.TrimSpace(re.MatchType)))
		if matchType != domaintrie.RuleScopeExact && matchType != domaintrie.RuleScopeSuffix {
			return nil, fmt.Errorf("%s: entry %d has an unknown match_type", adblockExcErrInvalidEntry, i)
		}
		sourceID, err := canonicalExceptionSourceID(re.SourceID)
		if err != nil {
			return nil, fmt.Errorf("%s: entry %d has an invalid source_id", adblockExcErrInvalidEntry, i)
		}
		category := ""
		if trimmed := strings.ToLower(strings.TrimSpace(re.Category)); trimmed != "" {
			if !domaintrie.IsValidRuleCategory(trimmed) {
				return nil, fmt.Errorf("%s: entry %d has an unknown category", adblockExcErrInvalidEntry, i)
			}
			category = trimmed
		}
		if scope == domaintrie.RuleScopeSuffix {
			if _, err := publicsuffix.EffectiveTLDPlusOne(domain); err != nil {
				return nil, fmt.Errorf("%s: entry %d selector is a public suffix", adblockExcErrInvalidEntry, i)
			}
		}
		if !selectorsIntersect(domain, scope, matchedRule, matchType) {
			return nil, fmt.Errorf("%s: entry %d selector can never meet its rule", adblockExcErrInvalidEntry, i)
		}
		selectorKey := domain + "\x00" + string(scope) + "\x00" + matchedRule + "\x00" +
			sourceID + "\x00" + string(matchType) + "\x00" + category
		if _, dup := seenSelectors[selectorKey]; dup {
			return nil, fmt.Errorf("%s: entry %d duplicates a selector", adblockExcErrInvalidEntry, i)
		}
		seenSelectors[selectorKey] = struct{}{}
		entries = append(entries, adblockException{
			ID:          re.ID,
			Domain:      domain,
			Scope:       scope,
			MatchedRule: matchedRule,
			SourceID:    sourceID,
			MatchType:   matchType,
			Category:    category,
			Reason:      reason,
		})
	}
	return entries, nil
}

// buildAdblockExceptionSnapshot indexes validated entries into an immutable
// snapshot and digests the canonical form. The digest covers every semantic
// selector plus the trimmed operator reason, so a reason-only edit changes
// the revision; raw file bytes never participate. A valid empty snapshot
// goes through the same encoder with entry count 0, so its digest stays
// non-empty and distinguishable from the feature-disabled state, which keeps
// an empty revision.
func buildAdblockExceptionSnapshot(entries []adblockException) *adblockExceptionSnapshot {
	snap := &adblockExceptionSnapshot{
		count:  len(entries),
		exact:  make(map[string]adblockExceptionBucket, len(entries)),
		suffix: make(map[string]adblockExceptionBucket, len(entries)),
	}
	for _, e := range entries {
		bucket := adblockExceptionBucket{}
		if e.Scope == domaintrie.RuleScopeExact {
			bucket = snap.exact[e.Domain]
		} else {
			bucket = snap.suffix[e.Domain]
		}
		key := adblockExceptionKey{
			MatchedRule: e.MatchedRule,
			SourceID:    e.SourceID,
			MatchType:   e.MatchType,
			Category:    e.Category,
		}
		if e.Category == "" {
			if bucket.wildcard == nil {
				bucket.wildcard = make(map[adblockExceptionKey]string)
			}
			bucket.wildcard[key] = e.ID
		} else {
			if bucket.specific == nil {
				bucket.specific = make(map[adblockExceptionKey]string)
			}
			bucket.specific[key] = e.ID
		}
		if e.Scope == domaintrie.RuleScopeExact {
			snap.exact[e.Domain] = bucket
		} else {
			snap.suffix[e.Domain] = bucket
		}
	}
	snap.revision = hashAdblockExceptionRevision(entries)
	return snap
}

// hashAdblockExceptionRevision digests the canonical snapshot encoding:
// domain-separation prefix, entry count, then per-entry length-prefixed
// fields over entries sorted by canonical tuple. Length-prefix framing makes
// the encoding unambiguous even when fields embed NUL bytes, newlines or
// separator-like content.
func hashAdblockExceptionRevision(entries []adblockException) string {
	ordered := make([]adblockException, len(entries))
	copy(ordered, entries)
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.Domain != b.Domain {
			return a.Domain < b.Domain
		}
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		if a.MatchedRule != b.MatchedRule {
			return a.MatchedRule < b.MatchedRule
		}
		if a.SourceID != b.SourceID {
			return a.SourceID < b.SourceID
		}
		if a.MatchType != b.MatchType {
			return a.MatchType < b.MatchType
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return a.Reason < b.Reason
	})
	h := sha256.New()
	writeFramedString(h, revisionDomainSeparator)
	writeFramedUint64(h, uint64(len(ordered)))
	for _, e := range ordered {
		writeFramedString(h, e.ID)
		writeFramedString(h, e.Domain)
		writeFramedString(h, string(e.Scope))
		writeFramedString(h, e.MatchedRule)
		writeFramedString(h, e.SourceID)
		writeFramedString(h, string(e.MatchType))
		writeFramedString(h, e.Category)
		writeFramedString(h, e.Reason)
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

// matchBucket resolves one queried-domain bucket with at most two map
// lookups: the rule's full provenance first, then the category wildcard.
// Validation rejects duplicate selectors, so each lookup is unambiguous and
// the result never depends on JSON order.
func matchBucket(bucket adblockExceptionBucket, rule *domaintrie.Rule) (string, bool) {
	key := adblockExceptionKey{
		MatchedRule: rule.Domain,
		SourceID:    rule.SourceID,
		MatchType:   rule.Scope,
		Category:    rule.Category,
	}
	if id, ok := bucket.specific[key]; ok {
		return id, true
	}
	key.Category = ""
	if id, ok := bucket.wildcard[key]; ok {
		return id, true
	}
	return "", false
}

// match looks up an exception for an already-normalized queried domain and a
// fired rule. Exact queried-domain candidates come first, then suffix at the
// query itself and each parent from deep to shallow. Matching is O(labels of
// the queried domain) outer lookups with O(1) work inside each bucket. It
// performs map lookups only: no I/O, no logging, no metric labels.
func (s *adblockExceptionSnapshot) match(query string, rule *domaintrie.Rule) (string, bool) {
	if s == nil || s.count == 0 || rule == nil {
		return "", false
	}
	if bucket, ok := s.exact[query]; ok {
		if id, ok := matchBucket(bucket, rule); ok {
			return id, true
		}
	}
	// Suffix walk at label boundaries: the query itself, then each parent.
	for candidate := query; ; {
		if bucket, ok := s.suffix[candidate]; ok {
			if id, ok := matchBucket(bucket, rule); ok {
				return id, true
			}
		}
		dot := strings.IndexByte(candidate, '.')
		if dot < 0 {
			break
		}
		candidate = candidate[dot+1:]
	}
	return "", false
}

// normalizeExceptionQuery normalizes an already lowercased queried domain the
// same way selectors are stored. Pure-ASCII queries (the common case) return
// without a second canonicalization or allocation.
func normalizeExceptionQuery(query string) (string, bool) {
	ascii := true
	for i := 0; i < len(query); i++ {
		if query[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return query, query != ""
	}
	converted, err := idna.Lookup.ToASCII(query)
	if err != nil || converted == "" {
		return "", false
	}
	return converted, true
}

// loadAdblockExceptionFile reads, bounds, parses and validates the exception
// config inside the feed file root. It returns the snapshot or a bounded
// error class; raw content and decoder errors never leave this function.
func loadAdblockExceptionFile(root, path string) (*adblockExceptionSnapshot, string) {
	file, err := safefile.OpenWithin(root, path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, adblockExcErrMissing
		}
		// Path escapes the root or the sandbox cannot open: fail closed with
		// a bounded class rather than leaking path details.
		return nil, adblockExcErrMissing
	}
	defer func() { _ = file.Close() }()

	body, err := io.ReadAll(io.LimitReader(file, adblockExceptionsMaxBytes+1))
	if err != nil {
		return nil, adblockExcErrInvalidEntry
	}
	if len(body) > adblockExceptionsMaxBytes {
		return nil, adblockExcErrOversize
	}
	entries, err := validateAdblockExceptions(body)
	if err != nil {
		msg := err.Error()
		for _, class := range []string{
			adblockExcErrInvalidJSON, adblockExcErrInvalidVersion, adblockExcErrTooManyEntries,
		} {
			if msg == class {
				return nil, class
			}
		}
		return nil, adblockExcErrInvalidEntry
	}
	return buildAdblockExceptionSnapshot(entries), ""
}

// reloadAdblockExceptions reloads the exception file into a new immutable
// snapshot and publishes it atomically. Invalid, missing or oversized configs
// keep the previous valid snapshot; a valid empty file publishes an empty
// set. Reload writers are serialized internally.
func (s *Service) reloadAdblockExceptions() {
	if s == nil {
		return
	}
	s.adblockExcMu.Lock()
	defer s.adblockExcMu.Unlock()
	if !s.adblockExceptionsPinned {
		s.adblockExceptionsFile = strings.TrimSpace(config.String(envAdblockExceptionsFile, ""))
	}
	path := s.adblockExceptionsFile
	if path == "" {
		if s.adblockExceptionsConfigured.Load() {
			s.adblockExceptions.Store(newEmptyAdblockExceptionSnapshot())
			s.adblockExceptionsConfigured.Store(false)
		}
		return
	}
	// A set path means configured, even when the content fails to load.
	s.adblockExceptionsConfigured.Store(true)
	previous := s.adblockExceptions.Load()
	previousRevision := ""
	if previous != nil {
		previousRevision = previous.revision
	}
	snapshot, errorClass := loadAdblockExceptionFile(s.adblockDataRoot, path)
	now := time.Now()
	if errorClass != "" {
		s.adblockExcLastReload.Store(now)
		s.adblockExcLastOK.Store(false)
		s.adblockExcLastErr.Store(errorClass)
		s.adblockExcReloadFailures.Add(1)
		count := 0
		if previous != nil {
			count = previous.count
		}
		logjson.Warn("adblock exceptions reload failed; keeping previous snapshot", map[string]any{
			"service":     "risk",
			"error_class": errorClass,
			"revision":    previousRevision,
			"count":       count,
		})
		return
	}
	s.adblockExceptions.Store(snapshot)
	s.adblockExcLastReload.Store(now)
	s.adblockExcLastOK.Store(true)
	s.adblockExcLastErr.Store("")
	s.adblockExcReloadSuccesses.Add(1)
	if snapshot.revision != previousRevision {
		logjson.Info("adblock exceptions reloaded", map[string]any{
			"service":  "risk",
			"revision": snapshot.revision,
			"count":    snapshot.count,
		})
	}
}

// matchAdblockException reports the exception ID suppressing a fired adblock
// rule for a queried domain. Request path: one atomic Load plus RAM map
// lookups only — never file, Redis, SQLite or HTTP.
func (s *Service) matchAdblockException(query string, rule *domaintrie.Rule) (string, bool) {
	if s == nil || rule == nil {
		return "", false
	}
	snapshot := s.adblockExceptions.Load()
	if snapshot == nil || snapshot.count == 0 {
		return "", false
	}
	normalized, ok := normalizeExceptionQuery(query)
	if !ok {
		return "", false
	}
	return snapshot.match(normalized, rule)
}

// AdblockExceptionStatus returns the aggregate content-exception snapshot for
// status endpoints: counts, digest revision and bounded error classes only.
func (s *Service) AdblockExceptionStatus() AdblockExceptionStatus {
	status := AdblockExceptionStatus{
		Configured:      s.adblockExceptionsConfigured.Load(),
		LastReloadOK:    s.adblockExcLastOK.Load(),
		ReloadSuccesses: s.adblockExcReloadSuccesses.Load(),
		ReloadFailures:  s.adblockExcReloadFailures.Load(),
		Matches:         s.adblockExcMatches.Load(),
	}
	if snapshot := s.adblockExceptions.Load(); snapshot != nil {
		status.Count = snapshot.count
		status.Revision = snapshot.revision
	}
	if v := s.adblockExcLastReload.Load(); v != nil {
		if ts, ok := v.(time.Time); ok && !ts.IsZero() {
			status.LastReloadAt = ts.UTC().Format(time.RFC3339)
		}
	}
	if v := s.adblockExcLastErr.Load(); v != nil {
		if class, ok := v.(string); ok {
			status.LastErrorClass = class
		}
	}
	return status
}
