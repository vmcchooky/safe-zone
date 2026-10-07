package risk

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"safe-zone/internal/domaintrie"
	"safe-zone/internal/logjson"
)

type adblockSourceMeta struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

func splitAdblockSources(sources string) []string {
	parts := strings.Split(sources, ",")
	result := make([]string, 0, len(parts))
	for _, source := range parts {
		source = strings.TrimSpace(source)
		if source != "" {
			result = append(result, source)
		}
	}
	return result
}

func (e *AdblockEngine) adblockMetaPath() string {
	return filepath.Join(e.adblockDataRoot, "adblock_meta.json")
}

func (e *AdblockEngine) adblockCachePath() string {
	return filepath.Join(e.adblockDataRoot, "adblock_cache.txt")
}

func (e *AdblockEngine) adblockSourceCacheRoot() string {
	return filepath.Join(e.adblockDataRoot, "adblock_sources")
}

// adblockSourceCachePath derives the on-disk location of a source's download
// cache. Keyed by the canonical source key so it matches canonicalSourceID,
// which stamps the same identity into rule provenance: hashing the raw string
// here while provenance used the canonical form gave one source two
// identities, and two cache files for a case change that meant the same source.
func (e *AdblockEngine) adblockSourceCachePath(source string) string {
	sum := sha256.Sum256([]byte(canonicalSourceKey(strings.TrimSpace(source))))
	return filepath.Join(e.adblockSourceCacheRoot(), fmt.Sprintf("%x.txt", sum[:]))
}

func (e *AdblockEngine) ensureAdblockDataRoot() error {
	if strings.TrimSpace(e.adblockDataRoot) == "" {
		return nil
	}
	return os.MkdirAll(e.adblockDataRoot, 0o750)
}

func (e *AdblockEngine) ensureAdblockSourceCacheRoot() error {
	if err := e.ensureAdblockDataRoot(); err != nil {
		return err
	}
	return os.MkdirAll(e.adblockSourceCacheRoot(), 0o750)
}

func replaceFile(tmpPath, finalPath string) error {
	lock, _ := replaceFileLocks.LoadOrStore(finalPath, &sync.Mutex{})
	mu := lock.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	if err := os.Remove(finalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(tmpPath, finalPath)
}

func createReplaceTempFile(finalPath string) (*os.File, string, error) {
	dir := filepath.Dir(finalPath)
	pattern := filepath.Base(finalPath) + ".tmp-*"
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, "", err
	}
	return f, f.Name(), nil
}

func isRemoteAdblockSource(source string) bool {
	return strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://")
}

func loadAdblockMeta(metaPath string) map[string]adblockSourceMeta {
	meta := make(map[string]adblockSourceMeta)
	// #nosec G304 -- metaPath is constructed safely internally
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		return meta
	}
	_ = json.Unmarshal(metaData, &meta)
	return meta
}

func adblockSourceMetaFromHeader(header http.Header) adblockSourceMeta {
	if header == nil {
		return adblockSourceMeta{}
	}
	return adblockSourceMeta{
		ETag:         header.Get("ETag"),
		LastModified: header.Get("Last-Modified"),
	}
}

func (e *AdblockEngine) saveAdblockMeta(metaPath string, meta map[string]adblockSourceMeta) {
	metaData, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return
	}
	if err := e.ensureAdblockDataRoot(); err != nil {
		logjson.Warn("failed to create adblock data root", map[string]any{"error": err.Error()})
		return
	}
	f, tmpMeta, err := createReplaceTempFile(metaPath)
	if err != nil {
		return
	}
	if _, err := f.Write(metaData); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpMeta)
		return
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpMeta)
		return
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpMeta)
		return
	}
	if err := replaceFile(tmpMeta, metaPath); err != nil {
		logjson.Warn("failed to rename adblock meta temp file", map[string]any{"error": err.Error()})
		_ = os.Remove(tmpMeta)
	}
}

// parseAdblockSourceInto decodes one feed stream into the provided staging
// trie without touching any global destination. It returns the Scanner/I/O
// error (if any) so callers can decide whether the staging state is committable.
// The stream itself is never buffered as []Rule/[]byte; only parsed rules
// accumulate in the staging trie.
// adblockSectionCategories maps merged-list section names (the "# Start
// <name>" markers of composite hosts files such as StevenBlack's unified
// list) to closed-vocab content categories. Every mapping is evidenced by
// the section's own documented purpose, quoted below. Sections without an
// unambiguous documented purpose keep the source-level category (unknown
// by default): the parser never infers from entry text, so a reorganized
// upstream degrades to today's behavior instead of mislabeling.
var adblockSectionCategories = map[string]string{
	// "Blocking mobile ad providers and some analytics providers"
	"adaway.org": "tracking",
	// "Only include advertisers in Vietnam"
	"hostsVN": "ads",
	// "minecraft-hosts - Tracking Domains"
	"minecraft-hosts": "tracking",
}

func parseAdblockSectionMarker(raw string) (name string, end bool) {
	line := strings.TrimSpace(raw)
	if !strings.HasPrefix(line, "#") {
		return "", false
	}
	fields := strings.Fields(strings.TrimSpace(line[1:]))
	if len(fields) == 0 {
		return "", false
	}
	switch fields[0] {
	case "Start":
		// Single-token names only: "# Start your engines" prose must
		// never flip section state.
		if len(fields) == 2 {
			return fields[1], false
		}
		return "", false
	case "End":
		return "", true
	default:
		return "", false
	}
}

func (e *AdblockEngine) parseAdblockSourceInto(reader io.Reader, staging *domaintrie.Trie, sourceID string, category string, scope domaintrie.RuleScope, origin domaintrie.ScopeOrigin) error {
	if staging == nil {
		return errors.New("adblock staging trie is nil")
	}
	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)
	section := ""
	for scanner.Scan() {
		raw := scanner.Text()
		if name, end := parseAdblockSectionMarker(raw); name != "" || end {
			if end {
				section = ""
			} else {
				section = name
			}
			continue
		}
		ruleCategory := category
		if section != "" {
			if mapped, ok := adblockSectionCategories[section]; ok {
				ruleCategory = mapped
			}
		}
		line := strings.TrimSpace(raw)
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		startIdx := 0
		if ip := net.ParseIP(parts[0]); ip != nil {
			startIdx = 1
		}

		for _, domain := range parts[startIdx:] {
			domain = strings.ToLower(domain)
			if domain != "" && domain != "localhost" && domain != "local" && domain != "broadcasthost" {
				staging.AddRule(domaintrie.Rule{
					Domain:   domain,
					Scope:    scope,
					SourceID: sourceID,
					Category: ruleCategory,
					Action:   domaintrie.RuleActionBlock,
					Origin:   origin,
				})
			}
		}
	}
	return scanner.Err()
}

// parseAdblockSource parses one feed stream with source-level atomicity: the
// stream is decoded into a staging trie and merged into trie only after the
// whole source scans without a Scanner/I/O error, so a source that fails
// partway contributes zero rules. Merging in SAFE_ZONE_ADBLOCK_SOURCES order
// preserves first-wins per (domain, scope). Remote fetches must not use this
// helper directly: saveAdblockSourceCache parses into staging and merges only
// after the cache commit (Close, Sync, replace) succeeds.
func (e *AdblockEngine) parseAdblockSource(reader io.Reader, trie *domaintrie.Trie, sourceID string, category string, scope domaintrie.RuleScope, origin domaintrie.ScopeOrigin) error {
	if trie == nil {
		return errors.New("adblock destination trie is nil")
	}
	staging := domaintrie.NewTrie()
	if err := e.parseAdblockSourceInto(reader, staging, sourceID, category, scope, origin); err != nil {
		return err
	}
	trie.MergeFrom(staging)
	return nil
}

// parseAdblockCache loads the global cache with whole-load atomicity: records
// decode into a staging trie and merge only when the Scanner reaches EOF
// without an I/O/token-too-long error. A Scanner error fails the entire load
// (false, destination untouched) so a partially read cache is never
// published. Individual malformed v2 records are still skipped by design.
// Legacy v1 domain-only content is lossy (exact/suffix provenance is dropped
// on write) and reloads as suffix/unknown/block for degraded-mode continuity,
// never as a lossless typed restore.
func (e *AdblockEngine) parseAdblockCache(reader io.Reader, trie *domaintrie.Trie) bool {
	if trie == nil {
		return false
	}
	staging := domaintrie.NewTrie()
	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	firstLine := true
	v2 := false
	malformed := 0
	total := 0
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if firstLine {
			firstLine = false
			if strings.HasPrefix(line, domaintrie.CacheV2Header) {
				v2 = true
				continue
			}
			// Legacy v1 cache: the first line is already a domain.
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if v2 {
			total++
			rule, ok := domaintrie.ParseCacheV2Line(line)
			if !ok {
				malformed++
				continue
			}
			staging.AddRule(rule)
			continue
		}
		// Legacy degraded-mode semantics: domains-only cache reloads as
		// suffix/unknown/block rules from a synthetic provenance label, so a
		// degraded network sync never silently changes match behavior to the
		// configured exact default.
		total++
		staging.AddRule(domaintrie.Rule{
			Domain:   strings.TrimSpace(line),
			Scope:    domaintrie.RuleScopeSuffix,
			SourceID: domaintrie.CacheV2LegacySourceID,
			Category: domaintrie.DefaultRuleCategory,
			Action:   domaintrie.RuleActionBlock,
			Origin:   domaintrie.OriginLegacyCache,
		})
	}
	if err := scanner.Err(); err != nil {
		logjson.Warn("error reading adblock cache file", map[string]any{"error": err.Error()})
		return false
	}
	if malformed > 0 {
		logjson.Warn("skipped malformed adblock cache records", map[string]any{
			"records":   total,
			"malformed": malformed,
		})
	}
	if staging.Count() == 0 {
		return false
	}
	trie.MergeFrom(staging)
	return true
}

// saveAdblockSourceCache persists one remote source body to its per-source
// cache file and merges its rules into trie only after parse, Close, Sync and
// replace all succeed. A cache persistence failure therefore contributes
// exactly zero rules; the sync loop's fallback to the old cache file then
// merges only old data, never a mix of uncommitted refresh plus old cache.
func (e *AdblockEngine) saveAdblockSourceCache(source string, reader io.Reader, trie *domaintrie.Trie, sourceID string, category string, scope domaintrie.RuleScope, origin domaintrie.ScopeOrigin) error {
	if trie == nil {
		return errors.New("adblock destination trie is nil")
	}
	if err := e.ensureAdblockSourceCacheRoot(); err != nil {
		return err
	}
	finalPath := e.adblockSourceCachePath(source)
	f, tmpPath, err := createReplaceTempFile(finalPath)
	if err != nil {
		return err
	}

	staging := domaintrie.NewTrie()
	tee := io.TeeReader(reader, f)
	parseErr := e.parseAdblockSourceInto(tee, staging, sourceID, category, scope, origin)
	closeErr := f.Close()
	if parseErr != nil {
		_ = os.Remove(tmpPath)
		return parseErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return closeErr
	}
	if err := commitAdblockSourceCache(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	trie.MergeFrom(staging)
	return nil
}

// commitAdblockSourceCache fsyncs the staged per-source cache temp file and
// publishes it at the final cache path via replaceFile. replaceFile is a
// remove-then-rename sequence serialized in-process per path, not a
// crash-atomic rename: a crash between remove and rename can leave the final
// path momentarily absent. Concurrent readers therefore observe either the
// old file or an error, never a torn write, since the temp file is fully
// synced before the swap.
func commitAdblockSourceCache(tmpPath, finalPath string) error {
	if err := syncPath(tmpPath); err != nil {
		return err
	}
	return replaceFile(tmpPath, finalPath)
}

func syncPath(path string) error {
	// #nosec G304 -- path is constructed safely internally
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}

func (e *AdblockEngine) loadAdblockSourceCache(source string, trie *domaintrie.Trie, sourceID string, category string, scope domaintrie.RuleScope, origin domaintrie.ScopeOrigin) bool {
	f, err := os.Open(e.adblockSourceCachePath(source))
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	if err := e.parseAdblockSource(f, trie, sourceID, category, scope, origin); err != nil {
		logjson.Warn("error reading adblock source cache", map[string]any{"source": source, "error": err.Error()})
		return false
	}
	return true
}
