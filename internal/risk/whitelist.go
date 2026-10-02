package risk

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
	"safe-zone/internal/logjson"
	"safe-zone/internal/safefile"
	"safe-zone/internal/store"
)

// whitelistFPR is the Bloom filter's target false positive rate. With an exact
// index behind it, a false positive costs a binary search rather than a
// database read, so the rate is no longer a hot-path concern.
const whitelistFPR = 0.01

// Whitelist reports whether a domain is on the allow list.
//
// The index lives entirely in RAM: a Bloom filter for the negative fast path and
// a sorted, deduplicated slice for an exact answer. Lookups therefore never
// touch the database, which is the point.
//
// It used to verify a Bloom hit against SQLite on every request. That put the
// single database connection on the DNS hot path: a measured 400k-row reload
// held it for seconds, and a lookup that waited on it consumed the caller's
// whole DoT budget, after which the whitelisted domain answered "not
// whitelisted" and went through the rest of the pipeline where any layer can
// block it. Keeping the exact set in RAM removes that failure mode rather than
// bounding it.
//
// The cost is memory: roughly 50 bytes per entry for the sorted slice plus the
// filter, so about 52 MiB for a million domains. SQLite remains the durable
// copy that LoadFromDB rebuilds the index from; it is no longer on the request
// path.
type Whitelist struct {
	mu    sync.RWMutex
	bloom *BloomFilter
	db    *store.DB
	// exact holds every whitelisted domain, sorted and deduplicated, and is
	// replaced wholesale on load. Reading it after the lock is released is safe
	// because nothing mutates a published slice.
	exact []string
}

// NewWhitelist creates an empty Whitelist.
func NewWhitelist(db *store.DB) *Whitelist {
	return &Whitelist{db: db}
}

// buildIndex assembles the RAM lookup structures from a domain set: a Bloom
// filter for negatives and a sorted, deduplicated slice for exact answers.
// Duplicates are compacted here rather than relied on upstream, because a file
// import can repeat a line and the slice is what the memory cost is paid on.
func buildIndex(domains []string) (*BloomFilter, []string) {
	exact := append([]string(nil), domains...)
	sort.Strings(exact)

	kept := exact[:0]
	for i, domain := range exact {
		if i > 0 && domain == exact[i-1] {
			continue
		}
		kept = append(kept, domain)
	}
	exact = kept

	var bf *BloomFilter
	if len(exact) > 0 {
		bf = NewBloomFilter(len(exact), whitelistFPR)
		for _, domain := range exact {
			bf.Add(domain)
		}
	}
	return bf, exact
}

func (w *Whitelist) publish(bf *BloomFilter, exact []string) {
	w.mu.Lock()
	w.bloom = bf
	w.exact = exact
	w.mu.Unlock()
}

// LoadFromDB streams the SQLite whitelist and rebuilds the RAM index.
func (w *Whitelist) LoadFromDB() error {
	if w == nil || w.db == nil || !w.db.Enabled() {
		return nil
	}

	count, err := w.db.GetWhitelistCount(context.Background())
	if err != nil {
		return fmt.Errorf("count whitelist from db: %w", err)
	}

	if count == 0 {
		// Refuse to replace a populated index with an empty one. The poison
		// floor in store.UpdateWhitelist already rejects the two ways this
		// state is reachable today, so this is the last line of defence — but
		// the consequence of it firing is that every whitelisted domain starts
		// being scored and can be blocked, with nothing to indicate why. An
		// empty table on a genuinely empty store is still honoured.
		if w.ExactCount() > 0 {
			logjson.Error("whitelist table is empty but an index is loaded; keeping the previous index", map[string]any{
				"service":     "risk",
				"retained":    w.ExactCount(),
				"consequence": "a whitelisted domain would fall through to the decision pipeline and could be blocked",
			})
			return nil
		}
		w.publish(nil, nil)
		return nil
	}

	domains := make([]string, 0, count)
	if err := w.db.StreamWhitelist(context.Background(), func(domain string) error {
		domains = append(domains, domain)
		return nil
	}); err != nil {
		return fmt.Errorf("stream whitelist from db: %w", err)
	}

	bf, exact := buildIndex(domains)
	w.publish(bf, exact)

	logjson.Info("whitelist index loaded from database", map[string]any{
		"service":   "risk",
		"storage":   "sqlite",
		"strategy":  "bloom+exact",
		"domains":   len(exact),
		"filter_kb": float64(bf.m) / 8.0 / 1024.0,
		"hashes":    bf.k,
	})
	return nil
}

// LoadFromFile parses a whitelist file (such as a Tranco Top 1M CSV).
//
// With a database configured the file is imported there and the RAM index is
// rebuilt from the store, so one code path builds the index either way.
func (w *Whitelist) LoadFromFile(path string) error {
	if path == "" {
		return nil
	}

	file, err := safefile.OpenWithin(config.FeedFileRoot(), path)
	if err != nil {
		if os.IsNotExist(err) {
			logjson.Warn("whitelist file not found; continuing without whitelisting", map[string]any{
				"service": "risk",
				"path":    path,
			})
			return nil
		}
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	var domains []string
	// rejected counts entries that are syntactically valid domains but would
	// be unsafe as whitelist entries. They are dropped rather than failing the
	// whole file, because one bad line in a 1M-row import must not cost the
	// operator every other entry.
	rejected := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Basic CSV support: if comma-separated, grab the second column (typical Tranco/Alexa format)
		parts := strings.Split(line, ",")
		domain := parts[0]
		if len(parts) >= 2 {
			domain = parts[1]
		}

		normalized, err := analysis.NormalizeDomain(domain)
		if err != nil || normalized == "" {
			continue
		}
		if !isWhitelistEntrySafe(normalized) {
			rejected++
			continue
		}
		domains = append(domains, normalized)
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	if rejected > 0 {
		logjson.Warn("dropped unsafe whitelist entries", map[string]any{
			"service":  "risk",
			"path":     path,
			"dropped":  rejected,
			"accepted": len(domains),
			"reason":   "entry is a public suffix (or has no registrable label) and would allowlist every domain beneath it",
		})
	}

	if w.db != nil && w.db.Enabled() {
		if err := w.db.UpdateWhitelist(context.Background(), domains); err != nil {
			return fmt.Errorf("load file to database: %w", err)
		}
		// Rebuilt from the store, so the index reflects what was actually
		// persisted rather than what the file claimed.
		return w.LoadFromDB()
	}

	bf, exact := buildIndex(domains)
	w.publish(bf, exact)

	logjson.Info("whitelist index loaded from file", map[string]any{
		"service":  "risk",
		"storage":  "file",
		"strategy": "bloom+exact",
		"domains":  len(exact),
		"path":     path,
	})
	return nil
}

// isWhitelistEntrySafe reports whether a domain may be stored as a whitelist
// entry. See analysis.IsRegistrableDomain for why a public suffix must never
// be stored; the same rule guards the adblock exception path
// (adblock_exceptions.go) and the admin-override path (store.UpsertOverride),
// so all three behave alike.
func isWhitelistEntrySafe(domain string) bool {
	return analysis.IsRegistrableDomain(domain)
}

// IsAllowed reports whether the domain, or any parent up to its registrable
// label, is whitelisted.
//
// No database access, so there is no query to time out and nothing to queue
// behind: the answer is bounded by a filter probe and a binary search. ctx is
// honoured only to stop early when the caller has already gone away, which
// matters because this runs per DoH request.
func (w *Whitelist) IsAllowed(ctx context.Context, domain string) bool {
	if w == nil {
		return false
	}
	bloom, exact := w.snapshot()

	// Check exact match and parent domains (e.g. if google.com is allowed then
	// mail.google.com is too), stopping at the registrable label so a
	// public-suffix entry can never act as a wildcard.
	parts := strings.Split(domain, ".")
	floor := analysis.RegistrableWalkFloor(domain)
	for i := 0; i < len(parts) && i <= floor; i++ {
		if ctx != nil && ctx.Err() != nil {
			// The caller gave up; nothing here is worth the walk.
			return false
		}
		candidate := strings.Join(parts[i:], ".")
		if candidate == "" {
			continue
		}
		if bloom != nil && !bloom.Test(candidate) {
			// Filter says no. With no filter loaded there is no cheap negative,
			// so the exact index has to answer.
			continue
		}
		if containsDomain(exact, candidate) {
			return true
		}
	}
	return false
}

// containsDomain binary-searches the sorted exact index.
//
// sort.SearchStrings returns the insertion point, not a match: it is >= 0 for
// every input, including every miss. The element at that index has to be
// compared, or the filter says "maybe" and every absent domain matches.
func containsDomain(sorted []string, domain string) bool {
	i := sort.SearchStrings(sorted, domain)
	return i < len(sorted) && sorted[i] == domain
}

// ExactCount reports how many domains the RAM index holds.
func (w *Whitelist) ExactCount() int {
	if w == nil {
		return 0
	}
	_, exact := w.snapshot()
	return len(exact)
}

// ContainsExactIndex reports whether the RAM index holds a domain verbatim.
// Exported so an operator-facing check can assert the index state without
// reaching for the internals, and so the in-package tests can use the same
// predicate IsAllowed uses instead of re-implementing the search.
func (w *Whitelist) ContainsExactIndex(domain string) bool {
	if w == nil {
		return false
	}
	_, exact := w.snapshot()
	return containsDomain(exact, domain)
}

// snapshot copies the in-memory index under the read lock. Both values are
// replaced wholesale on load and never mutated in place, so they are safe to
// read after the lock is released.
func (w *Whitelist) snapshot() (*BloomFilter, []string) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.bloom, w.exact
}

// WhitelistMetrics holds operational index size and RAM usage.
type WhitelistMetrics struct {
	LoadedDomains int     `json:"loaded_domains"`
	BloomBits     uint64  `json:"bloom_bits"`
	BloomHashes   uint64  `json:"bloom_hashes"`
	BloomSizeRAM  float64 `json:"bloom_size_ram_kb"`
	FPR           float64 `json:"fpr"`
	// ExactIndexEntries is the length of the sorted slice behind the filter.
	// This is the number the memory estimate scales with, roughly 50 bytes per
	// entry on top of the filter.
	ExactIndexEntries int `json:"exact_index_entries"`
}

// Metrics queries Whitelist capacity and RAM usage.
//
// Every field comes from the snapshot, not from the live struct: the agent
// handler calls this while the cache-flush handler calls LoadFromDB, and reading
// the live bloom raced that reload and could dereference nil after a reload
// emptied the table.
//
// The store is read for the durable count only, outside the lock. This is an
// operator endpoint, not the DNS hot path, so waiting on the single connection
// here does not affect resolution.
func (w *Whitelist) Metrics() WhitelistMetrics {
	if w == nil {
		return WhitelistMetrics{}
	}
	bloom, exact := w.snapshot()

	loaded := len(exact)
	if w.db != nil && w.db.Enabled() {
		if count, err := w.db.GetWhitelistCount(context.Background()); err == nil {
			loaded = count
		}
	}

	var bits, hashes uint64
	var sizeRAM float64
	if bloom != nil {
		bits = bloom.m
		hashes = bloom.k
		sizeRAM = float64(bits) / 8.0 / 1024.0 // KB
	}

	return WhitelistMetrics{
		LoadedDomains:     loaded,
		BloomBits:         bits,
		BloomHashes:       hashes,
		BloomSizeRAM:      sizeRAM,
		FPR:               whitelistFPR,
		ExactIndexEntries: len(exact),
	}
}
