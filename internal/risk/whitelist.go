package risk

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
	"safe-zone/internal/logjson"
	"safe-zone/internal/safefile"
	"safe-zone/internal/store"
)

// Whitelist checks if domains are in the clean/allowed list.
// Uses a Hybrid Bloom-SQLite architecture when a database is present,
// and falls back to a standard in-memory map otherwise.
type Whitelist struct {
	mu      sync.RWMutex
	bloom   *BloomFilter
	db      *store.DB
	allowed map[string]struct{} // fallback for file-based non-sqlite mode
}

// NewWhitelist creates an empty Whitelist.
func NewWhitelist(db *store.DB) *Whitelist {
	return &Whitelist{
		db:      db,
		allowed: make(map[string]struct{}),
	}
}

// LoadFromDB reads all whitelisted domains from SQLite and constructs the Bloom Filter in RAM.
func (w *Whitelist) LoadFromDB() error {
	if w == nil || w.db == nil || !w.db.Enabled() {
		return nil
	}

	domains, err := w.db.GetWhitelist()
	if err != nil {
		return fmt.Errorf("get whitelist from db: %w", err)
	}

	if len(domains) == 0 {
		w.mu.Lock()
		w.bloom = nil
		w.mu.Unlock()
		return nil
	}

	// Create Bloom Filter with 1% false positive rate
	bf := NewBloomFilter(len(domains), 0.01)
	for _, d := range domains {
		bf.Add(d)
	}

	w.mu.Lock()
	w.bloom = bf
	w.mu.Unlock()

	logjson.Info("whitelist bloom filter loaded from database", map[string]any{
		"service":  "risk",
		"storage":  "sqlite",
		"strategy": "bloom",
		"domains":  len(domains),
		"size_kb":  float64(bf.m) / 8.0 / 1024.0,
		"hashes":   bf.k,
	})
	return nil
}

// LoadFromFile parses a whitelist file (such as Tranco Top 1M CSV).
// If a database is configured, it bulk-saves it to the database and reconstructs the RAM Bloom Filter.
// Otherwise, it populates the fallback in-memory map.
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
		if err == nil && normalized != "" {
			domains = append(domains, normalized)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if w.db != nil && w.db.Enabled() {
		// Import into SQLite database
		if err := w.db.UpdateWhitelist(domains); err != nil {
			return fmt.Errorf("load file to database: %w", err)
		}
		// Synchronize RAM Bloom Filter from DB
		return w.LoadFromDB()
	}

	// Fallback to in-memory map
	w.mu.Lock()
	w.allowed = make(map[string]struct{})
	for _, d := range domains {
		w.allowed[d] = struct{}{}
	}
	w.mu.Unlock()

	logjson.Info("whitelist map loaded from file", map[string]any{
		"service":  "risk",
		"storage":  "file",
		"strategy": "map",
		"domains":  len(domains),
		"path":     path,
	})
	return nil
}

// IsAllowed checks if the domain (or any of its parent domains) is whitelisted.
func (w *Whitelist) IsAllowed(domain string) bool {
	if w == nil {
		return false
	}

	w.mu.RLock()
	defer w.mu.RUnlock()

	// Check exact match and parent domains (e.g., if google.com is allowed, mail.google.com is allowed)
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts); i++ {
		candidate := strings.Join(parts[i:], ".")
		if candidate == "" {
			continue
		}

		// 1. Fallback mode: check in-memory map
		if w.db == nil || !w.db.Enabled() {
			if _, ok := w.allowed[candidate]; ok {
				return true
			}
			continue
		}

		// 2. Hybrid mode: check RAM Bloom Filter, then verify in SQLite
		if w.bloom != nil {
			if !w.bloom.Test(candidate) {
				// Bloom Filter says No → 100% accurate negative
				continue
			}
			// Bloom Filter says Yes → Verify in SQLite (resolves the 1% false positive rate)
			ok, err := w.db.IsDomainWhitelisted(candidate)
			if err == nil && ok {
				return true
			}
		}
	}

	return false
}

// WhitelistMetrics holds operational Bloom filter and Whitelist size metrics.
type WhitelistMetrics struct {
	LoadedDomains int     `json:"loaded_domains"`
	BloomBits     uint64  `json:"bloom_bits"`
	BloomHashes   uint64  `json:"bloom_hashes"`
	BloomSizeRAM  float64 `json:"bloom_size_ram_kb"`
	FPR           float64 `json:"fpr"`
}

// Metrics queries Whitelist capacity and dynamic RAM usage.
func (w *Whitelist) Metrics() WhitelistMetrics {
	if w == nil {
		return WhitelistMetrics{}
	}
	w.mu.RLock()
	defer w.mu.RUnlock()

	var loaded int
	if w.db != nil && w.db.Enabled() {
		if domains, err := w.db.GetWhitelist(); err == nil {
			loaded = len(domains)
		}
	} else {
		loaded = len(w.allowed)
	}

	var bits, hashes uint64
	var sizeRAM float64
	if w.bloom != nil {
		bits = w.bloom.m
		hashes = w.bloom.k
		sizeRAM = float64(bits) / 8.0 / 1024.0 // KB
	}

	return WhitelistMetrics{
		LoadedDomains: loaded,
		BloomBits:     bits,
		BloomHashes:   hashes,
		BloomSizeRAM:  sizeRAM,
		FPR:           0.01, // 1% false positive rate
	}
}

