package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"safe-zone/internal/config"
	"safe-zone/internal/logjson"
)

// TelemetryEntry represents a single domain analysis record.
type TelemetryEntry struct {
	ID         int64    `json:"id,omitempty"`
	Domain     string   `json:"domain"`
	Verdict    string   `json:"verdict"`
	Score      int      `json:"score"`
	Confidence float64  `json:"confidence"`
	Reasons    []string `json:"reasons"`
	CacheHit   bool     `json:"cache_hit"`
	Source     string   `json:"source"`
	AnalyzedAt string   `json:"analyzed_at"`
	CreatedAt  string   `json:"created_at,omitempty"`
	ClientIP   string   `json:"client_ip,omitempty"`
	ClientID   string   `json:"client_id,omitempty"`
}

// TelemetryFilter constrains recent telemetry queries at the SQL layer.
type TelemetryFilter struct {
	Verdict string    `json:"verdict,omitempty"`
	Source  string    `json:"source,omitempty"`
	Domain  string    `json:"domain,omitempty"`
	Since   time.Time `json:"since,omitempty"`
}

// ClientGroup represents a policy group for clients.
type ClientGroup struct {
	ID              int64    `json:"id"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	BlockCategories []string `json:"block_categories"` // stored as JSON array in SQLite
	StrictPhishing  bool     `json:"strict_phishing"`
	StrictMalware   bool     `json:"strict_malware"`
	CreatedAt       string   `json:"created_at"`
	UpdatedAt       string   `json:"updated_at"`
}

// ClientMapping represents a mapping of a client device to a policy group.
type ClientMapping struct {
	ID          int64  `json:"id"`
	MappingType string `json:"mapping_type"` // "ip", "cidr", "client_id"
	Value       string `json:"value"`
	GroupID     int64  `json:"group_id"`
	GroupName   string `json:"group_name,omitempty"` // populated during joins
	CreatedAt   string `json:"created_at"`
}

// GroupOverride represents a manual override rule specific to a policy group.
type GroupOverride struct {
	ID        int64  `json:"id"`
	GroupID   int64  `json:"group_id"`
	Domain    string `json:"domain"`
	Action    string `json:"action"` // "allow", "block"
	Reason    string `json:"reason"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// Override represents a manually configured domain allow/block rule.
type Override struct {
	ID        int64  `json:"id"`
	Domain    string `json:"domain"`
	Action    string `json:"action"` // "allow" or "block"
	Reason    string `json:"reason"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// TrendPoint represents a single data point in a time-series trend.
type TrendPoint struct {
	Timestamp  string `json:"timestamp"`
	Safe       int64  `json:"safe"`
	Suspicious int64  `json:"suspicious"`
	Malicious  int64  `json:"malicious"`
	Threats    int64  `json:"threats"`
}

// ScoreBand is an aggregate count for one inclusive threat-score range.
type ScoreBand struct {
	Label string `json:"label"`
	Value int64  `json:"value"`
}

// Stats contains aggregate telemetry statistics.
type Stats struct {
	Total      int64        `json:"total"`
	Safe       int64        `json:"safe"`
	Suspicious int64        `json:"suspicious"`
	Malicious  int64        `json:"malicious"`
	CacheHits  int64        `json:"cache_hits"`
	Period     string       `json:"period"`
	ScoreBands []ScoreBand  `json:"score_bands"`
	Trend      []TrendPoint `json:"trend"`
}

// AgentEvent represents a single entry in the agent_audit_log table.
type AgentEvent struct {
	ID        int64  `json:"id"`
	TaskName  string `json:"task_name"`
	EventType string `json:"event_type"`
	Domain    string `json:"domain,omitempty"`
	Details   string `json:"details"`
	CreatedAt string `json:"created_at"`
}

type OSINTEvidence struct {
	ID           int64    `json:"id,omitempty"`
	Domain       string   `json:"domain"`
	SourceURL    string   `json:"source_url"`
	SourceTitle  string   `json:"source_title,omitempty"`
	SourceType   string   `json:"source_type"`
	Confidence   float64  `json:"confidence"`
	MatchedTerms []string `json:"matched_terms,omitempty"`
	RetrievedAt  string   `json:"retrieved_at"`
	ExpiresAt    string   `json:"expires_at"`
}

type BlockReport struct {
	ID        int64  `json:"id"`
	Domain    string `json:"domain"`
	Contact   string `json:"contact"`
	Note      string `json:"note"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

// BlockReportFilter constrains user report queries at the SQL layer.
type BlockReportFilter struct {
	Status string
	Query  string
}

// DomainCount holds a domain and its occurrence count from audit queries.
type DomainCount struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

type WhoisCacheEntry struct {
	Domain         string
	Found          bool
	RegisteredDate time.Time
	DomainAgeDays  int
	Registrar      string
	PrivacyGuard   bool
	Score          int
	Reasons        []string
	RawText        string
	CachedAt       time.Time
	ExpiresAt      time.Time
}

type cidrMapping struct {
	groupID int64
	ipNet   *net.IPNet
}

// DB wraps a SQLite connection with telemetry and override capabilities.
type DB struct {
	db            *sql.DB
	dbPath        string
	telemetryCh   chan TelemetryEntry
	retentionDays int
	configMu      sync.RWMutex
	done          chan struct{}
	wg            sync.WaitGroup

	// CIDR Cache
	cidrMu    sync.RWMutex
	cidrCache []cidrMapping
}

const schema = `
CREATE TABLE IF NOT EXISTS analysis_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    verdict TEXT NOT NULL,
    score INTEGER NOT NULL,
    confidence REAL NOT NULL,
    reasons TEXT,
    cache_hit INTEGER NOT NULL DEFAULT 0,
    source TEXT,
    analyzed_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    client_ip TEXT DEFAULT '',
    client_id TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_log_domain ON analysis_log(domain);
CREATE INDEX IF NOT EXISTS idx_log_analyzed_at ON analysis_log(analyzed_at);
CREATE INDEX IF NOT EXISTS idx_log_verdict ON analysis_log(verdict);

CREATE TABLE IF NOT EXISTS local_overrides (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    action TEXT NOT NULL CHECK(action IN ('allow', 'block')),
    reason TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS agent_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_name TEXT NOT NULL,
    event_type TEXT NOT NULL,
    domain TEXT,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_agent_audit_task ON agent_audit_log(task_name);
CREATE INDEX IF NOT EXISTS idx_agent_audit_created ON agent_audit_log(created_at);

CREATE TABLE IF NOT EXISTS osint_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    source_url TEXT NOT NULL,
    source_title TEXT DEFAULT '',
    source_type TEXT NOT NULL,
    confidence REAL NOT NULL,
    matched_terms TEXT,
    retrieved_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(domain, source_url)
);
CREATE INDEX IF NOT EXISTS idx_osint_evidence_domain ON osint_evidence(domain);
CREATE INDEX IF NOT EXISTS idx_osint_evidence_expires ON osint_evidence(expires_at);

CREATE TABLE IF NOT EXISTS whitelist_domains (
    domain TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS client_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    block_categories TEXT NOT NULL DEFAULT '[]', -- JSON array of strings
    strict_phishing INTEGER NOT NULL DEFAULT 0,
    strict_malware INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS client_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mapping_type TEXT NOT NULL CHECK(mapping_type IN ('ip', 'cidr', 'client_id')),
    value TEXT NOT NULL,
    group_id INTEGER NOT NULL REFERENCES client_groups(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(mapping_type, value)
);
CREATE INDEX IF NOT EXISTS idx_mapping_value ON client_mappings(value);

CREATE TABLE IF NOT EXISTS group_overrides (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL REFERENCES client_groups(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('allow', 'block')),
    reason TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(group_id, domain)
);
CREATE INDEX IF NOT EXISTS idx_group_override_lookup ON group_overrides(group_id, domain);

CREATE TABLE IF NOT EXISTS trusted_brands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    official_domain TEXT NOT NULL UNIQUE,
    alt_domains TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_trusted_brands_name ON trusted_brands(name);
CREATE INDEX IF NOT EXISTS idx_trusted_brands_official_domain ON trusted_brands(official_domain);

CREATE TABLE IF NOT EXISTS block_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    contact TEXT,
    note TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_block_reports_status ON block_reports(status);
CREATE INDEX IF NOT EXISTS idx_block_reports_domain ON block_reports(domain);

CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS whois_cache (
    domain TEXT PRIMARY KEY,
    found INTEGER NOT NULL DEFAULT 0,
    registered_date TEXT,
    domain_age_days INTEGER NOT NULL DEFAULT 0,
    registrar TEXT DEFAULT '',
    privacy_guard INTEGER NOT NULL DEFAULT 0,
    score INTEGER NOT NULL DEFAULT 0,
    reasons TEXT NOT NULL DEFAULT '[]',
    raw_text TEXT DEFAULT '',
    cached_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_whois_cache_expires ON whois_cache(expires_at);
`

const telemetryBufferSize = 1000
const cleanupInterval = 1 * time.Hour
const whitelistInsertChunkSize = 500

// New opens a SQLite database at the given path, runs migrations, and starts
// background goroutines for async telemetry writes and periodic cleanup.
// If path is empty, returns nil (disabled mode).
func New(path string, retentionDays int) (*DB, error) {
	if path == "" {
		return nil, nil
	}
	if retentionDays <= 0 {
		retentionDays = 30
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("create sqlite directory %s: %w", dir, err)
		}
	}

	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	if strings.Contains(path, ":memory:") {
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
	} else {
		// modernc.org/sqlite serializes writes internally. Limiting open
		// connections prevents OS-level thread contention on the DB lock
		// and avoids "database is locked" under concurrent load.
		sqlDB.SetMaxOpenConns(2)
		sqlDB.SetMaxIdleConns(2)
		sqlDB.SetConnMaxLifetime(0) // reuse indefinitely
	}

	// Apply performance pragmas.
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA cache_size=-8000",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	}
	for _, pragma := range pragmas {
		if _, err := sqlDB.Exec(pragma); err != nil {
			_ = sqlDB.Close() // #nosec G104 -- error path; primary error already captured
			return nil, fmt.Errorf("exec %s: %w", pragma, err)
		}
	}

	// Run schema migrations.
	if _, err := sqlDB.Exec(schema); err != nil {
		_ = sqlDB.Close() // #nosec G104 -- error path; primary error already captured
		return nil, fmt.Errorf("migrate schema: %w", err)
	}

	// Dynamic migration for legacy analysis_log table (adding client_ip and client_id)
	var hasClientIP, hasClientID bool
	rows, err := sqlDB.Query("PRAGMA table_info(analysis_log)")
	if err == nil {
		for rows.Next() {
			var cid int
			var name, ctype string
			var notnull int
			var dfltVal any
			var pk int
			if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltVal, &pk); err == nil {
				if name == "client_ip" {
					hasClientIP = true
				}
				if name == "client_id" {
					hasClientID = true
				}
			}
		}
		_ = rows.Close() // #nosec G104 -- rows read successfully; close error is non-critical
	}
	if !hasClientIP {
		_, _ = sqlDB.Exec("ALTER TABLE analysis_log ADD COLUMN client_ip TEXT DEFAULT ''")
	}
	if !hasClientID {
		_, _ = sqlDB.Exec("ALTER TABLE analysis_log ADD COLUMN client_id TEXT DEFAULT ''")
	}

	// Load custom retentionDays if stored in database
	var customRetentionStr string
	_ = sqlDB.QueryRow(`SELECT value FROM system_config WHERE key = 'telemetry_retention_days'`).Scan(&customRetentionStr)
	if customRetentionStr != "" {
		if val, err := strconv.Atoi(customRetentionStr); err == nil && val > 0 {
			retentionDays = val
		}
	}

	d := &DB{
		db:            sqlDB,
		dbPath:        path,
		telemetryCh:   make(chan TelemetryEntry, telemetryBufferSize),
		retentionDays: retentionDays,
		done:          make(chan struct{}),
	}

	if err := d.SeedDefaultBrands(context.Background()); err != nil {
		_ = sqlDB.Close() // #nosec G104 -- error path; primary error already captured
		return nil, fmt.Errorf("seed default brands: %w", err)
	}

	// Auto-initialize default groups
	if err := d.CreateDefaultGroups(context.Background()); err != nil {
		_ = sqlDB.Close() // #nosec G104 -- error path; primary error already captured
		return nil, fmt.Errorf("create default groups: %w", err)
	}

	// Load CIDR mappings cache into memory for fast DNS querying
	if err := d.loadCIDRCache(); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("load cidr cache: %w", err)
	}

	d.wg.Add(2)
	go d.telemetryWriter()
	go d.cleanupLoop()

	logjson.Info("sqlite store opened", map[string]any{
		"service":        "store",
		"path":           path,
		"retention_days": retentionDays,
	})
	return d, nil
}

// Close stops background goroutines and closes the database.
func (d *DB) Close() error {
	if d == nil {
		return nil
	}
	close(d.done)
	d.wg.Wait()
	return d.db.Close()
}

// Enabled returns true if the store is initialized and available.
func (d *DB) Enabled() bool {
	return d != nil && d.db != nil
}

// --- Telemetry ---

// RecordAnalysis enqueues a telemetry entry for async writing.
// Non-blocking: if the buffer is full, the entry is silently dropped.
func (d *DB) RecordAnalysis(entry TelemetryEntry) {
	if !d.Enabled() {
		return
	}
	select {
	case d.telemetryCh <- entry:
	default:
		// Buffer full, drop entry to avoid blocking DNS resolution.
	}
}

func (d *DB) telemetryWriter() {
	defer d.wg.Done()
	for {
		select {
		case entry := <-d.telemetryCh:
			d.writeEntry(entry)
		case <-d.done:
			// Drain remaining entries before exiting.
			for {
				select {
				case entry := <-d.telemetryCh:
					d.writeEntry(entry)
				default:
					return
				}
			}
		}
	}
}

func (d *DB) writeEntry(entry TelemetryEntry) {
	reasonsJSON, _ := json.Marshal(entry.Reasons)
	cacheHit := 0
	if entry.CacheHit {
		cacheHit = 1
	}
	_, err := d.db.ExecContext(context.Background(),
		`INSERT INTO analysis_log (domain, verdict, score, confidence, reasons, cache_hit, source, analyzed_at, client_ip, client_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.Domain, entry.Verdict, entry.Score, entry.Confidence,
		string(reasonsJSON), cacheHit, entry.Source, entry.AnalyzedAt,
		entry.ClientIP, entry.ClientID,
	)
	if err != nil {
		logjson.Error("telemetry write failed", map[string]any{
			"service": "store",
			"error":   err.Error(),
		})
	}
}

// QueryRecent returns the most recent telemetry entries with pagination.
func (d *DB) QueryRecent(ctx context.Context, limit, offset int) ([]TelemetryEntry, error) {
	return d.QueryRecentFiltered(ctx, TelemetryFilter{}, limit, offset)
}

// QueryRecentFiltered returns recent telemetry entries with server-side filtering and pagination.
func (d *DB) QueryRecentFiltered(ctx context.Context, filter TelemetryFilter, limit, offset int) ([]TelemetryEntry, error) {
	if !d.Enabled() {
		return nil, nil
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	where, args := telemetryWhereClause(filter)
	args = append(args, limit, offset)

	// #nosec G202 -- query is safely constructed via string concatenation but parameters are parameterized.
	rows, err := d.db.QueryContext(ctx,
		`SELECT id, domain, verdict, score, confidence,
		        COALESCE(reasons, '[]'), cache_hit, COALESCE(source, ''),
		        analyzed_at, created_at, COALESCE(client_ip, ''), COALESCE(client_id, '')
		 FROM analysis_log `+where+` ORDER BY id DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("query recent: %w", err)
	}
	defer rows.Close()

	var entries []TelemetryEntry
	for rows.Next() {
		var e TelemetryEntry
		var reasonsJSON string
		var cacheHit int
		if err := rows.Scan(&e.ID, &e.Domain, &e.Verdict, &e.Score, &e.Confidence,
			&reasonsJSON, &cacheHit, &e.Source, &e.AnalyzedAt, &e.CreatedAt, &e.ClientIP, &e.ClientID); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		_ = json.Unmarshal([]byte(reasonsJSON), &e.Reasons)
		e.CacheHit = cacheHit != 0
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func telemetryWhereClause(filter TelemetryFilter) (string, []any) {
	var clauses []string
	var args []any
	if filter.Verdict != "" {
		clauses = append(clauses, "verdict = ?")
		args = append(args, strings.ToUpper(strings.TrimSpace(filter.Verdict)))
	}
	if filter.Source != "" {
		clauses = append(clauses, "source = ?")
		args = append(args, strings.TrimSpace(filter.Source))
	}
	if filter.Domain != "" {
		clauses = append(clauses, "LOWER(domain) LIKE ?")
		args = append(args, "%"+strings.ToLower(strings.TrimSpace(filter.Domain))+"%")
	}
	if !filter.Since.IsZero() {
		clauses = append(clauses, "analyzed_at >= ?")
		args = append(args, filter.Since.UTC().Format(time.RFC3339))
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

// QueryStats returns aggregate telemetry statistics and trend data for the given period.
func (d *DB) QueryStats(ctx context.Context, period string) (Stats, error) {
	if !d.Enabled() {
		return Stats{}, nil
	}

	now := time.Now()
	var since time.Time
	var bucketDuration time.Duration

	switch period {
	case "7d":
		since = now.Add(-7 * 24 * time.Hour)
		bucketDuration = 4 * time.Hour
	case "30d":
		since = now.Add(-30 * 24 * time.Hour)
		bucketDuration = 12 * time.Hour
	case "24h":
		fallthrough
	default:
		period = "24h"
		since = now.Add(-24 * time.Hour)
		bucketDuration = 1 * time.Hour
	}

	sinceStr := since.UTC().Format(time.RFC3339)
	row := d.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*) AS total,
			COALESCE(SUM(CASE WHEN verdict = 'SAFE' THEN 1 ELSE 0 END), 0) AS safe,
			COALESCE(SUM(CASE WHEN verdict = 'SUSPICIOUS' THEN 1 ELSE 0 END), 0) AS suspicious,
			COALESCE(SUM(CASE WHEN verdict = 'MALICIOUS' THEN 1 ELSE 0 END), 0) AS malicious,
			COALESCE(SUM(cache_hit), 0) AS cache_hits,
			COALESCE(SUM(CASE WHEN score BETWEEN 0 AND 20 THEN 1 ELSE 0 END), 0) AS score_0_20,
			COALESCE(SUM(CASE WHEN score BETWEEN 21 AND 40 THEN 1 ELSE 0 END), 0) AS score_21_40,
			COALESCE(SUM(CASE WHEN score BETWEEN 41 AND 60 THEN 1 ELSE 0 END), 0) AS score_41_60,
			COALESCE(SUM(CASE WHEN score BETWEEN 61 AND 80 THEN 1 ELSE 0 END), 0) AS score_61_80,
			COALESCE(SUM(CASE WHEN score BETWEEN 81 AND 100 THEN 1 ELSE 0 END), 0) AS score_81_100
		FROM analysis_log WHERE analyzed_at >= ?`, sinceStr)

	var s Stats
	var score0To20, score21To40, score41To60, score61To80, score81To100 int64
	if err := row.Scan(
		&s.Total,
		&s.Safe,
		&s.Suspicious,
		&s.Malicious,
		&s.CacheHits,
		&score0To20,
		&score21To40,
		&score41To60,
		&score61To80,
		&score81To100,
	); err != nil {
		return Stats{}, fmt.Errorf("query stats: %w", err)
	}
	s.Period = period
	s.ScoreBands = []ScoreBand{
		{Label: "0-20", Value: score0To20},
		{Label: "21-40", Value: score21To40},
		{Label: "41-60", Value: score41To60},
		{Label: "61-80", Value: score61To80},
		{Label: "81-100", Value: score81To100},
	}

	// Query hourly data for the trend chart
	trendRows, err := d.db.QueryContext(ctx, `
		SELECT
			substr(analyzed_at, 1, 13) AS hr,
			COALESCE(SUM(CASE WHEN verdict = 'SAFE' THEN 1 ELSE 0 END), 0) AS safe,
			COALESCE(SUM(CASE WHEN verdict = 'SUSPICIOUS' THEN 1 ELSE 0 END), 0) AS suspicious,
			COALESCE(SUM(CASE WHEN verdict = 'MALICIOUS' THEN 1 ELSE 0 END), 0) AS malicious
		FROM analysis_log 
		WHERE analyzed_at >= ?
		GROUP BY hr
		ORDER BY hr ASC`, sinceStr)

	if err != nil {
		return Stats{}, fmt.Errorf("query trend: %w", err)
	}
	defer trendRows.Close()

	// Map to hold hourly counts
	hourlyMap := make(map[string]TrendPoint)
	for trendRows.Next() {
		var hr string
		var safe, suspicious, malicious int64
		if err := trendRows.Scan(&hr, &safe, &suspicious, &malicious); err == nil {
			hourlyMap[hr] = TrendPoint{
				Safe:       safe,
				Suspicious: suspicious,
				Malicious:  malicious,
				Threats:    suspicious + malicious,
			}
		}
	}
	if err := trendRows.Err(); err != nil {
		return Stats{}, fmt.Errorf("read trend: %w", err)
	}

	// Generate every bucket intersecting the requested rolling period. Including
	// the partial first and current buckets keeps the trend total consistent with
	// the aggregate total instead of silently dropping the period edges.
	var trend []TrendPoint
	firstBucketTime := since.UTC().Truncate(bucketDuration)
	currentBucketTime := now.UTC().Truncate(bucketDuration)
	for bucketStart := firstBucketTime; !bucketStart.After(currentBucketTime); bucketStart = bucketStart.Add(bucketDuration) {

		tp := TrendPoint{
			Timestamp: bucketStart.Format(time.RFC3339),
		}

		// Sum up the hours that fall into this bucket
		// E.g., for a 4-hour bucket, check the 4 hours starting at bucketStart
		hoursInBucket := int(bucketDuration / time.Hour)
		for h := 0; h < hoursInBucket; h++ {
			hrTime := bucketStart.Add(time.Duration(h) * time.Hour)
			hrStr := hrTime.UTC().Format("2006-01-02T15")
			if pt, ok := hourlyMap[hrStr]; ok {
				tp.Safe += pt.Safe
				tp.Suspicious += pt.Suspicious
				tp.Malicious += pt.Malicious
				tp.Threats += pt.Threats
			}
		}

		trend = append(trend, tp)
	}
	s.Trend = trend

	return s, nil
}

func (d *DB) cleanupLoop() {
	defer d.wg.Done()
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			d.cleanup()
		case <-d.done:
			return
		}
	}
}

func (d *DB) cleanup() {
	cutoff := time.Now().AddDate(0, 0, -d.GetRetentionDays(context.Background())).UTC().Format(time.RFC3339)
	result, err := d.db.ExecContext(context.Background(), `DELETE FROM analysis_log WHERE analyzed_at < ?`, cutoff)
	if err != nil {
		logjson.Error("telemetry cleanup failed", map[string]any{
			"service": "store",
			"cutoff":  cutoff,
			"error":   err.Error(),
		})
		return
	}
	if n, _ := result.RowsAffected(); n > 0 {
		logjson.Info("telemetry cleanup removed old entries", map[string]any{
			"service": "store",
			"cutoff":  cutoff,
			"removed": n,
		})
	}
	if _, err := d.db.ExecContext(context.Background(), `DELETE FROM whois_cache WHERE expires_at <= ?`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		logjson.Error("whois cache cleanup failed", map[string]any{
			"service": "store",
			"error":   err.Error(),
		})
	}
}

// --- Overrides ---

// GetOverride checks if a domain (or any of its parent domains) has an override.
// Returns nil if no override is found.
func (d *DB) GetOverride(ctx context.Context, domain string) (*Override, error) {
	if !d.Enabled() {
		return nil, nil
	}
	// Check exact match and parent domains (e.g., mail.google.com → google.com → com).
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts); i++ {
		candidate := strings.Join(parts[i:], ".")
		var o Override
		err := d.db.QueryRowContext(ctx,
			`SELECT id, domain, action, reason, created_at, updated_at
			 FROM local_overrides WHERE domain = ?`, candidate).
			Scan(&o.ID, &o.Domain, &o.Action, &o.Reason, &o.CreatedAt, &o.UpdatedAt)
		if err == nil {
			return &o, nil
		}
		if err != sql.ErrNoRows {
			return nil, fmt.Errorf("get override %s: %w", candidate, err)
		}
	}
	return nil, nil
}

// ListOverrides returns all overrides, optionally filtered by action.
func (d *DB) ListOverrides(ctx context.Context, action string) ([]Override, error) {
	if !d.Enabled() {
		return nil, nil
	}

	var rows *sql.Rows
	var err error
	if action == "allow" || action == "block" {
		rows, err = d.db.QueryContext(ctx,
			`SELECT id, domain, action, reason, created_at, updated_at
			 FROM local_overrides WHERE action = ? ORDER BY updated_at DESC`, action)
	} else {
		rows, err = d.db.QueryContext(ctx,
			`SELECT id, domain, action, reason, created_at, updated_at
			 FROM local_overrides ORDER BY updated_at DESC`)
	}
	if err != nil {
		return nil, fmt.Errorf("list overrides: %w", err)
	}
	defer rows.Close()

	var overrides []Override
	for rows.Next() {
		var o Override
		if err := rows.Scan(&o.ID, &o.Domain, &o.Action, &o.Reason, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan override: %w", err)
		}
		overrides = append(overrides, o)
	}
	return overrides, rows.Err()
}

// UpsertOverride creates or updates an override for a domain.
func (d *DB) UpsertOverride(ctx context.Context, domain, action, reason string) error {
	if !d.Enabled() {
		return nil
	}
	if action != "allow" && action != "block" {
		return fmt.Errorf("invalid action %q: must be 'allow' or 'block'", action)
	}
	domain = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(domain)), ".")
	if domain == "" {
		return fmt.Errorf("override domain cannot be empty")
	}
	_, err := d.db.ExecContext(ctx, `
		INSERT INTO local_overrides (domain, action, reason, updated_at)
		VALUES (?, ?, ?, datetime('now'))
		ON CONFLICT(domain) DO UPDATE SET
			action = excluded.action,
			reason = excluded.reason,
			updated_at = datetime('now')`,
		domain, action, reason)
	if err != nil {
		return fmt.Errorf("upsert override %s: %w", domain, err)
	}
	return nil
}

// DeleteOverride removes an override for a domain.
func (d *DB) DeleteOverride(ctx context.Context, domain string) error {
	if !d.Enabled() {
		return nil
	}
	result, err := d.db.ExecContext(ctx, `DELETE FROM local_overrides WHERE domain = ?`, domain)
	if err != nil {
		return fmt.Errorf("delete override %s: %w", domain, err)
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return fmt.Errorf("override not found: %s", domain)
	}
	return nil
}

// --- Agent Audit Log ---

// RecordAgentEvent writes an entry to the agent_audit_log table.
func (d *DB) RecordAgentEvent(ctx context.Context, taskName, eventType, domain, details string) error {
	if !d.Enabled() {
		return nil
	}
	_, err := d.db.ExecContext(ctx,
		`INSERT INTO agent_audit_log (task_name, event_type, domain, details) VALUES (?, ?, ?, ?)`,
		taskName, eventType, domain, details,
	)
	if err != nil {
		return fmt.Errorf("record agent event: %w", err)
	}
	return nil
}

// QueryAgentEvents returns agent events since a given time, optionally filtered by event types.
func (d *DB) QueryAgentEvents(ctx context.Context, since time.Time, eventTypes []string, limit int) ([]AgentEvent, error) {
	if !d.Enabled() {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}

	// Use SQLite-compatible datetime format (matches datetime('now') output).
	sinceStr := since.UTC().Format("2006-01-02 15:04:05")

	var rows *sql.Rows
	var err error
	if len(eventTypes) > 0 {
		placeholders := make([]string, len(eventTypes))
		args := make([]any, 0, len(eventTypes)+2)
		args = append(args, sinceStr)
		for i, et := range eventTypes {
			placeholders[i] = "?"
			args = append(args, et)
		}
		args = append(args, limit)
		query := fmt.Sprintf( // #nosec G201 -- placeholders are always literal "?" strings, never user input
			`SELECT id, task_name, event_type, COALESCE(domain, ''), COALESCE(details, ''), created_at
			 FROM agent_audit_log
			 WHERE created_at >= ? AND event_type IN (%s)
			 ORDER BY created_at ASC LIMIT ?`,
			strings.Join(placeholders, ","))
		rows, err = d.db.QueryContext(ctx, query, args...)
	} else {
		rows, err = d.db.QueryContext(ctx,
			`SELECT id, task_name, event_type, COALESCE(domain, ''), COALESCE(details, ''), created_at
			 FROM agent_audit_log
			 WHERE created_at >= ?
			 ORDER BY created_at ASC LIMIT ?`, sinceStr, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("query agent events: %w", err)
	}
	defer rows.Close()

	var events []AgentEvent
	for rows.Next() {
		var e AgentEvent
		if err := rows.Scan(&e.ID, &e.TaskName, &e.EventType, &e.Domain, &e.Details, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan agent event: %w", err)
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// QuerySuspiciousDomains returns domains with verdict SUSPICIOUS that appeared
// at least minOccurrences times since the given time, ordered by count descending.
func (d *DB) QuerySuspiciousDomains(ctx context.Context, since time.Time, minOccurrences, limit int) ([]DomainCount, error) {
	if !d.Enabled() {
		return nil, nil
	}
	if minOccurrences <= 0 {
		minOccurrences = 3
	}
	if limit <= 0 {
		limit = 50
	}

	sinceStr := since.UTC().Format(time.RFC3339)
	rows, err := d.db.QueryContext(ctx, `
		SELECT domain, COUNT(*) AS cnt
		FROM analysis_log
		WHERE verdict = 'SUSPICIOUS' AND analyzed_at >= ?
		GROUP BY domain
		HAVING cnt >= ?
		ORDER BY cnt DESC
		LIMIT ?`, sinceStr, minOccurrences, limit)
	if err != nil {
		return nil, fmt.Errorf("query suspicious domains: %w", err)
	}
	defer rows.Close()

	var results []DomainCount
	for rows.Next() {
		var dc DomainCount
		if err := rows.Scan(&dc.Domain, &dc.Count); err != nil {
			return nil, fmt.Errorf("scan domain count: %w", err)
		}
		results = append(results, dc)
	}
	return results, rows.Err()
}

// QueryRecentAllowedOrSuspiciousDomains returns recently seen non-malicious
// domains for background evidence checks. The caller applies domain-keyword
// filtering so this query stays simple and index-friendly.
func (d *DB) QueryRecentAllowedOrSuspiciousDomains(ctx context.Context, since time.Time, limit int) ([]DomainCount, error) {
	if !d.Enabled() {
		return nil, nil
	}
	if limit <= 0 {
		limit = 50
	}

	sinceStr := since.UTC().Format(time.RFC3339)
	rows, err := d.db.QueryContext(ctx, `
		SELECT domain, COUNT(*) AS cnt
		FROM analysis_log
		WHERE verdict IN ('SAFE', 'SUSPICIOUS') AND analyzed_at >= ?
		GROUP BY domain
		ORDER BY cnt DESC
		LIMIT ?`, sinceStr, limit)
	if err != nil {
		return nil, fmt.Errorf("query osint candidate domains: %w", err)
	}
	defer rows.Close()

	var results []DomainCount
	for rows.Next() {
		var dc DomainCount
		if err := rows.Scan(&dc.Domain, &dc.Count); err != nil {
			return nil, fmt.Errorf("scan osint candidate: %w", err)
		}
		results = append(results, dc)
	}
	return results, rows.Err()
}

func (d *DB) ReplaceOSINTEvidence(ctx context.Context, domain string, evidence []OSINTEvidence) error {
	if !d.Enabled() {
		return nil
	}
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return fmt.Errorf("domain is required")
	}

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin osint evidence transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM osint_evidence WHERE domain = ?`, domain); err != nil {
		return fmt.Errorf("delete old osint evidence: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO osint_evidence
			(domain, source_url, source_title, source_type, confidence, matched_terms, retrieved_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare osint evidence insert: %w", err)
	}
	defer stmt.Close()

	for _, item := range evidence {
		termsJSON, _ := json.Marshal(item.MatchedTerms)
		if item.Domain == "" {
			item.Domain = domain
		}
		if _, err := stmt.ExecContext(ctx,
			item.Domain,
			item.SourceURL,
			item.SourceTitle,
			item.SourceType,
			item.Confidence,
			string(termsJSON),
			item.RetrievedAt,
			item.ExpiresAt,
		); err != nil {
			return fmt.Errorf("insert osint evidence: %w", err)
		}
	}

	return tx.Commit()
}

func (d *DB) ListOSINTEvidence(ctx context.Context, domain string, now time.Time) ([]OSINTEvidence, error) {
	if !d.Enabled() {
		return nil, nil
	}
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	nowStr := now.UTC().Format(time.RFC3339Nano)
	rows, err := d.db.QueryContext(ctx, `
		SELECT id, domain, source_url, COALESCE(source_title, ''), source_type, confidence,
		       COALESCE(matched_terms, '[]'), retrieved_at, expires_at
		FROM osint_evidence
		WHERE domain = ? AND expires_at > ?
		ORDER BY confidence DESC, retrieved_at DESC`, domain, nowStr)
	if err != nil {
		return nil, fmt.Errorf("list osint evidence: %w", err)
	}
	defer rows.Close()

	var items []OSINTEvidence
	for rows.Next() {
		var item OSINTEvidence
		var termsJSON string
		if err := rows.Scan(&item.ID, &item.Domain, &item.SourceURL, &item.SourceTitle, &item.SourceType, &item.Confidence, &termsJSON, &item.RetrievedAt, &item.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan osint evidence: %w", err)
		}
		_ = json.Unmarshal([]byte(termsJSON), &item.MatchedTerms)
		items = append(items, item)
	}
	return items, rows.Err()
}

// --- Whitelist ---

// UpdateWhitelist clears the existing whitelist and inserts a new set of domains
// in a single highly optimized transaction.
func (d *DB) UpdateWhitelist(ctx context.Context, domains []string) error {
	if !d.Enabled() {
		return nil
	}

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin whitelist transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, "DELETE FROM whitelist_domains")
	if err != nil {
		return fmt.Errorf("delete old whitelist: %w", err)
	}

	for start := 0; start < len(domains); start += whitelistInsertChunkSize {
		end := start + whitelistInsertChunkSize
		if end > len(domains) {
			end = len(domains)
		}

		query, args := buildWhitelistInsertQuery(domains[start:end])
		if len(args) == 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("insert whitelist domains chunk [%d:%d]: %w", start, end, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit whitelist transaction: %w", err)
	}

	return nil
}

func buildWhitelistInsertQuery(domains []string) (string, []any) {
	args := make([]any, 0, len(domains))
	var builder strings.Builder
	builder.Grow(len("INSERT OR IGNORE INTO whitelist_domains (domain) VALUES ") + len(domains)*5)
	builder.WriteString("INSERT OR IGNORE INTO whitelist_domains (domain) VALUES ")

	for _, domain := range domains {
		if domain == "" {
			continue
		}
		if len(args) > 0 {
			builder.WriteString(",")
		}
		builder.WriteString("(?)")
		args = append(args, domain)
	}

	return builder.String(), args
}

// IsDomainWhitelisted checks if the domain exists exactly in the SQLite whitelist table.
func (d *DB) IsDomainWhitelisted(ctx context.Context, domain string) (bool, error) {
	if !d.Enabled() {
		return false, nil
	}

	var exists int
	err := d.db.QueryRowContext(ctx, "SELECT 1 FROM whitelist_domains WHERE domain = ? LIMIT 1", domain).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check whitelist domain %s: %w", domain, err)
	}

	return true, nil
}

// GetWhitelistCount returns the number of domains stored in the SQLite whitelist table.
func (d *DB) GetWhitelistCount(ctx context.Context) (int, error) {
	if !d.Enabled() {
		return 0, nil
	}

	var count int
	if err := d.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM whitelist_domains").Scan(&count); err != nil {
		return 0, fmt.Errorf("count whitelist domains: %w", err)
	}
	return count, nil
}

// StreamWhitelist iterates sequentially over whitelist domains without allocating
// an intermediate slice of all rows in memory.
func (d *DB) StreamWhitelist(ctx context.Context, fn func(string) error) error {
	if !d.Enabled() || fn == nil {
		return nil
	}

	rows, err := d.db.QueryContext(ctx, "SELECT domain FROM whitelist_domains")
	if err != nil {
		return fmt.Errorf("query whitelist domains: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return fmt.Errorf("scan whitelist domain: %w", err)
		}
		if err := fn(domain); err != nil {
			return fmt.Errorf("stream whitelist domain %s: %w", domain, err)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate whitelist domains: %w", err)
	}
	return nil
}

// GetWhitelist retrieves all domains in the SQLite whitelist table.
func (d *DB) GetWhitelist(ctx context.Context) ([]string, error) {
	if !d.Enabled() {
		return nil, nil
	}

	rows, err := d.db.QueryContext(ctx, "SELECT domain FROM whitelist_domains")
	if err != nil {
		return nil, fmt.Errorf("query whitelist domains: %w", err)
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, fmt.Errorf("scan whitelist domain: %w", err)
		}
		domains = append(domains, domain)
	}

	return domains, rows.Err()
}

// --- Multi-Tenant CRUD and Dynamic Mapping Methods ---

// CreateDefaultGroups auto-initializes the core 'default' policy group.
func (d *DB) CreateDefaultGroups(ctx context.Context) error {
	if !d.Enabled() {
		return nil
	}

	var exists int
	err := d.db.QueryRowContext(ctx, "SELECT 1 FROM client_groups WHERE name = 'default'").Scan(&exists)
	if err == sql.ErrNoRows {
		_, err = d.db.ExecContext(ctx, `
			INSERT INTO client_groups (name, description, block_categories, strict_phishing, strict_malware)
			VALUES ('default', 'Default policy group', '[]', 0, 1)`)
		if err != nil {
			return fmt.Errorf("insert default group: %w", err)
		}
		logjson.Info("sqlite store initialized default policy group", map[string]any{
			"service": "store",
			"group":   "default",
		})
		return nil
	}
	return err
}

// CreateGroup creates a new client policy group.
func (d *DB) CreateGroup(ctx context.Context, name, description string, blockCategories []string, strictPhishing, strictMalware bool) (int64, error) {
	if !d.Enabled() {
		return 0, fmt.Errorf("sqlite store disabled")
	}

	blockCatsJSON, err := json.Marshal(blockCategories)
	if err != nil {
		return 0, fmt.Errorf("marshal block categories: %w", err)
	}

	sp := 0
	if strictPhishing {
		sp = 1
	}
	sm := 0
	if strictMalware {
		sm = 1
	}

	res, err := d.db.ExecContext(ctx, `
		INSERT INTO client_groups (name, description, block_categories, strict_phishing, strict_malware)
		VALUES (?, ?, ?, ?, ?)`,
		name, description, string(blockCatsJSON), sp, sm)
	if err != nil {
		return 0, fmt.Errorf("insert group %q: %w", name, err)
	}

	return res.LastInsertId()
}

// UpdateGroup updates an existing client policy group.
func (d *DB) UpdateGroup(ctx context.Context, id int64, name, description string, blockCategories []string, strictPhishing, strictMalware bool) error {
	if !d.Enabled() {
		return fmt.Errorf("sqlite store disabled")
	}

	// Protect default group name
	if id == 1 {
		name = "default" // Force name to remain 'default' for protection
	}

	blockCatsJSON, err := json.Marshal(blockCategories)
	if err != nil {
		return fmt.Errorf("marshal block categories: %w", err)
	}

	sp := 0
	if strictPhishing {
		sp = 1
	}
	sm := 0
	if strictMalware {
		sm = 1
	}

	_, err = d.db.ExecContext(ctx, `
		UPDATE client_groups
		SET name = ?, description = ?, block_categories = ?, strict_phishing = ?, strict_malware = ?, updated_at = datetime('now')
		WHERE id = ?`,
		name, description, string(blockCatsJSON), sp, sm, id)
	if err != nil {
		return fmt.Errorf("update group id %d: %w", id, err)
	}

	return nil
}

// DeleteGroup deletes a client policy group.
func (d *DB) DeleteGroup(ctx context.Context, id int64) error {
	if !d.Enabled() {
		return fmt.Errorf("sqlite store disabled")
	}

	if id == 1 {
		return fmt.Errorf("cannot delete default policy group")
	}

	res, err := d.db.ExecContext(ctx, "DELETE FROM client_groups WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete group id %d: %w", id, err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("group not found: id %d", id)
	}

	return nil
}

// GetGroup retrieves a policy group by its ID.
func (d *DB) GetGroup(ctx context.Context, id int64) (*ClientGroup, error) {
	if !d.Enabled() {
		return nil, fmt.Errorf("sqlite store disabled")
	}

	var g ClientGroup
	var blockCatsJSON string
	var sp, sm int

	err := d.db.QueryRowContext(ctx, `
		SELECT id, name, description, block_categories, strict_phishing, strict_malware, created_at, updated_at
		FROM client_groups WHERE id = ?`, id).
		Scan(&g.ID, &g.Name, &g.Description, &blockCatsJSON, &sp, &sm, &g.CreatedAt, &g.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("group not found: id %d", id)
	}
	if err != nil {
		return nil, fmt.Errorf("get group id %d: %w", id, err)
	}

	_ = json.Unmarshal([]byte(blockCatsJSON), &g.BlockCategories)
	g.StrictPhishing = sp != 0
	g.StrictMalware = sm != 0

	return &g, nil
}

// GetGroupByName retrieves a policy group by its unique name.
func (d *DB) GetGroupByName(ctx context.Context, name string) (*ClientGroup, error) {
	if !d.Enabled() {
		return nil, fmt.Errorf("sqlite store disabled")
	}

	var g ClientGroup
	var blockCatsJSON string
	var sp, sm int

	err := d.db.QueryRowContext(ctx, `
		SELECT id, name, description, block_categories, strict_phishing, strict_malware, created_at, updated_at
		FROM client_groups WHERE name = ?`, name).
		Scan(&g.ID, &g.Name, &g.Description, &blockCatsJSON, &sp, &sm, &g.CreatedAt, &g.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("group not found: name %s", name)
	}
	if err != nil {
		return nil, fmt.Errorf("get group name %s: %w", name, err)
	}

	_ = json.Unmarshal([]byte(blockCatsJSON), &g.BlockCategories)
	g.StrictPhishing = sp != 0
	g.StrictMalware = sm != 0

	return &g, nil
}

// ListGroups returns all defined client policy groups.
func (d *DB) ListGroups(ctx context.Context) ([]ClientGroup, error) {
	if !d.Enabled() {
		return nil, nil
	}

	rows, err := d.db.QueryContext(ctx, `
		SELECT id, name, description, block_categories, strict_phishing, strict_malware, created_at, updated_at
		FROM client_groups ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	defer rows.Close()

	var groups []ClientGroup
	for rows.Next() {
		var g ClientGroup
		var blockCatsJSON string
		var sp, sm int
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &blockCatsJSON, &sp, &sm, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan group: %w", err)
		}
		_ = json.Unmarshal([]byte(blockCatsJSON), &g.BlockCategories)
		g.StrictPhishing = sp != 0
		g.StrictMalware = sm != 0
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

// AddMapping maps a client identifier (IP, CIDR, or DoH Client ID) to a policy group.
func (d *DB) AddMapping(ctx context.Context, mappingType, value, groupID string) (int64, error) {
	// Group ID is actually an integer, parse it
	var groupIDInt int64
	_, err := fmt.Sscanf(groupID, "%d", &groupIDInt)
	if err != nil {
		// Try parsing from database fallback or direct call helper
		return 0, fmt.Errorf("invalid group id: %w", err)
	}
	return d.AddMappingInt(ctx, mappingType, value, groupIDInt)
}

// AddMappingInt maps a client with group ID integer.
func (d *DB) AddMappingInt(ctx context.Context, mappingType, value string, groupID int64) (int64, error) {
	if !d.Enabled() {
		return 0, fmt.Errorf("sqlite store disabled")
	}

	mappingType = strings.TrimSpace(strings.ToLower(mappingType))
	if mappingType != "ip" && mappingType != "cidr" && mappingType != "client_id" {
		return 0, fmt.Errorf("invalid mapping type %q: must be 'ip', 'cidr', or 'client_id'", mappingType)
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("mapping value cannot be empty")
	}

	// Validate IP or CIDR formats
	if mappingType == "ip" {
		if net.ParseIP(value) == nil {
			return 0, fmt.Errorf("invalid IP address format: %s", value)
		}
	} else if mappingType == "cidr" {
		if _, ipNet, err := net.ParseCIDR(value); err != nil {
			return 0, fmt.Errorf("invalid CIDR format %q: %w", value, err)
		} else {
			value = ipNet.String()
		}
	}

	res, err := d.db.ExecContext(ctx, `
		INSERT INTO client_mappings (mapping_type, value, group_id)
		VALUES (?, ?, ?)`,
		mappingType, value, groupID)
	if err != nil {
		return 0, fmt.Errorf("insert mapping (%s, %s) -> group %d: %w", mappingType, value, groupID, err)
	}

	lastID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	if mappingType == "cidr" {
		_ = d.loadCIDRCache()
	}

	return lastID, nil
}

// DeleteMapping removes a client device mapping.
func (d *DB) DeleteMapping(ctx context.Context, id int64) error {
	if !d.Enabled() {
		return fmt.Errorf("sqlite store disabled")
	}

	res, err := d.db.ExecContext(ctx, "DELETE FROM client_mappings WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete mapping id %d: %w", id, err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("mapping not found: id %d", id)
	}

	_ = d.loadCIDRCache()
	return nil
}

// ListMappings returns all registered client mappings with group names.
func (d *DB) ListMappings(ctx context.Context) ([]ClientMapping, error) {
	if !d.Enabled() {
		return nil, nil
	}

	rows, err := d.db.QueryContext(ctx, `
		SELECT m.id, m.mapping_type, m.value, m.group_id, g.name, m.created_at
		FROM client_mappings m
		JOIN client_groups g ON m.group_id = g.id
		ORDER BY m.id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list mappings: %w", err)
	}
	defer rows.Close()

	var mappings []ClientMapping
	for rows.Next() {
		var m ClientMapping
		if err := rows.Scan(&m.ID, &m.MappingType, &m.Value, &m.GroupID, &m.GroupName, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan mapping: %w", err)
		}
		mappings = append(mappings, m)
	}
	return mappings, rows.Err()
}

// UpsertGroupOverride creates or updates a domain override rule specific to a policy group.
func (d *DB) UpsertGroupOverride(ctx context.Context, groupID int64, domain, action, reason string) error {
	if !d.Enabled() {
		return fmt.Errorf("sqlite store disabled")
	}

	if action != "allow" && action != "block" {
		return fmt.Errorf("invalid action %q: must be 'allow' or 'block'", action)
	}

	domain = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(domain)), ".")
	if domain == "" {
		return fmt.Errorf("override domain cannot be empty")
	}

	_, err := d.db.ExecContext(ctx, `
		INSERT INTO group_overrides (group_id, domain, action, reason, updated_at)
		VALUES (?, ?, ?, ?, datetime('now'))
		ON CONFLICT(group_id, domain) DO UPDATE SET
			action = excluded.action,
			reason = excluded.reason,
			updated_at = datetime('now')`,
		groupID, domain, action, reason)
	if err != nil {
		return fmt.Errorf("upsert group override (group %d, %s): %w", groupID, domain, err)
	}

	return nil
}

// DeleteGroupOverride removes a group-specific domain override.
func (d *DB) DeleteGroupOverride(ctx context.Context, groupID int64, domain string) error {
	if !d.Enabled() {
		return fmt.Errorf("sqlite store disabled")
	}

	domain = strings.TrimSpace(strings.ToLower(domain))
	res, err := d.db.ExecContext(ctx, "DELETE FROM group_overrides WHERE group_id = ? AND domain = ?", groupID, domain)
	if err != nil {
		return fmt.Errorf("delete group override (group %d, %s): %w", groupID, domain, err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("group override not found for group %d, domain %s", groupID, domain)
	}

	return nil
}

// ListGroupOverrides returns all override rules configured for a specific policy group.
func (d *DB) ListGroupOverrides(ctx context.Context, groupID int64) ([]GroupOverride, error) {
	if !d.Enabled() {
		return nil, nil
	}

	rows, err := d.db.QueryContext(ctx, `
		SELECT id, group_id, domain, action, reason, created_at, updated_at
		FROM group_overrides WHERE group_id = ?
		ORDER BY updated_at DESC`, groupID)
	if err != nil {
		return nil, fmt.Errorf("list group overrides: %w", err)
	}
	defer rows.Close()

	var overrides []GroupOverride
	for rows.Next() {
		var o GroupOverride
		if err := rows.Scan(&o.ID, &o.GroupID, &o.Domain, &o.Action, &o.Reason, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan group override: %w", err)
		}
		overrides = append(overrides, o)
	}
	return overrides, rows.Err()
}

// GetGroupForClient dynamically resolves the policy group for a client request.
// It checks DoH ClientID mapping first, then exact IP, then CIDR ranges, and falls back to 'default'.
func (d *DB) GetGroupForClient(ctx context.Context, clientIP, clientID string) (*ClientGroup, error) {
	if !d.Enabled() {
		return d.GetGroupByName(ctx, "default")
	}

	clientID = strings.TrimSpace(clientID)
	clientIP = strings.TrimSpace(clientIP)

	// 1. Check DoH Client ID mapping
	if clientID != "" {
		var groupID int64
		err := d.db.QueryRowContext(ctx,
			"SELECT group_id FROM client_mappings WHERE mapping_type = 'client_id' AND value = ? LIMIT 1",
			clientID).Scan(&groupID)
		if err == nil {
			return d.GetGroup(ctx, groupID)
		}
	}

	// 2. Check exact IP mapping
	if clientIP != "" {
		var groupID int64
		err := d.db.QueryRowContext(ctx,
			"SELECT group_id FROM client_mappings WHERE mapping_type = 'ip' AND value = ? LIMIT 1",
			clientIP).Scan(&groupID)
		if err == nil {
			return d.GetGroup(ctx, groupID)
		}
	}

	// 3. Check CIDR mapping in high-performance RAM cache
	if clientIP != "" {
		ip := net.ParseIP(clientIP)
		if ip != nil {
			d.cidrMu.RLock()
			cache := d.cidrCache
			var matchedGroupID int64
			for _, entry := range cache {
				if entry.ipNet.Contains(ip) {
					matchedGroupID = entry.groupID
					break
				}
			}
			d.cidrMu.RUnlock()

			if matchedGroupID > 0 {
				return d.GetGroup(ctx, matchedGroupID)
			}
		}
	}

	// 4. Fallback to default group
	return d.GetGroupByName(ctx, "default")
}

// GetEffectiveOverride resolves allowed/blocked overrides specific to a policy group,
// falling back to Global local_overrides with intelligent subdomain inheritance.
func (d *DB) GetEffectiveOverride(ctx context.Context, groupID int64, domain string) (*Override, error) {
	if !d.Enabled() {
		return nil, nil
	}

	domain = strings.TrimSpace(strings.ToLower(domain))
	parts := strings.Split(domain, ".")

	// Traverse domain from specific to general: e.g. sub.example.com -> example.com -> com
	for i := 0; i < len(parts); i++ {
		candidate := strings.Join(parts[i:], ".")

		// A. Check Group Override first (Group preference)
		var goid, ggroupID int64
		var gdomain, gaction, greason, gcreated, gupdated string
		err := d.db.QueryRowContext(ctx, `
			SELECT id, group_id, domain, action, reason, created_at, updated_at
			FROM group_overrides WHERE group_id = ? AND domain = ?`,
			groupID, candidate).
			Scan(&goid, &ggroupID, &gdomain, &gaction, &greason, &gcreated, &gupdated)
		if err == nil {
			return &Override{
				ID:        goid,
				Domain:    gdomain,
				Action:    gaction,
				Reason:    greason,
				CreatedAt: gcreated,
				UpdatedAt: gupdated,
			}, nil
		}
		if err != sql.ErrNoRows {
			return nil, fmt.Errorf("query group override candidate %s: %w", candidate, err)
		}

		// B. Check Global Override second (Global inheritance fallback)
		var o Override
		err = d.db.QueryRowContext(ctx, `
			SELECT id, domain, action, reason, created_at, updated_at
			FROM local_overrides WHERE domain = ?`, candidate).
			Scan(&o.ID, &o.Domain, &o.Action, &o.Reason, &o.CreatedAt, &o.UpdatedAt)
		if err == nil {
			return &o, nil
		}
		if err != sql.ErrNoRows {
			return nil, fmt.Errorf("query global override candidate %s: %w", candidate, err)
		}
	}

	return nil, nil
}

func (d *DB) loadCIDRCache() error {
	if !d.Enabled() {
		return nil
	}

	rows, err := d.db.QueryContext(context.Background(), "SELECT group_id, value FROM client_mappings WHERE mapping_type = 'cidr'")
	if err != nil {
		return err
	}
	defer rows.Close()

	var cache []cidrMapping
	for rows.Next() {
		var groupID int64
		var cidrVal string
		if err := rows.Scan(&groupID, &cidrVal); err == nil {
			_, ipNet, err := net.ParseCIDR(cidrVal)
			if err == nil {
				cache = append(cache, cidrMapping{
					groupID: groupID,
					ipNet:   ipNet,
				})
			}
		}
	}

	sort.Slice(cache, func(i, j int) bool {
		s1, _ := cache[i].ipNet.Mask.Size()
		s2, _ := cache[j].ipNet.Mask.Size()
		return s1 > s2
	})

	d.cidrMu.Lock()
	d.cidrCache = cache
	d.cidrMu.Unlock()
	return nil
}

// CreateBlockReport creates a new block report entry.
func (d *DB) CreateBlockReport(ctx context.Context, domain, contact, note string) (int64, error) {
	if !d.Enabled() {
		return 0, fmt.Errorf("sqlite store disabled")
	}
	domain = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(domain)), ".")
	res, err := d.db.ExecContext(ctx, `
		INSERT INTO block_reports (domain, contact, note, status)
		VALUES (?, ?, ?, 'pending')`, domain, contact, note)
	if err != nil {
		return 0, fmt.Errorf("insert block report: %w", err)
	}
	return res.LastInsertId()
}

// ListBlockReports retrieves block reports with pagination.
func (d *DB) ListBlockReports(ctx context.Context, status string, limit, offset int) ([]BlockReport, error) {
	return d.ListBlockReportsFiltered(ctx, BlockReportFilter{Status: status}, limit, offset)
}

// ListBlockReportsFiltered retrieves block reports with filtering and pagination.
func (d *DB) ListBlockReportsFiltered(ctx context.Context, filter BlockReportFilter, limit, offset int) ([]BlockReport, error) {
	if !d.Enabled() {
		return nil, nil
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT id, domain, COALESCE(contact, ''), COALESCE(note, ''), status, created_at
		FROM block_reports `
	var args []any
	var clauses []string
	if filter.Status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, strings.TrimSpace(filter.Status))
	}
	if filter.Query != "" {
		needle := "%" + strings.ToLower(strings.TrimSpace(filter.Query)) + "%"
		clauses = append(clauses, "(LOWER(domain) LIKE ? OR LOWER(COALESCE(contact, '')) LIKE ? OR LOWER(COALESCE(note, '')) LIKE ?)")
		args = append(args, needle, needle, needle)
	}
	if len(clauses) > 0 {
		// #nosec G202 -- clauses are safely concatenated
		query += `WHERE ` + strings.Join(clauses, " AND ") + ` `
	}
	query += `ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := d.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list block reports: %w", err)
	}
	defer rows.Close()

	var reports []BlockReport
	for rows.Next() {
		var r BlockReport
		if err := rows.Scan(&r.ID, &r.Domain, &r.Contact, &r.Note, &r.Status, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan block report: %w", err)
		}
		reports = append(reports, r)
	}
	return reports, rows.Err()
}

// CountBlockReportsFiltered returns the total number of reports matching a filter.
// It is intentionally separate from ListBlockReportsFiltered so callers can paginate
// at the database layer without loading all matching reports into memory.
func (d *DB) CountBlockReportsFiltered(ctx context.Context, filter BlockReportFilter) (int, error) {
	if !d.Enabled() {
		return 0, nil
	}

	query := `SELECT COUNT(*) FROM block_reports `
	var args []any
	var clauses []string
	if filter.Status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, strings.TrimSpace(filter.Status))
	}
	if filter.Query != "" {
		needle := "%" + strings.ToLower(strings.TrimSpace(filter.Query)) + "%"
		clauses = append(clauses, "(LOWER(domain) LIKE ? OR LOWER(COALESCE(contact, '')) LIKE ? OR LOWER(COALESCE(note, '')) LIKE ?)")
		args = append(args, needle, needle, needle)
	}
	if len(clauses) > 0 {
		// #nosec G202 -- clauses are safely concatenated
		query += `WHERE ` + strings.Join(clauses, " AND ")
	}

	var total int
	if err := d.db.QueryRowContext(ctx, query, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("count block reports: %w", err)
	}
	return total, nil
}

// UpdateBlockReportStatus updates the status of a specific block report.
func (d *DB) UpdateBlockReportStatus(ctx context.Context, id int64, status string) error {
	if !d.Enabled() {
		return fmt.Errorf("sqlite store disabled")
	}
	_, err := d.db.ExecContext(ctx, `UPDATE block_reports SET status = ? WHERE id = ?`, status, id)
	if err != nil {
		return fmt.Errorf("update block report status: %w", err)
	}
	return nil
}

// ResolveBlockReportsForDomain marks all pending reports for a domain as resolved.
func (d *DB) ResolveBlockReportsForDomain(ctx context.Context, domain string) error {
	if !d.Enabled() {
		return fmt.Errorf("sqlite store disabled")
	}
	_, err := d.db.ExecContext(ctx, `UPDATE block_reports SET status = 'resolved' WHERE domain = ? AND status = 'pending'`, domain)
	return err
}

// GetSystemConfig retrieves the value of a system configuration key.
// Returns an empty string and nil error if not found.
func (d *DB) GetSystemConfig(ctx context.Context, key string) (string, error) {
	if !d.Enabled() {
		return "", fmt.Errorf("sqlite store disabled")
	}
	var value string
	err := d.db.QueryRowContext(ctx, `SELECT value FROM system_config WHERE key = ?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get system config for key %s: %w", key, err)
	}
	return value, nil
}

// SetSystemConfig sets the value of a system configuration key (upsert).
func (d *DB) SetSystemConfig(ctx context.Context, key, value string) error {
	if !d.Enabled() {
		return fmt.Errorf("sqlite store disabled")
	}
	_, err := d.db.ExecContext(ctx, `
		INSERT INTO system_config (key, value, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
	`, key, value)
	if err != nil {
		return fmt.Errorf("set system config for key %s: %w", key, err)
	}
	return nil
}

func (d *DB) GetAnalysisConfig(ctx context.Context) (*config.AnalysisConfig, error) {
	value, err := d.GetSystemConfig(ctx, "analysis_config")
	if err != nil || value == "" {
		return nil, err
	}
	var cfg config.AnalysisConfig
	if err := json.Unmarshal([]byte(value), &cfg); err != nil {
		return nil, fmt.Errorf("decode analysis config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate stored analysis config: %w", err)
	}
	cloned := cfg.Clone()
	return &cloned, nil
}

func (d *DB) SetAnalysisConfig(ctx context.Context, cfg config.AnalysisConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	encoded, err := json.Marshal(cfg.Clone())
	if err != nil {
		return fmt.Errorf("encode analysis config: %w", err)
	}
	return d.SetSystemConfig(ctx, "analysis_config", string(encoded))
}

func (d *DB) GetWhoisCache(ctx context.Context, domain string, now time.Time) (WhoisCacheEntry, bool, error) {
	if !d.Enabled() {
		return WhoisCacheEntry{}, false, fmt.Errorf("sqlite store disabled")
	}
	var (
		entry                   WhoisCacheEntry
		found, privacyGuard     int
		registeredDate, reasons string
		cachedAt, expiresAt     string
	)
	err := d.db.QueryRowContext(ctx, `
		SELECT domain, found, COALESCE(registered_date, ''), domain_age_days,
		       COALESCE(registrar, ''), privacy_guard, score, reasons,
		       COALESCE(raw_text, ''), cached_at, expires_at
		FROM whois_cache WHERE domain = ? AND expires_at > ?
	`, domain, now.UTC().Format(time.RFC3339Nano)).Scan(
		&entry.Domain, &found, &registeredDate, &entry.DomainAgeDays,
		&entry.Registrar, &privacyGuard, &entry.Score, &reasons,
		&entry.RawText, &cachedAt, &expiresAt,
	)
	if err == sql.ErrNoRows {
		return WhoisCacheEntry{}, false, nil
	}
	if err != nil {
		return WhoisCacheEntry{}, false, fmt.Errorf("get whois cache: %w", err)
	}
	entry.Found = found != 0
	entry.PrivacyGuard = privacyGuard != 0
	if registeredDate != "" {
		entry.RegisteredDate, _ = time.Parse(time.RFC3339Nano, registeredDate)
	}
	entry.CachedAt, _ = time.Parse(time.RFC3339Nano, cachedAt)
	entry.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expiresAt)
	if err := json.Unmarshal([]byte(reasons), &entry.Reasons); err != nil {
		return WhoisCacheEntry{}, false, fmt.Errorf("decode whois cache reasons: %w", err)
	}
	return entry, true, nil
}

func (d *DB) SetWhoisCache(ctx context.Context, domain string, entry WhoisCacheEntry, ttl time.Duration) error {
	if !d.Enabled() {
		return fmt.Errorf("sqlite store disabled")
	}
	if ttl <= 0 {
		return fmt.Errorf("whois cache ttl must be positive")
	}
	reasons, err := json.Marshal(entry.Reasons)
	if err != nil {
		return fmt.Errorf("encode whois cache reasons: %w", err)
	}
	now := time.Now().UTC()
	registeredDate := ""
	if !entry.RegisteredDate.IsZero() {
		registeredDate = entry.RegisteredDate.UTC().Format(time.RFC3339Nano)
	}
	_, err = d.db.ExecContext(ctx, `
		INSERT INTO whois_cache (
			domain, found, registered_date, domain_age_days, registrar,
			privacy_guard, score, reasons, raw_text, cached_at, expires_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET
			found = excluded.found,
			registered_date = excluded.registered_date,
			domain_age_days = excluded.domain_age_days,
			registrar = excluded.registrar,
			privacy_guard = excluded.privacy_guard,
			score = excluded.score,
			reasons = excluded.reasons,
			raw_text = excluded.raw_text,
			cached_at = excluded.cached_at,
			expires_at = excluded.expires_at
	`, domain, entry.Found, registeredDate, entry.DomainAgeDays, entry.Registrar,
		entry.PrivacyGuard, entry.Score, string(reasons), entry.RawText,
		now.Format(time.RFC3339Nano), now.Add(ttl).Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("set whois cache: %w", err)
	}
	return nil
}

// DatabaseStats holds SQLite database storage usage metrics.
type DatabaseStats struct {
	FileSizeMB float64 `json:"file_size_mb"`
	DiskFreeGB float64 `json:"disk_free_gb"`
}

// Stats computes SQLite database file size and free storage capacity.
func (d *DB) Stats(ctx context.Context) DatabaseStats {
	if !d.Enabled() || d.dbPath == "" {
		return DatabaseStats{}
	}

	var fileSize float64
	if fi, err := os.Stat(d.dbPath); err == nil {
		fileSize = float64(fi.Size()) / 1024.0 / 1024.0 // MB
	}

	freeSpace, err := getFreeDiskSpace(d.dbPath)
	if err != nil {
		// Degrade gracefully if OS permission issue occurs
		freeSpace = 0.0
	}

	return DatabaseStats{
		FileSizeMB: fileSize,
		DiskFreeGB: freeSpace,
	}
}

// GetRetentionDays returns the active telemetry retention days thread-safely.
func (d *DB) GetRetentionDays(ctx context.Context) int {
	if d == nil {
		return 30
	}
	d.configMu.RLock()
	defer d.configMu.RUnlock()
	return d.retentionDays
}

// UpdateRetentionDays updates the active telemetry retention days thread-safely.
func (d *DB) UpdateRetentionDays(ctx context.Context, days int) {
	if d == nil {
		return
	}
	if days <= 0 {
		days = 30
	}
	d.configMu.Lock()
	d.retentionDays = days
	d.configMu.Unlock()
}
