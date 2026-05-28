package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

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

// Stats contains aggregate telemetry statistics.
type Stats struct {
	Total      int64  `json:"total"`
	Safe       int64  `json:"safe"`
	Suspicious int64  `json:"suspicious"`
	Malicious  int64  `json:"malicious"`
	CacheHits  int64  `json:"cache_hits"`
	Period     string `json:"period"`
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

// DomainCount holds a domain and its occurrence count from audit queries.
type DomainCount struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
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
`

const telemetryBufferSize = 1000
const cleanupInterval = 1 * time.Hour

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

	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
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

	if err := d.SeedDefaultBrands(); err != nil {
		_ = sqlDB.Close() // #nosec G104 -- error path; primary error already captured
		return nil, fmt.Errorf("seed default brands: %w", err)
	}

	// Auto-initialize default groups
	if err := d.CreateDefaultGroups(); err != nil {
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
	_, err := d.db.Exec(
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
func (d *DB) QueryRecent(limit, offset int) ([]TelemetryEntry, error) {
	if !d.Enabled() {
		return nil, nil
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	rows, err := d.db.Query(
		`SELECT id, domain, verdict, score, confidence,
		        COALESCE(reasons, '[]'), cache_hit, COALESCE(source, ''),
		        analyzed_at, created_at, COALESCE(client_ip, ''), COALESCE(client_id, '')
		 FROM analysis_log ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
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

// QueryStats returns aggregate telemetry statistics since the given time.
func (d *DB) QueryStats(since time.Time) (Stats, error) {
	if !d.Enabled() {
		return Stats{}, nil
	}
	sinceStr := since.UTC().Format(time.RFC3339)
	row := d.db.QueryRow(`
		SELECT
			COUNT(*) AS total,
			COALESCE(SUM(CASE WHEN verdict = 'SAFE' THEN 1 ELSE 0 END), 0) AS safe,
			COALESCE(SUM(CASE WHEN verdict = 'SUSPICIOUS' THEN 1 ELSE 0 END), 0) AS suspicious,
			COALESCE(SUM(CASE WHEN verdict = 'MALICIOUS' THEN 1 ELSE 0 END), 0) AS malicious,
			COALESCE(SUM(cache_hit), 0) AS cache_hits
		FROM analysis_log WHERE analyzed_at >= ?`, sinceStr)

	var s Stats
	if err := row.Scan(&s.Total, &s.Safe, &s.Suspicious, &s.Malicious, &s.CacheHits); err != nil {
		return Stats{}, fmt.Errorf("query stats: %w", err)
	}
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
	cutoff := time.Now().AddDate(0, 0, -d.GetRetentionDays()).UTC().Format(time.RFC3339)
	result, err := d.db.Exec(`DELETE FROM analysis_log WHERE analyzed_at < ?`, cutoff)
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
}

// --- Overrides ---

// GetOverride checks if a domain (or any of its parent domains) has an override.
// Returns nil if no override is found.
func (d *DB) GetOverride(domain string) (*Override, error) {
	if !d.Enabled() {
		return nil, nil
	}
	// Check exact match and parent domains (e.g., mail.google.com → google.com → com).
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts); i++ {
		candidate := strings.Join(parts[i:], ".")
		var o Override
		err := d.db.QueryRow(
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
func (d *DB) ListOverrides(action string) ([]Override, error) {
	if !d.Enabled() {
		return nil, nil
	}

	var rows *sql.Rows
	var err error
	if action == "allow" || action == "block" {
		rows, err = d.db.Query(
			`SELECT id, domain, action, reason, created_at, updated_at
			 FROM local_overrides WHERE action = ? ORDER BY updated_at DESC`, action)
	} else {
		rows, err = d.db.Query(
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
func (d *DB) UpsertOverride(domain, action, reason string) error {
	if !d.Enabled() {
		return nil
	}
	if action != "allow" && action != "block" {
		return fmt.Errorf("invalid action %q: must be 'allow' or 'block'", action)
	}
	_, err := d.db.Exec(`
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
func (d *DB) DeleteOverride(domain string) error {
	if !d.Enabled() {
		return nil
	}
	result, err := d.db.Exec(`DELETE FROM local_overrides WHERE domain = ?`, domain)
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
func (d *DB) RecordAgentEvent(taskName, eventType, domain, details string) error {
	if !d.Enabled() {
		return nil
	}
	_, err := d.db.Exec(
		`INSERT INTO agent_audit_log (task_name, event_type, domain, details) VALUES (?, ?, ?, ?)`,
		taskName, eventType, domain, details,
	)
	if err != nil {
		return fmt.Errorf("record agent event: %w", err)
	}
	return nil
}

// QueryAgentEvents returns agent events since a given time, optionally filtered by event types.
func (d *DB) QueryAgentEvents(since time.Time, eventTypes []string, limit int) ([]AgentEvent, error) {
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
		rows, err = d.db.Query(query, args...)
	} else {
		rows, err = d.db.Query(
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
func (d *DB) QuerySuspiciousDomains(since time.Time, minOccurrences, limit int) ([]DomainCount, error) {
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
	rows, err := d.db.Query(`
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
func (d *DB) QueryRecentAllowedOrSuspiciousDomains(since time.Time, limit int) ([]DomainCount, error) {
	if !d.Enabled() {
		return nil, nil
	}
	if limit <= 0 {
		limit = 50
	}

	sinceStr := since.UTC().Format(time.RFC3339)
	rows, err := d.db.Query(`
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

func (d *DB) ReplaceOSINTEvidence(domain string, evidence []OSINTEvidence) error {
	if !d.Enabled() {
		return nil
	}
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return fmt.Errorf("domain is required")
	}

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("begin osint evidence transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM osint_evidence WHERE domain = ?`, domain); err != nil {
		return fmt.Errorf("delete old osint evidence: %w", err)
	}

	stmt, err := tx.Prepare(`
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
		if _, err := stmt.Exec(
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

func (d *DB) ListOSINTEvidence(domain string, now time.Time) ([]OSINTEvidence, error) {
	if !d.Enabled() {
		return nil, nil
	}
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	nowStr := now.UTC().Format(time.RFC3339Nano)
	rows, err := d.db.Query(`
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
func (d *DB) UpdateWhitelist(domains []string) error {
	if !d.Enabled() {
		return nil
	}

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("begin whitelist transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec("DELETE FROM whitelist_domains")
	if err != nil {
		return fmt.Errorf("delete old whitelist: %w", err)
	}

	stmt, err := tx.Prepare("INSERT OR IGNORE INTO whitelist_domains (domain) VALUES (?)")
	if err != nil {
		return fmt.Errorf("prepare whitelist insert: %w", err)
	}
	defer stmt.Close()

	for _, domain := range domains {
		if domain == "" {
			continue
		}
		if _, err := stmt.Exec(domain); err != nil {
			return fmt.Errorf("insert whitelist domain %s: %w", domain, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit whitelist transaction: %w", err)
	}

	return nil
}

// IsDomainWhitelisted checks if the domain exists exactly in the SQLite whitelist table.
func (d *DB) IsDomainWhitelisted(domain string) (bool, error) {
	if !d.Enabled() {
		return false, nil
	}

	var exists int
	err := d.db.QueryRow("SELECT 1 FROM whitelist_domains WHERE domain = ? LIMIT 1", domain).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check whitelist domain %s: %w", domain, err)
	}

	return true, nil
}

// GetWhitelist retrieves all domains in the SQLite whitelist table.
func (d *DB) GetWhitelist() ([]string, error) {
	if !d.Enabled() {
		return nil, nil
	}

	rows, err := d.db.Query("SELECT domain FROM whitelist_domains")
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
func (d *DB) CreateDefaultGroups() error {
	if !d.Enabled() {
		return nil
	}

	var exists int
	err := d.db.QueryRow("SELECT 1 FROM client_groups WHERE name = 'default'").Scan(&exists)
	if err == sql.ErrNoRows {
		_, err = d.db.Exec(`
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
func (d *DB) CreateGroup(name, description string, blockCategories []string, strictPhishing, strictMalware bool) (int64, error) {
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

	res, err := d.db.Exec(`
		INSERT INTO client_groups (name, description, block_categories, strict_phishing, strict_malware)
		VALUES (?, ?, ?, ?, ?)`,
		name, description, string(blockCatsJSON), sp, sm)
	if err != nil {
		return 0, fmt.Errorf("insert group %q: %w", name, err)
	}

	return res.LastInsertId()
}

// UpdateGroup updates an existing client policy group.
func (d *DB) UpdateGroup(id int64, name, description string, blockCategories []string, strictPhishing, strictMalware bool) error {
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

	_, err = d.db.Exec(`
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
func (d *DB) DeleteGroup(id int64) error {
	if !d.Enabled() {
		return fmt.Errorf("sqlite store disabled")
	}

	if id == 1 {
		return fmt.Errorf("cannot delete default policy group")
	}

	res, err := d.db.Exec("DELETE FROM client_groups WHERE id = ?", id)
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
func (d *DB) GetGroup(id int64) (*ClientGroup, error) {
	if !d.Enabled() {
		return nil, fmt.Errorf("sqlite store disabled")
	}

	var g ClientGroup
	var blockCatsJSON string
	var sp, sm int

	err := d.db.QueryRow(`
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
func (d *DB) GetGroupByName(name string) (*ClientGroup, error) {
	if !d.Enabled() {
		return nil, fmt.Errorf("sqlite store disabled")
	}

	var g ClientGroup
	var blockCatsJSON string
	var sp, sm int

	err := d.db.QueryRow(`
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
func (d *DB) ListGroups() ([]ClientGroup, error) {
	if !d.Enabled() {
		return nil, nil
	}

	rows, err := d.db.Query(`
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
func (d *DB) AddMapping(mappingType, value, groupID string) (int64, error) {
	// Group ID is actually an integer, parse it
	var groupIDInt int64
	_, err := fmt.Sscanf(groupID, "%d", &groupIDInt)
	if err != nil {
		// Try parsing from database fallback or direct call helper
		return 0, fmt.Errorf("invalid group id: %w", err)
	}
	return d.AddMappingInt(mappingType, value, groupIDInt)
}

// AddMappingInt maps a client with group ID integer.
func (d *DB) AddMappingInt(mappingType, value string, groupID int64) (int64, error) {
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
		if _, _, err := net.ParseCIDR(value); err != nil {
			return 0, fmt.Errorf("invalid CIDR format %q: %w", value, err)
		}
	}

	res, err := d.db.Exec(`
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
func (d *DB) DeleteMapping(id int64) error {
	if !d.Enabled() {
		return fmt.Errorf("sqlite store disabled")
	}

	res, err := d.db.Exec("DELETE FROM client_mappings WHERE id = ?", id)
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
func (d *DB) ListMappings() ([]ClientMapping, error) {
	if !d.Enabled() {
		return nil, nil
	}

	rows, err := d.db.Query(`
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
func (d *DB) UpsertGroupOverride(groupID int64, domain, action, reason string) error {
	if !d.Enabled() {
		return fmt.Errorf("sqlite store disabled")
	}

	if action != "allow" && action != "block" {
		return fmt.Errorf("invalid action %q: must be 'allow' or 'block'", action)
	}

	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return fmt.Errorf("override domain cannot be empty")
	}

	_, err := d.db.Exec(`
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
func (d *DB) DeleteGroupOverride(groupID int64, domain string) error {
	if !d.Enabled() {
		return fmt.Errorf("sqlite store disabled")
	}

	domain = strings.TrimSpace(strings.ToLower(domain))
	res, err := d.db.Exec("DELETE FROM group_overrides WHERE group_id = ? AND domain = ?", groupID, domain)
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
func (d *DB) ListGroupOverrides(groupID int64) ([]GroupOverride, error) {
	if !d.Enabled() {
		return nil, nil
	}

	rows, err := d.db.Query(`
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
func (d *DB) GetGroupForClient(clientIP, clientID string) (*ClientGroup, error) {
	if !d.Enabled() {
		return d.GetGroupByName("default")
	}

	clientID = strings.TrimSpace(clientID)
	clientIP = strings.TrimSpace(clientIP)

	// 1. Check DoH Client ID mapping
	if clientID != "" {
		var groupID int64
		err := d.db.QueryRow(
			"SELECT group_id FROM client_mappings WHERE mapping_type = 'client_id' AND value = ? LIMIT 1",
			clientID).Scan(&groupID)
		if err == nil {
			return d.GetGroup(groupID)
		}
	}

	// 2. Check exact IP mapping
	if clientIP != "" {
		var groupID int64
		err := d.db.QueryRow(
			"SELECT group_id FROM client_mappings WHERE mapping_type = 'ip' AND value = ? LIMIT 1",
			clientIP).Scan(&groupID)
		if err == nil {
			return d.GetGroup(groupID)
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
				return d.GetGroup(matchedGroupID)
			}
		}
	}

	// 4. Fallback to default group
	return d.GetGroupByName("default")
}

// GetEffectiveOverride resolves allowed/blocked overrides specific to a policy group,
// falling back to Global local_overrides with intelligent subdomain inheritance.
func (d *DB) GetEffectiveOverride(groupID int64, domain string) (*Override, error) {
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
		err := d.db.QueryRow(`
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
		err = d.db.QueryRow(`
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

	rows, err := d.db.Query("SELECT group_id, value FROM client_mappings WHERE mapping_type = 'cidr'")
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

	d.cidrMu.Lock()
	d.cidrCache = cache
	d.cidrMu.Unlock()
	return nil
}

// CreateBlockReport creates a new block report entry.
func (d *DB) CreateBlockReport(domain, contact, note string) (int64, error) {
	if !d.Enabled() {
		return 0, fmt.Errorf("sqlite store disabled")
	}
	res, err := d.db.Exec(`
		INSERT INTO block_reports (domain, contact, note, status)
		VALUES (?, ?, ?, 'pending')`, domain, contact, note)
	if err != nil {
		return 0, fmt.Errorf("insert block report: %w", err)
	}
	return res.LastInsertId()
}

// ListBlockReports retrieves block reports with pagination.
func (d *DB) ListBlockReports(limit, offset int) ([]BlockReport, error) {
	if !d.Enabled() {
		return nil, nil
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := d.db.Query(`
		SELECT id, domain, COALESCE(contact, ''), COALESCE(note, ''), status, created_at
		FROM block_reports ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
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

// UpdateBlockReportStatus updates the status of a specific block report.
func (d *DB) UpdateBlockReportStatus(id int64, status string) error {
	if !d.Enabled() {
		return fmt.Errorf("sqlite store disabled")
	}
	_, err := d.db.Exec(`UPDATE block_reports SET status = ? WHERE id = ?`, status, id)
	if err != nil {
		return fmt.Errorf("update block report status: %w", err)
	}
	return nil
}

// ResolveBlockReportsForDomain marks all pending reports for a domain as resolved.
func (d *DB) ResolveBlockReportsForDomain(domain string) error {
	if !d.Enabled() {
		return fmt.Errorf("sqlite store disabled")
	}
	_, err := d.db.Exec(`UPDATE block_reports SET status = 'resolved' WHERE domain = ? AND status = 'pending'`, domain)
	return err
}

// GetSystemConfig retrieves the value of a system configuration key.
// Returns an empty string and nil error if not found.
func (d *DB) GetSystemConfig(key string) (string, error) {
	if !d.Enabled() {
		return "", fmt.Errorf("sqlite store disabled")
	}
	var value string
	err := d.db.QueryRow(`SELECT value FROM system_config WHERE key = ?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get system config for key %s: %w", key, err)
	}
	return value, nil
}

// SetSystemConfig sets the value of a system configuration key (upsert).
func (d *DB) SetSystemConfig(key, value string) error {
	if !d.Enabled() {
		return fmt.Errorf("sqlite store disabled")
	}
	_, err := d.db.Exec(`
		INSERT INTO system_config (key, value, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
	`, key, value)
	if err != nil {
		return fmt.Errorf("set system config for key %s: %w", key, err)
	}
	return nil
}

// DatabaseStats holds SQLite database storage usage metrics.
type DatabaseStats struct {
	FileSizeMB float64 `json:"file_size_mb"`
	DiskFreeGB float64 `json:"disk_free_gb"`
}

// Stats computes SQLite database file size and free storage capacity.
func (d *DB) Stats() DatabaseStats {
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
func (d *DB) GetRetentionDays() int {
	if d == nil {
		return 30
	}
	d.configMu.RLock()
	defer d.configMu.RUnlock()
	return d.retentionDays
}

// UpdateRetentionDays updates the active telemetry retention days thread-safely.
func (d *DB) UpdateRetentionDays(days int) {
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

