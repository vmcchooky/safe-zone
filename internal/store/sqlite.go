package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	// modernc.org/sqlite registers the "sqlite" database/sql driver as a
	// side effect; nothing here references the package directly.
	_ "modernc.org/sqlite"

	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
	"safe-zone/internal/logjson"
)

// TelemetryEntry represents a single domain analysis record.
type TelemetryEntry struct {
	ID             int64    `json:"id,omitempty"`
	Domain         string   `json:"domain"`
	Verdict        string   `json:"verdict"`
	Score          int      `json:"score"`
	Confidence     float64  `json:"confidence"`
	Reasons        []string `json:"reasons"`
	CacheHit       bool     `json:"cache_hit"`
	Source         string   `json:"source"`
	PolicyAction   string   `json:"policy_action,omitempty"`
	PolicyCategory string   `json:"policy_category,omitempty"`
	DecisionID     string   `json:"decision_id,omitempty"`
	Trace          string   `json:"trace,omitempty"`
	AnalyzedAt     string   `json:"analyzed_at"`
	CreatedAt      string   `json:"created_at,omitempty"`
	ClientIP       string   `json:"client_ip,omitempty"`
	ClientID       string   `json:"client_id,omitempty"`
}

// TelemetryFilter constrains recent telemetry queries at the SQL layer.
type TelemetryFilter struct {
	Verdict string    `json:"verdict,omitempty"`
	Source  string    `json:"source,omitempty"`
	Domain  string    `json:"domain,omitempty"`
	Since   time.Time `json:"since,omitempty"`
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
	ID               int64  `json:"id"`
	Domain           string `json:"domain"`
	Contact          string `json:"contact"`
	Note             string `json:"note"`
	Status           string `json:"status"`
	CreatedAt        string `json:"created_at"`
	ReviewReason     string `json:"review_reason"`
	ReviewedBy       string `json:"reviewed_by"`
	ReviewedAt       string `json:"reviewed_at"`
	ResolutionAction string `json:"resolution_action"`
}

// BlockReportStatusCounts summarizes the operator queue by workflow state.
type BlockReportStatusCounts struct {
	Pending  int `json:"pending"`
	Resolved int `json:"resolved"`
	Rejected int `json:"rejected"`
}

var (
	ErrBlockReportNotFound       = errors.New("block report not found")
	ErrBlockReportDomainMismatch = errors.New("block report domain mismatch")
)

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

// DB wraps a SQLite connection with telemetry and override capabilities.
type DB struct {
	db            *sql.DB
	dbPath        string
	telemetryCh   chan TelemetryEntry
	retentionDays int
	// writePercent controls what fraction of analysis telemetry entries are
	// actually persisted (0-100). Defaults to 100 so behavior is unchanged;
	// high-traffic deployments can lower it to bound SQLite growth.
	writePercent int32
	sampleSeq    atomic.Uint64
	configMu     sync.RWMutex
	done         chan struct{}
	closeOnce    sync.Once
	closed       atomic.Bool
	wg           sync.WaitGroup

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
    policy_action TEXT DEFAULT '',
    policy_category TEXT DEFAULT '',
    decision_id TEXT DEFAULT '',
    trace TEXT DEFAULT '{}',
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

CREATE TABLE IF NOT EXISTS agent_proposals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_name TEXT NOT NULL DEFAULT 'audit',
    domain TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('allow', 'block')),
    score INTEGER NOT NULL DEFAULT 0,
    confidence REAL NOT NULL DEFAULT 0,
    reasons TEXT NOT NULL DEFAULT '[]',
    evidence TEXT NOT NULL DEFAULT '{}',
    actor TEXT NOT NULL DEFAULT '',
    scope TEXT NOT NULL DEFAULT 'exact',
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected', 'expired')),
    expires_at TEXT NOT NULL,
    reviewer TEXT DEFAULT '',
    review_reason TEXT DEFAULT '',
    reviewed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_agent_proposals_status ON agent_proposals(status);
CREATE INDEX IF NOT EXISTS idx_agent_proposals_domain ON agent_proposals(domain);

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

CREATE TABLE IF NOT EXISTS admin_sessions (
    session_fingerprint TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions(expires_at);

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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    review_reason TEXT NOT NULL DEFAULT '',
    reviewed_by TEXT NOT NULL DEFAULT '',
    reviewed_at TEXT NOT NULL DEFAULT '',
    resolution_action TEXT NOT NULL DEFAULT ''
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

CREATE TABLE IF NOT EXISTS url_ml_feedback (
    fp TEXT PRIMARY KEY,
    key_version INTEGER NOT NULL DEFAULT 1,
    probability_bucket INTEGER NOT NULL DEFAULT -1,
    would_promote INTEGER NOT NULL DEFAULT 0,
    labeled INTEGER NOT NULL DEFAULT 0,
    label_malicious INTEGER NOT NULL DEFAULT 0,
    recorded_at TEXT NOT NULL,
    labeled_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_url_ml_feedback_recorded ON url_ml_feedback(recorded_at);
CREATE INDEX IF NOT EXISTS idx_url_ml_feedback_labeled ON url_ml_feedback(labeled);
`

const telemetryBufferSize = 1000
const cleanupInterval = 1 * time.Hour
const whitelistInsertChunkSize = 500

// New opens a SQLite database at the given path, runs migrations, and starts
// background goroutines for async telemetry writes and periodic cleanup.
// If path is empty, returns nil (disabled mode).

// New opens the database, applies pragmas, creates the schema and starts the
// background goroutines for async telemetry writes and periodic cleanup.
// If path is empty, returns nil (disabled mode).
func New(path string, retentionDays int) (*DB, error) {
	if path == "" {
		return nil, nil
	}
	if clamped, changed := ClampRetentionDays(retentionDays); changed {
		logjson.Warn("telemetry retention out of range; clamped", map[string]any{
			"service": "store",
			"given":   retentionDays,
			"applied": clamped,
			"reason":  "a value above the ceiling produces a cutoff so old that the prune matches nothing",
		})
		retentionDays = clamped
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("create sqlite directory %s: %w", dir, err)
		}
	}

	// _txlock=immediate makes every explicit transaction take the write lock up
	// front instead of upgrading later. A deferred transaction that has already
	// read cannot wait for a writer, so it fails immediately with SQLITE_BUSY
	// rather than honouring busy_timeout.
	//
	// The honest cost: this is connection-level, so it also makes read-only
	// transactions serialise from BEGIN against other connections. Measured on
	// this workload — two handles on one file, 200 concurrent whitelist
	// imports — the latency difference was not observable (p99 629us patched
	// vs 649us baseline) and neither side reported a busy error, because the
	// deployment runs a single connection and one writer at a time. It would
	// matter for a multi-writer workload, which this is not.
	sqlDB, err := sql.Open("sqlite", path+"?_txlock=immediate")
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	// Single pooled connection: PRAGMAs below (busy_timeout, foreign_keys,
	// synchronous, cache_size) apply per-connection in SQLite, so a second
	// pooled connection would run with busy_timeout 0 and surface
	// SQLITE_BUSY under concurrent writers (telemetry background writer
	// racing an operator transaction) instead of waiting. Serializing all
	// queries through one connection keeps every pragma effective; the
	// workload is indexed point queries on a single VPS, so this costs
	// negligible latency and removes the whole lock-contention class.
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0) // reuse indefinitely

	// Apply performance pragmas.
	//
	// busy_timeout comes first, deliberately. journal_mode=WAL needs a write
	// lock, and when a second connection opens an existing WAL database it can
	// find that lock held — at which point a busy_timeout set afterwards would
	// be no help at all. Setting it first means every subsequent statement can
	// actually wait. The ordering here was the reverse, which is why opening a
	// second handle on the same file could fail with SQLITE_BUSY.
	pragmas := []string{
		"PRAGMA busy_timeout=5000",
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA cache_size=-8000",
		"PRAGMA foreign_keys=ON",
		// Incremental vacuum lets cleanup() return freelist pages without
		// a full blocking rebuild on every cycle. It only takes effect
		// for databases created after it is set; existing files are
		// converted once below.
		"PRAGMA auto_vacuum=INCREMENTAL",
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

	// Extend databases created before policy decisions were persisted
	// alongside security verdicts. Empty defaults keep legacy rows
	// readable as "no content-policy involved".
	policyColumns := []struct {
		name string
		sql  string
	}{
		{"policy_action", "ALTER TABLE analysis_log ADD COLUMN policy_action TEXT DEFAULT ''"},
		{"policy_category", "ALTER TABLE analysis_log ADD COLUMN policy_category TEXT DEFAULT ''"},
		{"decision_id", "ALTER TABLE analysis_log ADD COLUMN decision_id TEXT DEFAULT ''"},
		{"trace", "ALTER TABLE analysis_log ADD COLUMN trace TEXT DEFAULT '{}'"},
	}
	logColumns := make(map[string]bool)
	logRows, logErr := sqlDB.Query("PRAGMA table_info(analysis_log)")
	if logErr != nil {
		_ = sqlDB.Close() // #nosec G104 -- error path; primary error already captured
		return nil, fmt.Errorf("inspect analysis_log schema: %w", logErr)
	}
	for logRows.Next() {
		var cid int
		var name, columnType string
		var notNull int
		var defaultValue any
		var primaryKey int
		if err := logRows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = logRows.Close() // #nosec G104 -- error path; primary error already captured
			_ = sqlDB.Close()
			return nil, fmt.Errorf("scan analysis_log schema: %w", err)
		}
		logColumns[name] = true
	}
	if err := logRows.Err(); err != nil {
		_ = logRows.Close() // #nosec G104 -- error path; primary error already captured
		_ = sqlDB.Close()
		return nil, fmt.Errorf("read analysis_log schema: %w", err)
	}
	_ = logRows.Close() // #nosec G104 -- rows read successfully; close error is non-critical
	for _, migration := range policyColumns {
		if logColumns[migration.name] {
			continue
		}
		if _, err := sqlDB.Exec(migration.sql); err != nil {
			_ = sqlDB.Close()
			return nil, fmt.Errorf("migrate analysis_log column %s: %w", migration.name, err)
		}
	}
	blockReportColumns := make(map[string]bool)
	rows, err = sqlDB.Query("PRAGMA table_info(block_reports)")
	if err != nil {
		_ = sqlDB.Close() // #nosec G104 -- error path; primary error already captured
		return nil, fmt.Errorf("inspect block_reports schema: %w", err)
	}
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull int
		var defaultValue any
		var primaryKey int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close() // #nosec G104 -- error path; primary error already captured
			_ = sqlDB.Close()
			return nil, fmt.Errorf("scan block_reports schema: %w", err)
		}
		blockReportColumns[name] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close() // #nosec G104 -- error path; primary error already captured
		_ = sqlDB.Close()
		return nil, fmt.Errorf("read block_reports schema: %w", err)
	}
	_ = rows.Close() // #nosec G104 -- rows read successfully; close error is non-critical

	blockReportMigrations := []struct {
		name string
		sql  string
	}{
		{"review_reason", "ALTER TABLE block_reports ADD COLUMN review_reason TEXT NOT NULL DEFAULT ''"},
		{"reviewed_by", "ALTER TABLE block_reports ADD COLUMN reviewed_by TEXT NOT NULL DEFAULT ''"},
		{"reviewed_at", "ALTER TABLE block_reports ADD COLUMN reviewed_at TEXT NOT NULL DEFAULT ''"},
		{"resolution_action", "ALTER TABLE block_reports ADD COLUMN resolution_action TEXT NOT NULL DEFAULT ''"},
	}
	for _, migration := range blockReportMigrations {
		if blockReportColumns[migration.name] {
			continue
		}
		if _, err := sqlDB.Exec(migration.sql); err != nil {
			_ = sqlDB.Close() // #nosec G104 -- error path; primary error already captured
			return nil, fmt.Errorf("migrate block_reports column %s: %w", migration.name, err)
		}
	}

	// Load custom retentionDays if stored in database. Clamped for the same
	// reason as the constructor argument: a database that already holds an
	// absurd value would otherwise reapply it on every restart, with pruning
	// silently matching nothing.
	var customRetentionStr string
	_ = sqlDB.QueryRow(`SELECT value FROM system_config WHERE key = 'telemetry_retention_days'`).Scan(&customRetentionStr)
	if customRetentionStr != "" {
		if val, err := strconv.Atoi(customRetentionStr); err == nil && val > 0 {
			if clamped, changed := ClampRetentionDays(val); changed {
				logjson.Warn("stored telemetry retention out of range; clamped at boot", map[string]any{
					"service": "store",
					"given":   val,
					"applied": clamped,
					"reason":  "a value above the ceiling produces a cutoff so old that the prune matches nothing",
				})
				retentionDays = clamped
			} else {
				retentionDays = val
			}
		}
	}

	// Telemetry write sampling: persist only a fraction of analysis records.
	// Defaults to 100% (unchanged behavior); bounded-traffic deployments can
	// lower it to cap SQLite growth at high request rates.
	writePercent := 100
	if v := os.Getenv("SAFE_ZONE_TELEMETRY_WRITE_PERCENT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 100 {
			writePercent = n
		}
	}

	d := &DB{
		db:            sqlDB,
		dbPath:        path,
		telemetryCh:   make(chan TelemetryEntry, telemetryBufferSize),
		retentionDays: retentionDays,
		writePercent:  int32(writePercent),
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

	// One-time conversion of pre-existing database files to incremental
	// vacuum. A full VACUUM rewrites the file, so it runs once, guarded
	// by a system_config flag, and never on the request path.
	if err := d.ensureIncrementalVacuum(context.Background()); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}

	d.wg.Add(2)
	go d.telemetryWriter()
	go d.cleanupLoop()

	logjson.Info("sqlite store opened", map[string]any{
		"service":        "store",
		"path":           path,
		"retention_days": retentionDays,
		"write_percent":  writePercent,
	})
	return d, nil
}

// Close stops background goroutines and closes the database. It is
// idempotent: a second call is a no-op so layered owners (risk service,
// tests) can each close safely.
func (d *DB) Close() error {
	if d == nil {
		return nil
	}
	d.closeOnce.Do(func() {
		d.closed.Store(true)
		close(d.done)
	})
	d.wg.Wait()
	if d.db == nil {
		return nil
	}
	return d.db.Close()
}

// Enabled reports whether the store can serve reads and writes. It is the single
// check callers use instead of touching the handle, and it is deliberately
// cheap: the decision-path handlers call it on every request.
//
// Callers must not treat this as sufficient on its own. The store can be closed
// between the check and the call, which is why methods re-check internally and
// return ErrDisabled rather than panicking on a closed handle.
func (d *DB) Enabled() bool {
	return d != nil && d.db != nil && !d.closed.Load()
}

// --- Telemetry ---

// sampleAccept reports whether sequence number seq should be persisted for
// the given write percentage (0-100). Pure function so the distribution can
// be unit-tested exhaustively; uses a splitmix64-style finalizer so that
// consecutive sequence numbers scatter uniformly across the acceptance range.
func sampleAccept(seq uint64, percent int) bool {
	if percent >= 100 {
		return true
	}
	if percent <= 0 {
		return false
	}
	h := seq
	h ^= h >> 30
	h *= 0xbf58476d1ce4e5b9
	h ^= h >> 27
	h *= 0x94d049bb133111eb
	h ^= h >> 31
	return int(h%10000) < percent*100
}

// Telemetry ingestion and queries live in telemetry.go (second slice of the
// sqlite.go breakup; same package, no API change.)

// --- Whitelist ---

// UpdateWhitelist clears the existing whitelist and inserts a new set of domains
// in a single highly optimized transaction.
// ErrWhitelistBelowFloor reports an import that would leave the whitelist
// smaller than the configured floor allows. The live set is untouched, so the
// caller can retry, fall back, or raise an alert without having caused an
// outage by trying.
var ErrWhitelistBelowFloor = errors.New("whitelist import below safety floor")

const (
	// defaultWhitelistMinAbsolute is the floor used when the operator has not
	// set one. It is low enough to let a genuinely small whitelist through and
	// high enough to catch a download that produced nothing.
	defaultWhitelistMinAbsolute = 100
	// defaultWhitelistMinRelative is the percentage of the previous set that a
	// replacement must reach. 50 allows a legitimate halving while rejecting
	// the cliff-edge drops that a format change or a truncated body produce.
	defaultWhitelistMinRelative = 50
)

func (d *DB) whitelistMinAbsolute() int {
	value := config.Int("SAFE_ZONE_WHITELIST_MIN_ENTRIES", defaultWhitelistMinAbsolute)
	if value < 0 {
		return 0
	}
	return value
}

func (d *DB) whitelistMinRelative() int {
	value := config.Int("SAFE_ZONE_WHITELIST_MIN_PERCENT", defaultWhitelistMinRelative)
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func (d *DB) UpdateWhitelist(ctx context.Context, domains []string) error {
	if !d.Enabled() {
		return ErrDisabled
	}

	// Entries that are a public suffix ("com", "co.uk", "github.io") are not
	// registrable domains, so they are never a legitimate entry. But the
	// runtime matches a whitelist entry against the domain *and its parents*,
	// so a stored "com" answers true for every .com domain and the request
	// comes back "whitelisted" — which short-circuits the threat feed, lexical
	// scoring, ML, AI, OSINT and group enforcement. One bad line in an
	// otherwise valid list silently disables protection for a whole namespace.
	//
	// The filter lives here rather than in the callers because this is the one
	// function every ingest path goes through: the operator's file import in
	// risk.Whitelist.LoadFromFile, and the agent's whitelist_update task,
	// which downloads from an operator-configured URL and previously wrote
	// straight to this method with no validation at all. Validating at the
	// storage boundary means a new caller cannot forget.
	//
	// risk.Whitelist.LoadFromFile also filters, so the count it logs is
	// unaffected: filtering an already-filtered list is a no-op.
	accepted := make([]string, 0, len(domains))
	dropped := 0
	for _, domain := range domains {
		if analysis.IsRegistrableDomain(domain) {
			accepted = append(accepted, domain)
			continue
		}
		dropped++
	}
	if dropped > 0 {
		logjson.Warn("dropped unsafe whitelist entries", map[string]any{
			"service":  "store",
			"dropped":  dropped,
			"accepted": len(accepted),
			"reason":   "entry is a public suffix or has no registrable label, and would allowlist every domain beneath it",
		})
	}

	// Poison floor.
	//
	// This table is a safety valve: a domain on it is reported SAFE and the
	// request never reaches the threat feed, lexical scoring, ML, AI, OSINT or
	// group enforcement. So wiping it is not a partial degradation, it is a
	// total loss of protection for every domain that was on it — which is
	// exactly what an empty or truncated download produces. A captive portal
	// page, a gzip bomb that unzips to nothing, an HTTP error body, or a
	// source that silently changes format all land here as "zero domains".
	//
	// The threat-feed path already refuses to replace a live set with zero
	// valid entries (feed.Sync); this is the same guard for the whitelist.
	//
	// It applies only when there is something to lose. An empty previous set
	// means the whitelist was not protecting anything, so a first import of any
	// size — including none — removes no protection and is accepted. That keeps
	// the floor out of the way of a small hand-written list while still
	// catching the cliff-edge drop that breaks a real deployment.
	//
	// Once populated, two conditions must hold: an absolute floor (a source
	// that held a million entries and now returns twelve is not a smaller
	// whitelist, it is a broken one) and a relative floor (so a legitimate
	// reshrink, such as the operator retiring a source, stays possible).
	//
	// A rejected import leaves the live set exactly as it was.
	previous, countErr := d.GetWhitelistCount(ctx)
	if countErr != nil {
		return fmt.Errorf("read current whitelist size before replace: %w", countErr)
	}
	if previous > 0 {
		minAbsolute := d.whitelistMinAbsolute()
		minRelative := d.whitelistMinRelative()
		if len(accepted) < minAbsolute {
			// Say why the number is low. The public-suffix filter runs first and
			// only records its drop count in a log line the caller cannot see, so
			// without this an operator reading the error sees "0 usable
			// entries" and has no way to tell an empty download from a source
			// that was entirely rejected as unsafe.
			reason := ""
			if dropped > 0 {
				reason = fmt.Sprintf(" (%d dropped: public suffix or no registrable label)", dropped)
			}
			return fmt.Errorf("%w: source returned %d usable entries%s, floor is %d; the live whitelist of %d entries is unchanged",
				ErrWhitelistBelowFloor, len(accepted), reason, minAbsolute, previous)
		}
		if len(accepted)*100 < previous*minRelative {
			return fmt.Errorf("%w: source returned %d entries, a drop from %d (floor is %d%%); the live whitelist is unchanged",
				ErrWhitelistBelowFloor, len(accepted), previous, minRelative)
		}
	}

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin whitelist transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx, "DELETE FROM whitelist_domains")
	if err != nil {
		return fmt.Errorf("delete old whitelist: %w", err)
	}

	for start := 0; start < len(accepted); start += whitelistInsertChunkSize {
		end := start + whitelistInsertChunkSize
		if end > len(accepted) {
			end = len(accepted)
		}

		query, args := buildWhitelistInsertQuery(accepted[start:end])
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
		return false, ErrDisabled
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
		return 0, ErrDisabled
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
	defer func() { _ = rows.Close() }()

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
		return nil, ErrDisabled
	}

	rows, err := d.db.QueryContext(ctx, "SELECT domain FROM whitelist_domains")
	if err != nil {
		return nil, fmt.Errorf("query whitelist domains: %w", err)
	}
	defer func() { _ = rows.Close() }()

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

// Multi-tenant policy groups, client mappings and group overrides live in
// groups.go (first slice of the sqlite.go breakup; same package, no API
// change).

// CreateBlockReport creates a new block report entry.
func (d *DB) CreateBlockReport(ctx context.Context, domain, contact, note string) (int64, error) {
	if !d.Enabled() {
		return 0, ErrDisabled
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

// CreateBlockReportWithAudit persists the queue item and its intake event as a
// single transaction so callers never observe only half of the submission.
func (d *DB) CreateBlockReportWithAudit(
	ctx context.Context,
	domain, contact, note string,
	auditDetails map[string]any,
) (int64, error) {
	if !d.Enabled() {
		return 0, ErrDisabled
	}
	domain = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(domain)), ".")

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin block report submission: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	result, err := tx.ExecContext(ctx, `
		INSERT INTO block_reports (domain, contact, note, status)
		VALUES (?, ?, ?, 'pending')`, domain, contact, note)
	if err != nil {
		return 0, fmt.Errorf("insert block report: %w", err)
	}
	reportID, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("read block report ID: %w", err)
	}

	details := make(map[string]any, len(auditDetails)+1)
	for key, value := range auditDetails {
		details[key] = value
	}
	details["report_id"] = reportID
	encodedDetails, err := json.Marshal(details)
	if err != nil {
		return 0, fmt.Errorf("marshal block report audit: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO agent_audit_log (task_name, event_type, domain, details) VALUES (?, ?, ?, ?)`,
		"block_page", "false_positive_report", domain, string(encodedDetails),
	); err != nil {
		return 0, fmt.Errorf("record block report audit: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit block report submission: %w", err)
	}
	return reportID, nil
}

// ListBlockReports retrieves block reports with pagination.
func (d *DB) ListBlockReports(ctx context.Context, status string, limit, offset int) ([]BlockReport, error) {
	return d.ListBlockReportsFiltered(ctx, BlockReportFilter{Status: status}, limit, offset)
}

// ListBlockReportsFiltered retrieves block reports with filtering and pagination.
func (d *DB) ListBlockReportsFiltered(ctx context.Context, filter BlockReportFilter, limit, offset int) ([]BlockReport, error) {
	if !d.Enabled() {
		return nil, ErrDisabled
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT id, domain, COALESCE(contact, ''), COALESCE(note, ''), status, created_at,
		       COALESCE(review_reason, ''), COALESCE(reviewed_by, ''),
		       COALESCE(reviewed_at, ''), COALESCE(resolution_action, '')
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
	defer func() { _ = rows.Close() }()

	var reports []BlockReport
	for rows.Next() {
		var r BlockReport
		if err := rows.Scan(
			&r.ID,
			&r.Domain,
			&r.Contact,
			&r.Note,
			&r.Status,
			&r.CreatedAt,
			&r.ReviewReason,
			&r.ReviewedBy,
			&r.ReviewedAt,
			&r.ResolutionAction,
		); err != nil {
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
		return 0, ErrDisabled
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

// CountBlockReportsByStatus summarizes all reports by workflow status.
func (d *DB) CountBlockReportsByStatus(ctx context.Context) (BlockReportStatusCounts, error) {
	if !d.Enabled() {
		return BlockReportStatusCounts{}, ErrDisabled
	}

	var counts BlockReportStatusCounts
	err := d.db.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END), 0)
		FROM block_reports`).Scan(&counts.Pending, &counts.Resolved, &counts.Rejected)
	if err != nil {
		return BlockReportStatusCounts{}, fmt.Errorf("count block reports by status: %w", err)
	}
	return counts, nil
}

// ReviewBlockReport records an operator decision and its audit event atomically.
func (d *DB) ReviewBlockReport(ctx context.Context, id int64, status, reason, reviewer, resolutionAction string) error {
	if !d.Enabled() {
		return ErrDisabled
	}

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin block report review: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var domain, previousStatus string
	if err := tx.QueryRowContext(ctx, `SELECT domain, status FROM block_reports WHERE id = ?`, id).Scan(&domain, &previousStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrBlockReportNotFound
		}
		return fmt.Errorf("load block report for review: %w", err)
	}

	result, err := tx.ExecContext(ctx, `
		UPDATE block_reports
		SET status = ?, review_reason = ?, reviewed_by = ?, reviewed_at = datetime('now'), resolution_action = ?
		WHERE id = ?`, status, reason, reviewer, resolutionAction, id)
	if err != nil {
		return fmt.Errorf("update block report review: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return fmt.Errorf("confirm block report review: %w", err)
		}
		return ErrBlockReportNotFound
	}

	details, err := json.Marshal(map[string]any{
		"report_id":         id,
		"previous_status":   previousStatus,
		"status":            status,
		"review_reason":     reason,
		"reviewed_by":       reviewer,
		"resolution_action": resolutionAction,
	})
	if err != nil {
		return fmt.Errorf("marshal block report review audit: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO agent_audit_log (task_name, event_type, domain, details) VALUES (?, ?, ?, ?)`,
		"operator_review", "operator_report_review", domain, string(details),
	); err != nil {
		return fmt.Errorf("record block report review audit: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit block report review: %w", err)
	}
	return nil
}

// GetBlockReport loads one user report by ID for review routing.
func (d *DB) GetBlockReport(ctx context.Context, id int64) (BlockReport, error) {
	if !d.Enabled() {
		return BlockReport{}, ErrDisabled
	}

	var report BlockReport
	err := d.db.QueryRowContext(ctx, `
		SELECT id, domain, contact, note, status, created_at,
			review_reason, reviewed_by, reviewed_at, resolution_action
		FROM block_reports WHERE id = ?`, id).Scan(
		&report.ID, &report.Domain, &report.Contact, &report.Note, &report.Status,
		&report.CreatedAt, &report.ReviewReason, &report.ReviewedBy,
		&report.ReviewedAt, &report.ResolutionAction,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return BlockReport{}, ErrBlockReportNotFound
		}
		return BlockReport{}, fmt.Errorf("load block report: %w", err)
	}
	return report, nil
}

// ApproveFalsePositive creates the allow override, updates related reports, and
// records the operator decision as one transaction. reportID is optional to
// preserve the existing review endpoint contract for reviews started elsewhere.
func (d *DB) ApproveFalsePositive(
	ctx context.Context,
	reportID int64,
	domain, overrideReason, reviewReason, reviewer, source, previousAction string,
) (int64, error) {
	if !d.Enabled() {
		return 0, ErrDisabled
	}

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin false-positive review: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if reportID > 0 {
		var reportDomain string
		if err := tx.QueryRowContext(ctx, `SELECT domain FROM block_reports WHERE id = ?`, reportID).Scan(&reportDomain); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return 0, ErrBlockReportNotFound
			}
			return 0, fmt.Errorf("load false-positive report: %w", err)
		}
		if reportDomain != domain {
			return 0, ErrBlockReportDomainMismatch
		}
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO local_overrides (domain, action, reason, updated_at)
		VALUES (?, 'allow', ?, datetime('now'))
		ON CONFLICT(domain) DO UPDATE SET
			action = 'allow',
			reason = excluded.reason,
			updated_at = datetime('now')`, domain, overrideReason); err != nil {
		return 0, fmt.Errorf("upsert false-positive allow override: %w", err)
	}

	var result sql.Result
	if reportID > 0 {
		result, err = tx.ExecContext(ctx, `
			UPDATE block_reports
			SET status = 'resolved', review_reason = ?, reviewed_by = ?, reviewed_at = datetime('now'), resolution_action = 'allow'
			WHERE domain = ? AND (status = 'pending' OR id = ?)`, reviewReason, reviewer, domain, reportID)
	} else {
		result, err = tx.ExecContext(ctx, `
			UPDATE block_reports
			SET status = 'resolved', review_reason = ?, reviewed_by = ?, reviewed_at = datetime('now'), resolution_action = 'allow'
			WHERE domain = ? AND status = 'pending'`, reviewReason, reviewer, domain)
	}
	if err != nil {
		return 0, fmt.Errorf("resolve false-positive reports: %w", err)
	}
	resolvedReports, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count resolved false-positive reports: %w", err)
	}

	details, err := json.Marshal(map[string]any{
		"report_id":        reportID,
		"source":           source,
		"review_reason":    reviewReason,
		"reviewed_by":      reviewer,
		"previous_action":  previousAction,
		"resolved_action":  "allow",
		"resolved_reports": resolvedReports,
	})
	if err != nil {
		return 0, fmt.Errorf("marshal false-positive review audit: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO agent_audit_log (task_name, event_type, domain, details) VALUES (?, ?, ?, ?)`,
		"operator_review", "operator_false_positive_review", domain, string(details),
	); err != nil {
		return 0, fmt.Errorf("record false-positive review audit: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit false-positive review: %w", err)
	}
	return resolvedReports, nil
}

// GetSystemConfig retrieves the value of a system configuration key.
// Returns an empty string and nil error if not found.
func (d *DB) GetSystemConfig(ctx context.Context, key string) (string, error) {
	if !d.Enabled() {
		return "", ErrDisabled
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
		return ErrDisabled
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
		return WhoisCacheEntry{}, false, ErrDisabled
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
		return ErrDisabled
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
