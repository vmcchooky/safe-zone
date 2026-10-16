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
	"sync"
	"sync/atomic"
	"time"

	// modernc.org/sqlite registers the "sqlite" database/sql driver as a
	// side effect; nothing here references the package directly.
	_ "modernc.org/sqlite"

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

// Whitelist import floor and lookups live in whitelist.go (third slice of the
// sqlite.go breakup; same package, no API change.)

// Multi-tenant policy groups, client mappings and group overrides live in
// groups.go (first slice of the sqlite.go breakup; same package, no API
// change).

// User block reports and operator reviews live in reports.go (fourth slice of
// the sqlite.go breakup; same package, no API change.)

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
