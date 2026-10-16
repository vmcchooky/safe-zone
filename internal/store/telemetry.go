package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/logjson"
)

// Telemetry ingestion, analysis queries, agent events and OSINT evidence live
// here. sqlite.go keeps connection lifecycle, schema/migrations, retention/vacuum,
// whitelist, reports and config. Remaining slices: whitelist, reports, retention.

// RecordAnalysis enqueues a telemetry entry for async writing.
// Non-blocking: if the buffer is full, the entry is silently dropped.
// When write sampling is enabled (SAFE_ZONE_TELEMETRY_WRITE_PERCENT < 100),
// entries are uniformly skipped so sustained high traffic cannot outgrow disk.
func (d *DB) RecordAnalysis(entry TelemetryEntry) {
	if !d.Enabled() {
		return
	}
	if d.writePercent < 100 {
		if !sampleAccept(d.sampleSeq.Add(1), int(d.writePercent)) {
			return
		}
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
		`INSERT INTO analysis_log (domain, verdict, score, confidence, reasons, cache_hit, source, policy_action, policy_category, decision_id, trace, analyzed_at, client_ip, client_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.Domain, entry.Verdict, entry.Score, entry.Confidence,
		string(reasonsJSON), cacheHit, entry.Source, entry.PolicyAction, entry.PolicyCategory,
		entry.DecisionID, entry.Trace, entry.AnalyzedAt, entry.ClientIP, entry.ClientID,
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
		return nil, ErrDisabled
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
		        COALESCE(policy_action, ''), COALESCE(policy_category, ''),
		        COALESCE(decision_id, ''), COALESCE(trace, '{}'),
		        analyzed_at, created_at, COALESCE(client_ip, ''), COALESCE(client_id, '')
		 FROM analysis_log `+where+` ORDER BY id DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("query recent: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []TelemetryEntry
	for rows.Next() {
		var e TelemetryEntry
		var reasonsJSON string
		var cacheHit int
		if err := rows.Scan(&e.ID, &e.Domain, &e.Verdict, &e.Score, &e.Confidence,
			&reasonsJSON, &cacheHit, &e.Source, &e.PolicyAction, &e.PolicyCategory,
			&e.DecisionID, &e.Trace, &e.AnalyzedAt, &e.CreatedAt, &e.ClientIP, &e.ClientID); err != nil {
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
		return Stats{}, ErrDisabled
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
	defer func() { _ = trendRows.Close() }()

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
	// Expired and revoked admin sessions. This was only ever called from the
	// login handler, so a deployment that was not being logged into accumulated
	// rows, and the idx on expires_at grew with them. It belongs here with the
	// other retention sweeps rather than on a timer of its own.
	if _, err := d.CleanupExpiredAdminSessions(context.Background()); err != nil {
		logjson.Warn("admin session cleanup failed", map[string]any{
			"service": "store",
			"error":   err.Error(),
		})
	}
	// Decided user reports (resolved/rejected) age out with telemetry
	// retention. Pending reports are never auto-deleted: they are the
	// operator's review queue. created_at uses CURRENT_TIMESTAMP (space
	// separator), so the cutoff is formatted to match for correct
	// lexicographic comparison.
	if result, err := d.db.ExecContext(context.Background(),
		`DELETE FROM block_reports WHERE status IN ('resolved', 'rejected') AND created_at < ?`,
		time.Now().AddDate(0, 0, -d.GetRetentionDays(context.Background())).UTC().Format("2006-01-02 15:04:05")); err != nil {
		logjson.Error("block report cleanup failed", map[string]any{
			"service": "store",
			"error":   err.Error(),
		})
	} else if n, _ := result.RowsAffected(); n > 0 {
		logjson.Info("block report cleanup removed decided entries", map[string]any{
			"service": "store",
			"removed": n,
		})
	}
	// Return a bounded number of freelist pages to the OS. Unlike a full
	// VACUUM this never rewrites the whole file, so retention deletes do
	// not grow the database file without bound.
	if _, err := d.db.ExecContext(context.Background(), `PRAGMA incremental_vacuum(100)`); err != nil {
		logjson.Warn("incremental vacuum failed", map[string]any{
			"service": "store",
			"error":   err.Error(),
		})
	}
}

// vacuumIncrementalDoneKey marks databases already converted to
// incremental vacuum mode.
const vacuumIncrementalDoneKey = "sqlite_vacuum_incremental_done"

// ensureIncrementalVacuum converts pre-existing database files to
// incremental vacuum mode exactly once. New files already inherit the
// mode from the open-time pragma.
func (d *DB) ensureIncrementalVacuum(ctx context.Context) error {
	if !d.Enabled() {
		return ErrDisabled
	}
	done, err := d.GetSystemConfig(ctx, vacuumIncrementalDoneKey)
	if err == nil && done == "1" {
		return nil
	}
	var mode string
	if err := d.db.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		return fmt.Errorf("inspect vacuum mode: %w", err)
	}
	// Modes: 0 = none (needs conversion), 1 = full (already self-
	// maintaining), 2 = incremental (desired state).
	if strings.TrimSpace(mode) == "0" {
		if _, err := d.db.ExecContext(ctx, `VACUUM`); err != nil {
			return fmt.Errorf("vacuum database: %w", err)
		}
	}
	if err := d.SetSystemConfig(ctx, vacuumIncrementalDoneKey, "1"); err != nil {
		return fmt.Errorf("record vacuum conversion: %w", err)
	}
	return nil
}

// --- Overrides ---

// GetOverride checks if a domain (or any of its parent domains) has an override.
// Returns nil if no override is found.
func (d *DB) GetOverride(ctx context.Context, domain string) (*Override, error) {
	if !d.Enabled() {
		return nil, ErrDisabled
	}
	// Check the exact match and its parents, stopping at the registrable
	// label (eTLD+1). A row keyed on a public suffix would otherwise apply to
	// every domain in that namespace, and this function is reached from the
	// agent's audit path, so a legacy "com" row would make the agent treat
	// every .com domain as already having an override. UpsertOverride refuses
	// such rows; the floor here covers databases written by older builds.
	parts := strings.Split(domain, ".")
	floor := analysis.RegistrableWalkFloor(domain)
	for i := 0; i < len(parts) && i <= floor; i++ {
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
		return nil, ErrDisabled
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
	defer func() { _ = rows.Close() }()

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
		return ErrDisabled
	}
	if action != "allow" && action != "block" {
		return fmt.Errorf("invalid action %q: must be 'allow' or 'block'", action)
	}
	domain = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(domain)), ".")
	if domain == "" {
		return fmt.Errorf("override domain cannot be empty")
	}
	// An override row is matched against the domain and its parents, so a
	// public suffix would apply to the whole namespace: an "allow" for "com"
	// would short-circuit the threat feed, lexical scoring, ML, AI and OSINT
	// for every .com domain, and a "block" would take all of .com offline.
	if !analysis.IsRegistrableDomain(domain) {
		return fmt.Errorf("override domain %q is a public suffix or has no registrable label; use a domain you control such as example.com", domain)
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
		return ErrDisabled
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
		return ErrDisabled
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
		return nil, ErrDisabled
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
	defer func() { _ = rows.Close() }()

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
		return nil, ErrDisabled
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
	defer func() { _ = rows.Close() }()

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

// QueryAgentEventsPage returns agent events after the (created_at, id) cursor
// in stable ascending order, optionally filtered by event types. The keyset
// pagination lets consumers page through large backlogs without skipping or
// repeating rows, including ties on the second-precision created_at column.
func (d *DB) QueryAgentEventsPage(ctx context.Context, afterCreatedAt string, afterID int64, eventTypes []string, limit int) ([]AgentEvent, error) {
	if !d.Enabled() {
		return nil, ErrDisabled
	}
	if limit <= 0 {
		limit = 100
	}

	var rows *sql.Rows
	var err error
	if len(eventTypes) > 0 {
		placeholders := make([]string, len(eventTypes))
		args := make([]any, 0, len(eventTypes)+4)
		args = append(args, afterCreatedAt, afterCreatedAt, afterID)
		for i, et := range eventTypes {
			placeholders[i] = "?"
			args = append(args, et)
		}
		args = append(args, limit)
		query := fmt.Sprintf( // #nosec G201 -- placeholders are always literal "?" strings, never user input
			`SELECT id, task_name, event_type, COALESCE(domain, ''), COALESCE(details, ''), created_at
			 FROM agent_audit_log
			 WHERE (created_at > ? OR (created_at = ? AND id > ?)) AND event_type IN (%s)
			 ORDER BY created_at ASC, id ASC LIMIT ?`,
			strings.Join(placeholders, ","))
		rows, err = d.db.QueryContext(ctx, query, args...)
	} else {
		rows, err = d.db.QueryContext(ctx,
			`SELECT id, task_name, event_type, COALESCE(domain, ''), COALESCE(details, ''), created_at
			 FROM agent_audit_log
			 WHERE created_at > ? OR (created_at = ? AND id > ?)
			 ORDER BY created_at ASC, id ASC LIMIT ?`, afterCreatedAt, afterCreatedAt, afterID, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("query agent events page: %w", err)
	}
	defer func() { _ = rows.Close() }()

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

// CountAgentEventsAfter counts agent events after the (created_at, id)
// cursor with the same event-type filters as QueryAgentEventsPage, so
// consumers can measure the pending backlog before deciding to act on it.
func (d *DB) CountAgentEventsAfter(ctx context.Context, afterCreatedAt string, afterID int64, eventTypes []string) (int64, error) {
	if !d.Enabled() {
		return 0, ErrDisabled
	}

	query := `SELECT COUNT(*) FROM agent_audit_log WHERE (created_at > ? OR (created_at = ? AND id > ?))`
	args := []any{afterCreatedAt, afterCreatedAt, afterID}
	if len(eventTypes) > 0 {
		placeholders := make([]string, len(eventTypes))
		for i, et := range eventTypes {
			placeholders[i] = "?"
			args = append(args, et)
		}
		query += ` AND event_type IN (` + strings.Join(placeholders, ",") + `)`
	}

	var count int64
	if err := d.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count agent events: %w", err)
	}
	return count, nil
}

// QuerySuspiciousDomainsPage is the keyset variant of QuerySuspiciousDomains
// for background audit cycles. It pages over a frozen [since, until) window
// ordered by domain ASC, resuming strictly after afterDomain. A frozen window
// keeps the domain grouping stable, so keyset pagination never skips or
// repeats a domain across pages.
func (d *DB) QuerySuspiciousDomainsPage(ctx context.Context, since, until time.Time, minOccurrences, limit int, afterDomain string) ([]DomainCount, error) {
	if !d.Enabled() {
		return nil, ErrDisabled
	}
	if minOccurrences <= 0 {
		minOccurrences = 3
	}
	if limit <= 0 {
		limit = 50
	}

	// analysis_log timestamps are RFC3339Nano text; fractional seconds sort
	// before the whole-second "Z" suffix lexicographically. Ceil the upper
	// bound to the next whole second so entries inside the boundary second
	// stay inside the window (a small overlap across windows is safe because
	// audit decisions are idempotent).
	untilStr := until.UTC().Truncate(time.Second).Add(time.Second).Format(time.RFC3339)
	sinceStr := since.UTC().Format(time.RFC3339)

	query := `
		SELECT domain, COUNT(*) AS cnt
		FROM analysis_log
		WHERE verdict = 'SUSPICIOUS' AND analyzed_at >= ? AND analyzed_at < ?
		GROUP BY domain
		HAVING cnt >= ?`
	args := []any{sinceStr, untilStr, minOccurrences}
	if afterDomain != "" {
		query += ` AND domain > ?`
		args = append(args, afterDomain)
	}
	query += `
		ORDER BY domain ASC
		LIMIT ?`
	args = append(args, limit)

	rows, err := d.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query suspicious domains page: %w", err)
	}
	defer func() { _ = rows.Close() }()

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
		return nil, ErrDisabled
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
	defer func() { _ = rows.Close() }()

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
		return ErrDisabled
	}
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return fmt.Errorf("domain is required")
	}

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin osint evidence transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

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
	defer func() { _ = stmt.Close() }()

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
		return nil, ErrDisabled
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
	defer func() { _ = rows.Close() }()

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
