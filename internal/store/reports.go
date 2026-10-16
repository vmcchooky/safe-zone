package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// User-submitted block reports, operator reviews and false-positive approvals
// live here. The sqlite.go breakup is complete: lifecycle/schema stay in
// sqlite.go; domains live in groups, telemetry, whitelist, reports, retention
// and overrides (same package, no API change).

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
