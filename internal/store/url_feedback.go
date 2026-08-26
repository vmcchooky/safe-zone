package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// URLFeedbackRow is one privacy-safe URL shadow feedback entry. It stores only
// an opaque HMAC fingerprint of the caller-generated event ID plus coarse
// aggregates. No raw URL, query, hostname, redirect target or client identity
// is ever written to this table.
type URLFeedbackRow struct {
	Fingerprint       string // hex HMAC-SHA256 prefix keyed with the configured secret
	KeyVersion        int
	ProbabilityBucket int // 0..9, -1 unknown
	WouldPromote      bool
	Labeled           bool
	LabelMalicious    bool
	RecordedAt        time.Time
	LabeledAt         time.Time // zero when unlabeled
}

// URLFeedbackStats holds aggregate counters computed from retained rows.
type URLFeedbackStats struct {
	Rows                 int64
	Labeled              int64
	ConfirmedMalicious   int64
	ReportedBenignFP     int64
	WouldPromoteLabelled int64
}

var (
	ErrURLFeedbackUnavailable = errors.New("url feedback persistence unavailable")
	ErrAlreadyLabelled        = errors.New("url feedback event already labelled")
)

func (db *DB) urlFeedbackReady() error {
	if db == nil || !db.Enabled() {
		return ErrURLFeedbackUnavailable
	}
	return nil
}

// UpsertURLFeedback inserts a fingerprint row or refreshes an existing one
// (idempotent dedupe for repeated observations of the same event ID).
func (db *DB) UpsertURLFeedback(ctx context.Context, row URLFeedbackRow) error {
	if err := db.urlFeedbackReady(); err != nil {
		return err
	}
	labeledAt := ""
	if !row.LabeledAt.IsZero() {
		labeledAt = row.LabeledAt.UTC().Format(time.RFC3339Nano)
	}
	_, err := db.db.ExecContext(ctx, `
INSERT INTO url_ml_feedback
    (fp, key_version, probability_bucket, would_promote, labeled, label_malicious, recorded_at, labeled_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(fp) DO UPDATE SET
    probability_bucket = excluded.probability_bucket,
    would_promote = excluded.would_promote`,
		row.Fingerprint, row.KeyVersion, row.ProbabilityBucket,
		boolToInt(row.WouldPromote), boolToInt(row.Labeled), boolToInt(row.LabelMalicious),
		row.RecordedAt.UTC().Format(time.RFC3339Nano), labeledAt,
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrURLFeedbackUnavailable, err)
	}
	return nil
}

// ApplyURLFeedbackLabel marks a retained fingerprint as labelled. It returns
// sql.ErrNoRows when the fingerprint is unknown and ErrAlreadyLabelled when
// the event was labelled before (anti-replay).
func (db *DB) ApplyURLFeedbackLabel(ctx context.Context, fingerprint string, malicious bool) error {
	if err := db.urlFeedbackReady(); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := db.db.ExecContext(ctx, `
UPDATE url_ml_feedback
SET labeled = 1, label_malicious = ?, labeled_at = ?
WHERE fp = ? AND labeled = 0`, boolToInt(malicious), now, fingerprint)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrURLFeedbackUnavailable, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrURLFeedbackUnavailable, err)
	}
	if affected == 0 {
		var labeled int
		switch err := db.db.QueryRowContext(ctx,
			`SELECT labeled FROM url_ml_feedback WHERE fp = ?`, fingerprint).Scan(&labeled); {
		case errors.Is(err, sql.ErrNoRows):
			return sql.ErrNoRows
		case err != nil:
			return fmt.Errorf("%w: %v", ErrURLFeedbackUnavailable, err)
		case labeled == 1:
			return ErrAlreadyLabelled
		default:
			return sql.ErrNoRows
		}
	}
	return nil
}

// URLFeedbackStats reads aggregate counters over retained rows.
func (db *DB) URLFeedbackStats(ctx context.Context) (URLFeedbackStats, error) {
	var stats URLFeedbackStats
	if err := db.urlFeedbackReady(); err != nil {
		return stats, err
	}
	err := db.db.QueryRowContext(ctx, `
SELECT
    COUNT(*),
    COALESCE(SUM(labeled), 0),
    COALESCE(SUM(CASE WHEN labeled = 1 AND label_malicious = 1 THEN 1 ELSE 0 END), 0),
    COALESCE(SUM(CASE WHEN labeled = 1 AND label_malicious = 0 AND would_promote = 1 THEN 1 ELSE 0 END), 0),
    COALESCE(SUM(CASE WHEN labeled = 1 AND would_promote = 1 THEN 1 ELSE 0 END), 0)
FROM url_ml_feedback`).Scan(
		&stats.Rows, &stats.Labeled, &stats.ConfirmedMalicious,
		&stats.ReportedBenignFP, &stats.WouldPromoteLabelled,
	)
	if err != nil {
		return stats, fmt.Errorf("%w: %v", ErrURLFeedbackUnavailable, err)
	}
	return stats, nil
}

// PruneURLFeedback deletes rows recorded before cutoff and enforces the row
// cap by deleting the oldest retained rows beyond maxRows.
func (db *DB) PruneURLFeedback(ctx context.Context, cutoff time.Time, maxRows int) (int64, error) {
	if err := db.urlFeedbackReady(); err != nil {
		return 0, err
	}
	var pruned int64
	res, err := db.db.ExecContext(ctx,
		`DELETE FROM url_ml_feedback WHERE recorded_at < ?`, cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrURLFeedbackUnavailable, err)
	}
	removed, _ := res.RowsAffected()
	pruned += removed
	if maxRows > 0 {
		var total int
		if err := db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM url_ml_feedback`).Scan(&total); err != nil {
			return pruned, fmt.Errorf("%w: %v", ErrURLFeedbackUnavailable, err)
		}
		if excess := int64(total) - int64(maxRows); excess > 0 {
			res, err := db.db.ExecContext(ctx, `
DELETE FROM url_ml_feedback WHERE fp IN (
    SELECT fp FROM url_ml_feedback ORDER BY recorded_at ASC LIMIT ?
)`, excess)
			if err != nil {
				return pruned, fmt.Errorf("%w: %v", ErrURLFeedbackUnavailable, err)
			}
			removed, _ := res.RowsAffected()
			pruned += removed
		}
	}
	return pruned, nil
}

// URLFeedbackRowCount returns the number of retained feedback rows.
func (db *DB) URLFeedbackRowCount(ctx context.Context) (int, error) {
	if err := db.urlFeedbackReady(); err != nil {
		return 0, err
	}
	var count int
	if err := db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM url_ml_feedback`).Scan(&count); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrURLFeedbackUnavailable, err)
	}
	return count, nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
