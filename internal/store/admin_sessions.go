package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// adminSessionDatetime matches the SQLite datetime('now') output used by the
// created_at/revoked_at defaults so SQL-side comparisons are consistent.
const adminSessionDatetime = "2006-01-02 15:04:05"

// CreateAdminSession persists a new admin session fingerprint. The raw
// session ID never reaches the database — callers store only its
// SHA-256 fingerprint. DB failures must fail the login (fail closed).
func (d *DB) CreateAdminSession(ctx context.Context, fingerprint, username string, expiresAt time.Time) error {
	if !d.Enabled() {
		return fmt.Errorf("sqlite store disabled")
	}
	_, err := d.db.ExecContext(ctx,
		`INSERT INTO admin_sessions (session_fingerprint, username, expires_at) VALUES (?, ?, ?)`,
		fingerprint, username, expiresAt.UTC().Format(adminSessionDatetime),
	)
	if err != nil {
		return fmt.Errorf("create admin session: %w", err)
	}
	return nil
}

// AdminSessionActive reports whether the fingerprint belongs to a session
// that is neither revoked nor expired. A missing row returns (false, nil);
// a database failure returns an error so callers can fail closed.
func (d *DB) AdminSessionActive(ctx context.Context, fingerprint string) (bool, error) {
	if !d.Enabled() {
		return false, fmt.Errorf("sqlite store disabled")
	}
	var one int
	err := d.db.QueryRowContext(ctx,
		`SELECT 1 FROM admin_sessions WHERE session_fingerprint = ? AND revoked_at IS NULL AND expires_at > datetime('now')`,
		fingerprint,
	).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check admin session: %w", err)
	}
	return true, nil
}

// RevokeAdminSession marks the session revoked (idempotent). After a
// successful revoke, any copy of the cookie is rejected at the next request.
func (d *DB) RevokeAdminSession(ctx context.Context, fingerprint string) error {
	if !d.Enabled() {
		return fmt.Errorf("sqlite store disabled")
	}
	_, err := d.db.ExecContext(ctx,
		`UPDATE admin_sessions SET revoked_at = datetime('now') WHERE session_fingerprint = ? AND revoked_at IS NULL`,
		fingerprint,
	)
	if err != nil {
		return fmt.Errorf("revoke admin session: %w", err)
	}
	return nil
}

// CleanupExpiredAdminSessions deletes expired and revoked sessions in a
// bounded batch and returns how many rows were removed.
func (d *DB) CleanupExpiredAdminSessions(ctx context.Context) (int64, error) {
	if !d.Enabled() {
		return 0, fmt.Errorf("sqlite store disabled")
	}
	result, err := d.db.ExecContext(ctx, `
		DELETE FROM admin_sessions
		WHERE rowid IN (
			SELECT rowid FROM admin_sessions
			WHERE expires_at <= datetime('now', '-1 day')
			   OR (revoked_at IS NOT NULL AND revoked_at <= datetime('now', '-1 day'))
			LIMIT 500
		)`)
	if err != nil {
		return 0, fmt.Errorf("cleanup admin sessions: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("cleanup admin sessions: %w", err)
	}
	return deleted, nil
}
