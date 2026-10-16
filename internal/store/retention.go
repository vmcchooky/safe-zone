package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"safe-zone/internal/logjson"
)

// Retention cleanup, incremental vacuum and the vacuum-conversion flag live here.
// The sqlite.go breakup is complete: lifecycle/schema stay in sqlite.go; domains live
// in groups, telemetry, whitelist, reports, retention and overrides.

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
