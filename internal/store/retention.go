package store

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"safe-zone/internal/logjson"
)

// Retention cleanup, incremental vacuum and the vacuum-conversion flag live here.
// The sqlite.go breakup is complete: lifecycle/schema stay in sqlite.go; domains live
// in groups, telemetry, whitelist, reports, retention and overrides.

// Agent artifacts need their own windows. A decided proposal is reviewable
// evidence, but it is not operator policy: the override it created survives
// until an operator changes it. Audit events outlive proposals so an approval
// can still be explained after the proposal row is gone.
const (
	DefaultAgentProposalRetentionDays = 90
	DefaultAgentAuditRetentionDays    = 365
)

// agentRetentionDaysFromEnv reads one retention window. An unset or malformed
// value falls back to the documented default; an out-of-range value is clamped
// to the same ceiling as telemetry, because a cutoff so old would silently
// match nothing and retention would stop.
func agentRetentionDaysFromEnv(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	days, err := strconv.Atoi(raw)
	if err != nil || days < MinRetentionDays {
		logjson.Warn("agent retention is invalid; using the default", map[string]any{
			"service": "store",
			"setting": name,
			"given":   raw,
			"applied": fallback,
		})
		return fallback
	}
	if days > MaxRetentionDays {
		logjson.Warn("agent retention is above the ceiling; clamped", map[string]any{
			"service": "store",
			"setting": name,
			"given":   days,
			"applied": MaxRetentionDays,
		})
		return MaxRetentionDays
	}
	return days
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
	// Agent proposals are reviewable evidence, not operator policy: the
	// override an approval created lives in local_overrides until an operator
	// changes it. Prune a proposal only once it is decided, or once its TTL
	// has lapsed while still pending. Pending, unexpired rows are the review
	// queue and are never deleted here.
	proposalCutoff := time.Now().AddDate(0, 0, -d.proposalRetentionDays).UTC().Format("2006-01-02 15:04:05")
	if result, err := d.db.ExecContext(context.Background(), `
		DELETE FROM agent_proposals
		WHERE (status = ? AND datetime(expires_at) < datetime(?))
		   OR (status IN (?, ?, ?) AND datetime(updated_at) < datetime(?))`,
		AgentProposalPending, proposalCutoff,
		AgentProposalApproved, AgentProposalRejected, AgentProposalExpired, proposalCutoff); err != nil {
		logjson.Error("agent proposal cleanup failed", map[string]any{
			"service": "store",
			"cutoff":  proposalCutoff,
			"error":   err.Error(),
		})
	} else if n, _ := result.RowsAffected(); n > 0 {
		logjson.Info("agent proposal cleanup removed decided or expired entries", map[string]any{
			"service": "store",
			"cutoff":  proposalCutoff,
			"removed": n,
		})
	}

	// Audit events describe what the agent and its reviewers did. They are kept
	// longer than proposals so the reasoning survives after the proposal row is
	// pruned, but they are not kept forever: created_at uses the SQLite space
	// timestamp format, matched by the cutoff above.
	auditCutoff := time.Now().AddDate(0, 0, -d.auditRetentionDays).UTC().Format("2006-01-02 15:04:05")
	if result, err := d.db.ExecContext(context.Background(),
		`DELETE FROM agent_audit_log WHERE datetime(created_at) < datetime(?)`, auditCutoff); err != nil {
		logjson.Error("agent audit cleanup failed", map[string]any{
			"service": "store",
			"cutoff":  auditCutoff,
			"error":   err.Error(),
		})
	} else if n, _ := result.RowsAffected(); n > 0 {
		logjson.Info("agent audit cleanup removed old events", map[string]any{
			"service": "store",
			"cutoff":  auditCutoff,
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
