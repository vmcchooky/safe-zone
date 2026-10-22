package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"safe-zone/internal/logjson"
)

// ErrWhitelistSnapshotNotFound reports that no rollback snapshot matches the
// requested id.
var ErrWhitelistSnapshotNotFound = errors.New("whitelist snapshot not found")

// ErrWhitelistSnapshotEmpty reports a snapshot with no entries. Restoring it
// would wipe the allow list, which is the failure a rollback exists to undo.
var ErrWhitelistSnapshotEmpty = errors.New("whitelist snapshot is empty")

// ErrWhitelistSnapshotCorrupt reports a snapshot whose stored digest or entry
// count no longer matches its rows.
var ErrWhitelistSnapshotCorrupt = errors.New("whitelist snapshot failed verification")

// MaxWhitelistSnapshots bounds how many rollback copies are kept. The allow
// list can hold a million domains, so each snapshot is tens of megabytes;
// keeping a handful is enough to undo the last bad import without letting
// the table grow without bound.
const MaxWhitelistSnapshots = 3

// WhitelistSnapshot is a durable copy of the allow list.
//
// The whitelist is the primary safety valve: a domain on it is reported SAFE
// and never reaches the threat feed, lexical scoring, ML, AI, OSINT or group
// enforcement. A replacement import therefore has to be undoable — otherwise
// one truncated download silently removes every curated exception.
type WhitelistSnapshot struct {
	ID         int64
	CreatedAt  string
	Source     string
	EntryCount int
	SHA256     string
	Domains    []string
}

// SaveWhitelistSnapshot stores a copy of the allow list and returns its id.
//
// The snapshot is written before the replacement import, so it always holds
// the set that was live before the change. Older snapshots beyond
// MaxWhitelistSnapshots are pruned.
func (d *DB) SaveWhitelistSnapshot(ctx context.Context, source string, domains []string) (int64, error) {
	if !d.Enabled() {
		return 0, ErrDisabled
	}

	blob := strings.Join(domains, "\n")
	sum := sha256.Sum256([]byte(blob))

	result, err := d.db.ExecContext(ctx,
		`INSERT INTO whitelist_snapshots (source, entry_count, sha256, domains) VALUES (?, ?, ?, ?)`,
		source, len(domains), hex.EncodeToString(sum[:]), blob,
	)
	if err != nil {
		return 0, fmt.Errorf("insert whitelist snapshot: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("whitelist snapshot id: %w", err)
	}

	d.pruneWhitelistSnapshots(ctx)
	return id, nil
}

// pruneWhitelistSnapshots keeps only the most recent snapshots.
func (d *DB) pruneWhitelistSnapshots(ctx context.Context) {
	if _, err := d.db.ExecContext(ctx,
		`DELETE FROM whitelist_snapshots WHERE id NOT IN (
			SELECT id FROM whitelist_snapshots ORDER BY id DESC LIMIT ?
		)`, MaxWhitelistSnapshots); err != nil {
		// The snapshot that was just written is intact; pruning is
		// housekeeping. Silently ignoring the error let the table grow without
		// bound with nothing in the logs to explain the disk usage.
		logjson.Warn("whitelist snapshot prune failed", map[string]any{
			"service": "store",
			"keep":    MaxWhitelistSnapshots,
			"error":   err.Error(),
		})
	}
}

// LatestWhitelistSnapshot returns the most recent snapshot, or
// ErrWhitelistSnapshotNotFound when there is none.
func (d *DB) LatestWhitelistSnapshot(ctx context.Context) (*WhitelistSnapshot, error) {
	if !d.Enabled() {
		return nil, ErrDisabled
	}

	row := d.db.QueryRowContext(ctx,
		`SELECT id, created_at, source, entry_count, sha256, domains FROM whitelist_snapshots ORDER BY id DESC LIMIT 1`)

	var snapshot WhitelistSnapshot
	var blob []byte
	if err := row.Scan(&snapshot.ID, &snapshot.CreatedAt, &snapshot.Source, &snapshot.EntryCount, &snapshot.SHA256, &blob); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrWhitelistSnapshotNotFound
		}
		return nil, fmt.Errorf("read latest whitelist snapshot: %w", err)
	}

	snapshot.Domains = splitSnapshotDomains(string(blob))
	return &snapshot, nil
}

// ListWhitelistSnapshots returns the stored rollback copies, newest first,
// without their domain blobs. An operator needs to discover a snapshot id
// before calling rollback; returning only the latest forced them to guess.
func (d *DB) ListWhitelistSnapshots(ctx context.Context) ([]WhitelistSnapshot, error) {
	if !d.Enabled() {
		return nil, ErrDisabled
	}

	rows, err := d.db.QueryContext(ctx,
		`SELECT id, created_at, source, entry_count, sha256 FROM whitelist_snapshots ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list whitelist snapshots: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var snapshots []WhitelistSnapshot
	for rows.Next() {
		var snapshot WhitelistSnapshot
		if err := rows.Scan(&snapshot.ID, &snapshot.CreatedAt, &snapshot.Source, &snapshot.EntryCount, &snapshot.SHA256); err != nil {
			return nil, fmt.Errorf("scan whitelist snapshot: %w", err)
		}
		snapshots = append(snapshots, snapshot)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate whitelist snapshots: %w", err)
	}
	return snapshots, nil
}

// LatestWhitelistRollback returns the most recent durable rollback audit
// event, or nil when no rollback has been recorded.
func (d *DB) LatestWhitelistRollback(ctx context.Context) (*AgentEvent, error) {
	if !d.Enabled() {
		return nil, ErrDisabled
	}

	var event AgentEvent
	err := d.db.QueryRowContext(ctx,
		`SELECT id, task_name, event_type, COALESCE(domain, ''), COALESCE(details, ''), created_at
		 FROM agent_audit_log
		 WHERE task_name = 'whitelist' AND event_type = 'rollback'
		 ORDER BY id DESC LIMIT 1`).
		Scan(&event.ID, &event.TaskName, &event.EventType, &event.Domain, &event.Details, &event.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read latest whitelist rollback: %w", err)
	}
	return &event, nil
}

// WhitelistSnapshotByID returns the snapshot with the given id.
func (d *DB) WhitelistSnapshotByID(ctx context.Context, id int64) (*WhitelistSnapshot, error) {
	if !d.Enabled() {
		return nil, ErrDisabled
	}

	row := d.db.QueryRowContext(ctx,
		`SELECT id, created_at, source, entry_count, sha256, domains FROM whitelist_snapshots WHERE id = ?`, id)

	var snapshot WhitelistSnapshot
	var blob []byte
	if err := row.Scan(&snapshot.ID, &snapshot.CreatedAt, &snapshot.Source, &snapshot.EntryCount, &snapshot.SHA256, &blob); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrWhitelistSnapshotNotFound
		}
		return nil, fmt.Errorf("read whitelist snapshot %d: %w", id, err)
	}

	snapshot.Domains = splitSnapshotDomains(string(blob))
	return &snapshot, nil
}

// RestoreWhitelistSnapshot replaces the live allow list with a snapshot and
// returns the number of entries restored.
//
// The restore deliberately bypasses the import safety floor: the floor
// compares against the current live set, so it would refuse to put back a
// smaller set — which is precisely the case a rollback exists for.
func (d *DB) RestoreWhitelistSnapshot(ctx context.Context, id int64) (int, error) {
	snapshot, err := d.WhitelistSnapshotByID(ctx, id)
	if err != nil {
		return 0, err
	}
	if snapshot.EntryCount == 0 || len(snapshot.Domains) == 0 {
		return 0, fmt.Errorf("%w: snapshot %d has no entries", ErrWhitelistSnapshotEmpty, id)
	}
	blob := strings.Join(snapshot.Domains, "\n")
	sum := sha256.Sum256([]byte(blob))
	if snapshot.EntryCount != len(snapshot.Domains) || !strings.EqualFold(snapshot.SHA256, hex.EncodeToString(sum[:])) {
		return 0, fmt.Errorf("%w: snapshot %d no longer matches its digest or entry count", ErrWhitelistSnapshotCorrupt, id)
	}
	if err := d.RestoreWhitelist(ctx, snapshot.Domains); err != nil {
		return 0, fmt.Errorf("restore whitelist snapshot %d: %w", id, err)
	}
	return len(snapshot.Domains), nil
}

// WhitelistSnapshotCount returns how many rollback copies are stored.
func (d *DB) WhitelistSnapshotCount(ctx context.Context) (int, error) {
	if !d.Enabled() {
		return 0, ErrDisabled
	}

	var count int
	if err := d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM whitelist_snapshots`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count whitelist snapshots: %w", err)
	}
	return count, nil
}

// splitSnapshotDomains turns the newline-joined blob back into a slice.
func splitSnapshotDomains(blob string) []string {
	if blob == "" {
		return nil
	}
	parts := strings.Split(blob, "\n")
	domains := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		domains = append(domains, part)
	}
	return domains
}
