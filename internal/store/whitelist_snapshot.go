package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ErrWhitelistSnapshotNotFound reports that no rollback snapshot matches the
// requested id.
var ErrWhitelistSnapshotNotFound = errors.New("whitelist snapshot not found")

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
	_, _ = d.db.ExecContext(ctx,
		`DELETE FROM whitelist_snapshots WHERE id NOT IN (
			SELECT id FROM whitelist_snapshots ORDER BY id DESC LIMIT ?
		)`, MaxWhitelistSnapshots)
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
