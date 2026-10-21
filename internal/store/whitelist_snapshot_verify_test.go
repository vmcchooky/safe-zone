package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func newSnapshotTestDB(t *testing.T) *DB {
	t.Helper()
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")

	db, err := New(filepath.Join(t.TempDir(), "snapshots.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestRestoreWhitelistSnapshotRejectsAnEmptySnapshot(t *testing.T) {
	db := newSnapshotTestDB(t)
	ctx := context.Background()

	id, err := db.SaveWhitelistSnapshot(ctx, "empty", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.RestoreWhitelistSnapshot(ctx, id); !errors.Is(err, ErrWhitelistSnapshotEmpty) {
		t.Fatalf("restore empty snapshot error = %v, want ErrWhitelistSnapshotEmpty", err)
	}
}

func TestRestoreWhitelistSnapshotVerifiesDigestAndCount(t *testing.T) {
	db := newSnapshotTestDB(t)
	ctx := context.Background()
	domains := []string{"one.example", "two.example"}
	if err := db.UpdateWhitelist(ctx, domains); err != nil {
		t.Fatal(err)
	}
	id, err := db.SaveWhitelistSnapshot(ctx, "test", domains)
	if err != nil {
		t.Fatal(err)
	}

	// A row that no longer matches its digest must not be applied.
	if _, err := db.db.ExecContext(ctx, `UPDATE whitelist_snapshots SET domains = 'tampered.example' WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RestoreWhitelistSnapshot(ctx, id); !errors.Is(err, ErrWhitelistSnapshotCorrupt) {
		t.Fatalf("restore tampered blob error = %v, want ErrWhitelistSnapshotCorrupt", err)
	}

	// A row whose entry_count disagrees with its blob is equally unusable.
	if _, err := db.db.ExecContext(ctx, `UPDATE whitelist_snapshots SET domains = ?, entry_count = 99 WHERE id = ?`, "one.example\ntwo.example", id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RestoreWhitelistSnapshot(ctx, id); !errors.Is(err, ErrWhitelistSnapshotCorrupt) {
		t.Fatalf("restore mismatched count error = %v, want ErrWhitelistSnapshotCorrupt", err)
	}
}

func TestListWhitelistSnapshotsIsNewestFirstAndKeepsThree(t *testing.T) {
	db := newSnapshotTestDB(t)
	ctx := context.Background()

	var ids []int64
	for _, domain := range []string{"one.example", "two.example", "three.example", "four.example"} {
		if err := db.UpdateWhitelist(ctx, []string{domain}); err != nil {
			t.Fatal(err)
		}
		id, err := db.SaveWhitelistSnapshot(ctx, domain, []string{domain})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}

	snapshots, err := db.ListWhitelistSnapshots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != MaxWhitelistSnapshots {
		t.Fatalf("snapshot count = %d, want %d", len(snapshots), MaxWhitelistSnapshots)
	}
	if snapshots[0].ID != ids[len(ids)-1] {
		t.Fatalf("first snapshot id = %d, want newest %d", snapshots[0].ID, ids[len(ids)-1])
	}
	if snapshots[0].Source != "four.example" || snapshots[0].EntryCount != 1 || snapshots[0].SHA256 == "" || snapshots[0].CreatedAt == "" {
		t.Fatalf("snapshot metadata is incomplete: %+v", snapshots[0])
	}
}

func TestLatestWhitelistRollbackReadsTheAuditLog(t *testing.T) {
	db := newSnapshotTestDB(t)
	ctx := context.Background()

	event, err := db.LatestWhitelistRollback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if event != nil {
		t.Fatalf("latest rollback = %+v before any rollback, want nil", event)
	}

	if err := db.RecordAgentEvent(ctx, "whitelist", "rollback", "", `{"snapshot_id":7,"actor":"admin","reason":"restore curated list"}`); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordAgentEvent(ctx, "whitelist", "rollback", "", `{"snapshot_id":8,"actor":"ops","reason":"newer rollback"}`); err != nil {
		t.Fatal(err)
	}

	event, err = db.LatestWhitelistRollback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if event == nil {
		t.Fatal("latest rollback is nil after an audit write")
	}
	if event.Details != `{"snapshot_id":8,"actor":"ops","reason":"newer rollback"}` {
		t.Fatalf("latest rollback details = %q, want the newest event", event.Details)
	}
}
