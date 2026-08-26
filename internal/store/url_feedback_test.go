package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newFeedbackTestDB(t *testing.T) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "feedback-store.db")
	db, err := New(path, 30)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestUpsertURLFeedbackIsIdempotentPerFingerprint(t *testing.T) {
	db := newFeedbackTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	row := URLFeedbackRow{
		Fingerprint:       "aa11",
		KeyVersion:        1,
		ProbabilityBucket: 4,
		WouldPromote:      true,
		RecordedAt:        now,
	}
	if err := db.UpsertURLFeedback(ctx, row); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	update := row
	update.ProbabilityBucket = 8
	if err := db.UpsertURLFeedback(ctx, update); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	stats, err := db.URLFeedbackStats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.Rows != 1 {
		t.Fatalf("expected dedupe to keep one row, got %d", stats.Rows)
	}
}

func TestApplyURLFeedbackLabelOnce(t *testing.T) {
	db := newFeedbackTestDB(t)
	ctx := context.Background()
	if err := db.UpsertURLFeedback(ctx, URLFeedbackRow{
		Fingerprint: "bb22", KeyVersion: 2, ProbabilityBucket: -1,
		WouldPromote: true, RecordedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := db.ApplyURLFeedbackLabel(ctx, "bb22", false); err != nil {
		t.Fatalf("apply label: %v", err)
	}
	err := db.ApplyURLFeedbackLabel(ctx, "bb22", true)
	if !errors.Is(err, ErrAlreadyLabelled) {
		t.Fatalf("expected ErrAlreadyLabelled, got %v", err)
	}
	if err := db.ApplyURLFeedbackLabel(ctx, "cc33", true); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows for unknown fingerprint, got %v", err)
	}
}

func TestPruneURLFeedbackEnforcesTTLAndRowCap(t *testing.T) {
	db := newFeedbackTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	for i, ts := range []time.Time{old, old.Add(time.Second), now} {
		if err := db.UpsertURLFeedback(ctx, URLFeedbackRow{
			Fingerprint: string(rune('a'+i)) + "000",
			KeyVersion:  1,
			RecordedAt:  ts,
		}); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
	}
	pruned, err := db.PruneURLFeedback(ctx, now.Add(-24*time.Hour), 1)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	count, err := db.URLFeedbackRowCount(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count > 1 || pruned == 0 {
		t.Fatalf("expected TTL+cap pruning to leave at most one row (pruned=%d count=%d)", pruned, count)
	}
}
