package store

import (
	"context"
	"path/filepath"
	"testing"
)

// The retention ceiling has to be enforced where the value is read, not where it
// is submitted.
//
// The API validator rejected an out-of-range value, but the same number could
// still arrive two other ways: as the constructor argument, and as a value
// already sitting in system_config from an older database. A value of 2e9 days
// puts the prune cutoff in the year -5473788, and SQLite compares these ISO
// timestamps as TEXT — "-" sorts before "2", so the comparison matches nothing.
// The DELETE then removes zero rows, the caller logs nothing because it only
// logs when rows > 0, and the telemetry table grows without bound. With the
// ceiling only in the API, a restart brought the bad value straight back.
func TestClampRetentionDaysBoundsBothDirections(t *testing.T) {
	for _, tc := range []struct {
		name        string
		given       int
		wantApplied int
		wantChanged bool
	}{
		{name: "negative clamps to the default", given: -5, wantApplied: DefaultRetentionDays, wantChanged: true},
		{name: "zero keeps the default and reports no change", given: 0, wantApplied: DefaultRetentionDays, wantChanged: false},
		{name: "below the floor clamps to the default", given: -1, wantApplied: DefaultRetentionDays, wantChanged: true},
		{name: "the floor itself is allowed", given: MinRetentionDays, wantApplied: MinRetentionDays, wantChanged: false},
		{name: "the ceiling itself is allowed", given: MaxRetentionDays, wantApplied: MaxRetentionDays, wantChanged: false},
		{name: "above the ceiling clamps down", given: 2_000_000_000, wantApplied: MaxRetentionDays, wantChanged: true},
		{name: "int max clamps down", given: int(^uint(0) >> 1), wantApplied: MaxRetentionDays, wantChanged: true},
		{name: "a normal value passes through", given: 30, wantApplied: 30, wantChanged: false},
		{name: "a year passes through", given: 365, wantApplied: 365, wantChanged: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			applied, changed := ClampRetentionDays(tc.given)
			if applied != tc.wantApplied {
				t.Fatalf("applied = %d, want %d", applied, tc.wantApplied)
			}
			if changed != tc.wantChanged {
				t.Fatalf("changed = %v, want %v", changed, tc.wantChanged)
			}
		})
	}
}

// Clamping the constructor argument is the first of the two paths the API
// validator cannot see.
func TestNewClampsAnAbsurdRetentionArgument(t *testing.T) {
	for _, tc := range []struct {
		name  string
		given int
	}{
		{name: "two billion days", given: 2_000_000_000},
		{name: "negative", given: -30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := New(filepath.Join(t.TempDir(), "retention.db"), tc.given)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer func() { _ = db.Close() }()

			got := db.GetRetentionDays(context.Background())
			if got < MinRetentionDays || got > MaxRetentionDays {
				t.Fatalf("GetRetentionDays = %d, want it inside [%d, %d]", got, MinRetentionDays, MaxRetentionDays)
			}
		})
	}
}

// The second path the API validator cannot see: a database that already holds a
// bad value re-reads it at every boot. This is the one that made the API-level
// fix insufficient, because the value came back on its own after a restart.
func TestBootClampsAnAbsurdStoredRetentionValue(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "boot.db")

	first, err := New(dbPath, 30)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Simulate a database written by an older build that accepted the value.
	if err := first.SetSystemConfig(context.Background(), "telemetry_retention_days", "2000000000"); err != nil {
		t.Fatalf("seed stored value: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	second, err := New(dbPath, 30)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = second.Close() }()

	got := second.GetRetentionDays(context.Background())
	if got != MaxRetentionDays {
		t.Fatalf("GetRetentionDays after boot = %d, want the ceiling %d", got, MaxRetentionDays)
	}
}

// A stored value inside the range must still be honoured, or the clamp would
// quietly override an operator's setting on every restart.
func TestBootKeepsAValidStoredRetentionValue(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "boot-valid.db")

	first, err := New(dbPath, 30)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := first.SetSystemConfig(context.Background(), "telemetry_retention_days", "90"); err != nil {
		t.Fatalf("seed stored value: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	second, err := New(dbPath, 30)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = second.Close() }()

	if got := second.GetRetentionDays(context.Background()); got != 90 {
		t.Fatalf("GetRetentionDays after boot = %d, want 90", got)
	}
}
