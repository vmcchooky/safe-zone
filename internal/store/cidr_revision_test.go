package store

import (
	"context"
	"path/filepath"
	"testing"
)

// Every write to client_mappings must advance the durable revision in the same
// transaction, because that revision is the only signal the second process
// (dns-resolver) has that its own CIDR index is stale.
func TestClientMappingsRevisionBumpsOnEveryMutation(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "mappings-revision.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()

	assertRevision := func(want int64) {
		t.Helper()
		got, err := db.GetClientMappingsRevision(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("client mappings revision = %d, want %d", got, want)
		}
	}

	assertRevision(0)

	groupID, err := db.CreateGroup(ctx, "revision", "", nil, false, false)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := db.AddMappingInt(ctx, "ip", "203.0.113.7", groupID); err != nil {
		t.Fatal(err)
	}
	assertRevision(1)

	mappingID, err := db.AddMappingInt(ctx, "cidr", "10.20.0.0/16", groupID)
	if err != nil {
		t.Fatal(err)
	}
	assertRevision(2)

	if err := db.DeleteMapping(ctx, mappingID); err != nil {
		t.Fatal(err)
	}
	assertRevision(3)

	// Deleting the group cascades its remaining mapping rows, so it is a
	// client_mappings change too.
	if err := db.DeleteGroup(ctx, groupID); err != nil {
		t.Fatal(err)
	}
	assertRevision(4)
}

// core-api and dns-resolver open the same SQLite file but build separate CIDR
// indexes. A mapping written through one handle must become visible to the
// other only after it reconciles the durable revision.
func TestReconcileCIDRMappingsAppliesCrossProcessChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared-mappings.db")
	writer, err := New(path, 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })

	reader, err := New(path, 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	ctx := context.Background()

	groupID, err := writer.CreateGroup(ctx, "cross-process", "", nil, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.AddMappingInt(ctx, "cidr", "10.20.0.0/16", groupID); err != nil {
		t.Fatal(err)
	}

	// The reader opened before the mapping existed, so its index is the
	// startup snapshot and the range must not resolve yet.
	group, err := reader.GetGroupForClient(ctx, "10.20.5.5", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if group.ID == groupID {
		t.Fatal("reader resolved a CIDR mapping it never reloaded")
	}

	reloaded, err := reader.ReconcileCIDRMappings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded {
		t.Fatal("expected a stale revision to rebuild the CIDR index")
	}

	group, err = reader.GetGroupForClient(ctx, "10.20.5.5", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if group.ID != groupID {
		t.Fatalf("after reconcile group = %d, want %d", group.ID, groupID)
	}

	// A second reconcile with no new revision must be a no-op.
	reloaded, err = reader.ReconcileCIDRMappings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded {
		t.Fatal("reconcile rebuilt the index without a revision change")
	}

	// Deleting the group cascades the CIDR row; the reader must drop it.
	if err := writer.DeleteGroup(ctx, groupID); err != nil {
		t.Fatal(err)
	}
	reloaded, err = reader.ReconcileCIDRMappings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded {
		t.Fatal("expected the cascaded delete to rebuild the CIDR index")
	}
	group, err = reader.GetGroupForClient(ctx, "10.20.5.5", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if group.ID == groupID {
		t.Fatal("reader kept a CIDR entry for a deleted group")
	}
}
