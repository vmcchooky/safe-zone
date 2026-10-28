package store

import (
	"context"
	"net"
	"testing"
)

func TestNormalizeCIDRForStorage(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"10.1.2.0/24", "10.1.2.0/24"},
		{"2001:db8::/32", "2001:db8::/32"},
		// 4-in-6 collapses to its IPv4 meaning instead of persisting a
		// shockingly broad rule under a misleading name.
		{"::ffff:10.0.0.0/104", "10.0.0.0/8"},
		{"::ffff:0:0/96", "0.0.0.0/0"},
		// ParseCIDR masks host bits, so this is genuinely ::/80.
		{"::ffff:1.2.3.4/80", "::/80"},
	}
	for _, tc := range cases {
		_, ipNet, err := net.ParseCIDR(tc.input)
		if err != nil {
			t.Fatalf("test setup: parse %q: %v", tc.input, err)
		}
		if got := normalizeCIDRForStorage(ipNet); got != tc.want {
			t.Fatalf("normalizeCIDRForStorage(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestAddMappingNormalizesV4MappedCIDR(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	grpID, err := db.CreateGroup(ctx, "mapped", "mapped group", []string{}, false, false)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, err := db.AddMappingInt(ctx, "cidr", "::ffff:10.0.0.0/104", grpID); err != nil {
		t.Fatalf("add mapped cidr: %v", err)
	}
	mappings, err := db.ListMappings(ctx)
	if err != nil {
		t.Fatalf("list mappings: %v", err)
	}
	if len(mappings) != 1 || mappings[0].Value != "10.0.0.0/8" {
		t.Fatalf("stored mapping = %+v, want normalized 10.0.0.0/8", mappings)
	}
}

func TestDeleteGroupRefreshesCIDRCache(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	grpID, err := db.CreateGroup(ctx, "contractor", "contractor devices", []string{}, false, false)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, err := db.AddMappingInt(ctx, "cidr", "10.20.0.0/16", grpID); err != nil {
		t.Fatalf("add cidr mapping: %v", err)
	}
	got, err := db.GetGroupForClient(ctx, "10.20.1.5", "", false)
	if err != nil {
		t.Fatalf("resolve group before delete: %v", err)
	}
	if got == nil || got.ID != grpID {
		t.Fatalf("GetGroupForClient(10.20.1.5) = %+v, want group %d", got, grpID)
	}

	// client_mappings.group_id is ON DELETE CASCADE, so deleting the group
	// removes its CIDR row as well. The in-memory index must be rebuilt from
	// that new state; otherwise it keeps matching a group that no longer
	// exists and the lookup fails instead of falling back to default.
	if err := db.DeleteGroup(ctx, grpID); err != nil {
		t.Fatalf("delete group: %v", err)
	}
	got, err = db.GetGroupForClient(ctx, "10.20.1.5", "", false)
	if err != nil {
		t.Fatalf("resolve group after delete: %v", err)
	}
	if got == nil || got.Name != "default" {
		t.Fatalf("GetGroupForClient(10.20.1.5) after delete = %+v, want default group", got)
	}
}

func TestGetGroupForClientPrefersMostSpecificCIDR(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	broadID, err := db.CreateGroup(ctx, "broad", "broad group", []string{}, false, false)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	narrowID, err := db.CreateGroup(ctx, "narrow", "narrow group", []string{}, false, false)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	// Insert broad first: without longest-prefix ordering the /8 would
	// shadow the /24 for every client beneath it.
	if _, err := db.AddMappingInt(ctx, "cidr", "10.0.0.0/8", broadID); err != nil {
		t.Fatalf("add broad cidr: %v", err)
	}
	if _, err := db.AddMappingInt(ctx, "cidr", "10.1.2.0/24", narrowID); err != nil {
		t.Fatalf("add narrow cidr: %v", err)
	}
	got, err := db.GetGroupForClient(ctx, "10.1.2.3", "", false)
	if err != nil {
		t.Fatalf("resolve group: %v", err)
	}
	if got == nil || got.ID != narrowID {
		t.Fatalf("GetGroupForClient(10.1.2.3) = %+v, want narrow group %d", got, narrowID)
	}
	got, err = db.GetGroupForClient(ctx, "10.9.9.9", "", false)
	if err != nil {
		t.Fatalf("resolve group: %v", err)
	}
	if got == nil || got.ID != broadID {
		t.Fatalf("GetGroupForClient(10.9.9.9) = %+v, want broad group %d", got, broadID)
	}
}
