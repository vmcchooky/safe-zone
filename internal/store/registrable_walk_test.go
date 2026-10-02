package store

import (
	"context"
	"testing"
)

// A row keyed on a public suffix must never be applied to a domain beneath it.
// UpsertOverride and UpsertGroupOverride refuse such rows, but a database
// written by an older build can still hold one, and every parent-suffix lookup
// has to enforce the floor itself.
func seedLegacyPublicSuffixRow(t *testing.T, db *DB, table, domain string) {
	t.Helper()
	query := `INSERT INTO ` + table + ` (domain, action, reason, updated_at) VALUES (?, 'allow', 'legacy row', datetime('now'))`
	if table == "group_overrides" {
		grpID, err := db.CreateGroup(context.Background(), "legacy", "Legacy group", []string{}, false, false)
		if err != nil {
			t.Fatalf("create group: %v", err)
		}
		query = `INSERT INTO group_overrides (group_id, domain, action, reason, updated_at)
			VALUES (?, ?, 'allow', 'legacy row', datetime('now'))`
		if _, err := db.db.ExecContext(context.Background(), query, grpID, domain); err != nil {
			t.Fatalf("seed legacy row in %s: %v", table, err)
		}
		return
	}
	if _, err := db.db.ExecContext(context.Background(), query, domain); err != nil {
		t.Fatalf("seed legacy row in %s: %v", table, err)
	}
}

func TestGetOverrideIgnoresALegacyPublicSuffixRow(t *testing.T) {
	db := newTestDB(t)
	seedLegacyPublicSuffixRow(t, db, "local_overrides", "com")

	for _, domain := range []string{"evil.com", "sub.evil.com", "x.y.evil.com"} {
		got, err := db.GetOverride(context.Background(), domain)
		if err != nil {
			t.Fatalf("GetOverride(%q): %v", domain, err)
		}
		if got != nil {
			t.Fatalf("GetOverride(%q) matched a public-suffix row: %+v", domain, got)
		}
	}

	// A registrable row still applies to its own subdomains.
	if err := db.UpsertOverride(context.Background(), "example.com", "block", "real"); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetOverride(context.Background(), "mail.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Domain != "example.com" {
		t.Fatalf("a registrable row must still apply to subdomains, got %+v", got)
	}
}

func TestHasGroupOverrideForDomainIgnoresALegacyPublicSuffixRow(t *testing.T) {
	db := newTestDB(t)
	seedLegacyPublicSuffixRow(t, db, "group_overrides", "co.uk")

	for _, domain := range []string{"evil.co.uk", "sub.evil.co.uk", "a.b.c.evil.co.uk"} {
		has, err := db.HasGroupOverrideForDomain(context.Background(), domain)
		if err != nil {
			t.Fatalf("HasGroupOverrideForDomain(%q): %v", domain, err)
		}
		if has {
			t.Fatalf("HasGroupOverrideForDomain(%q) matched a public-suffix row", domain)
		}
	}

	grpID, err := db.CreateGroup(context.Background(), "vip", "VIP", []string{}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertGroupOverride(context.Background(), grpID, "example.co.uk", "block", "real"); err != nil {
		t.Fatal(err)
	}
	has, err := db.HasGroupOverrideForDomain(context.Background(), "www.example.co.uk")
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Fatal("a registrable group row must still apply to subdomains")
	}
}

// The public-suffix upserts are the first line of defence; the walk floor is
// the second. Assert the first is still in place so the two do not drift.
func TestOverrideUpsertsRejectPublicSuffixes(t *testing.T) {
	db := newTestDB(t)
	grpID, err := db.CreateGroup(context.Background(), "vip", "VIP", []string{}, false, false)
	if err != nil {
		t.Fatal(err)
	}

	for _, suffix := range []string{"com", "net", "co.uk", "com.vn", "github.io"} {
		if err := db.UpsertOverride(context.Background(), suffix, "allow", "too broad"); err == nil {
			t.Fatalf("UpsertOverride accepted public suffix %q", suffix)
		}
		if err := db.UpsertGroupOverride(context.Background(), grpID, suffix, "allow", "too broad"); err == nil {
			t.Fatalf("UpsertGroupOverride accepted public suffix %q", suffix)
		}
	}
}
