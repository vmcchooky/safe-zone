package store

import (
	"context"
	"testing"
)

// Every ingest path reaches the whitelist_domains table through
// UpdateWhitelist: the operator's file import (risk.Whitelist.LoadFromFile) and
// the agent's whitelist_update task, which downloads from an
// operator-configured URL. Validating inside the agent or the file loader
// leaves the other path open, so the filter belongs at the storage boundary.
func TestUpdateWhitelistDropsPublicSuffixes(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// A poisoned source: mostly real domains, plus one line that would
	// allowlist every .com domain.
	domains := []string{
		"google.com",
		"tpb.vn",
		"com",
		"co.uk",
		"github.io",
		"com.vn",
		"example.org",
	}
	if err := db.UpdateWhitelist(ctx, domains); err != nil {
		t.Fatalf("UpdateWhitelist: %v", err)
	}

	// Assert through the count and through each row, rather than a stream
	// whose return value is awkward.
	if count, err := db.GetWhitelistCount(ctx); err != nil {
		t.Fatal(err)
	} else if count != 3 {
		var names []string
		_ = db.StreamWhitelist(ctx, func(d string) error {
			names = append(names, d)
			return nil
		})
		t.Fatalf("stored %d domains (%v), want 3: every public suffix must be dropped", count, names)
	}

	for _, suffix := range []string{"com", "co.uk", "github.io", "com.vn"} {
		ok, err := db.IsDomainWhitelisted(ctx, suffix)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Fatalf("public suffix %q was stored", suffix)
		}
	}

	// The legitimate entries survived.
	for _, keep := range []string{"google.com", "tpb.vn", "example.org"} {
		ok, err := db.IsDomainWhitelisted(ctx, keep)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("%q should have been stored", keep)
		}
	}
}

// A whitelist of nothing but public suffixes must leave the table empty rather
// than erroring: the ingest either has no usable rows or is entirely poisoned,
// and the caller's own poisoning floor decides what to do about that.
func TestUpdateWhitelistAcceptsAnAllUnsafeListWithoutError(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := db.UpdateWhitelist(ctx, []string{"com", "net", "co.uk"}); err != nil {
		t.Fatalf("UpdateWhitelist must not fail on an all-unsafe list: %v", err)
	}
	if count, err := db.GetWhitelistCount(ctx); err != nil {
		t.Fatal(err)
	} else if count != 0 {
		t.Fatalf("stored %d domains, want 0", count)
	}
}
