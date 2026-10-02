package store

import (
	"context"
	"errors"
	"strconv"
	"testing"
)

func seedWhitelist(t *testing.T, db *DB, n int) {
	t.Helper()
	domains := make([]string, 0, n)
	for i := range n {
		domains = append(domains, "d"+strconv.Itoa(i)+".example")
	}
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")
	if err := db.UpdateWhitelist(context.Background(), domains); err != nil {
		t.Fatalf("seed %d domains: %v", n, err)
	}
	// Re-enable the floor for the assertions that follow.
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "100")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "50")
}

// The whitelist is a safety valve: a listed domain is reported SAFE and never
// reaches the threat feed, lexical scoring, ML, AI, OSINT or group
// enforcement. Replacing it with an empty or collapsed set is therefore not a
// partial degradation but a total loss of protection for every domain on it.
//
// The threat-feed path already refuses a zero-valid replacement (feed.Sync).
// Before this, the whitelist had no equivalent guard, so a captive portal
// page, a truncated body, a gzip bomb that unzips to nothing, or a source that
// changed format all produced the same result: the table emptied and every
// previously-whitelisted domain started being scored.
func TestWhitelistImportRefusesToEmptyAPopulatedList(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	seedWhitelist(t, db, 1000)

	// The poisoned responses an operator would actually see.
	poisoned := map[string][]string{
		"empty body":             {},
		"html error page":        nil,
		"truncated to a handful": {"one.example", "two.example"},
		"only public suffixes":   {"com", "co.uk", "github.io"},
	}
	for name, domains := range poisoned {
		t.Run(name, func(t *testing.T) {
			err := db.UpdateWhitelist(ctx, domains)
			if err == nil {
				t.Fatal("a poisoned import must be refused, not applied")
			}
			if !errors.Is(err, ErrWhitelistBelowFloor) {
				t.Fatalf("error = %v, want it to wrap ErrWhitelistBelowFloor", err)
			}

			// The live set must be completely untouched.
			count, countErr := db.GetWhitelistCount(ctx)
			if countErr != nil {
				t.Fatal(countErr)
			}
			if count != 1000 {
				t.Fatalf("live whitelist has %d entries after a refused import, want the original 1000", count)
			}
			ok, err := db.IsDomainWhitelisted(ctx, "d500.example")
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatal("a refused import still removed an entry: the previous set must survive intact")
			}
		})
	}
}

// A collapse that stays above the absolute floor but drops most of the set is
// the shape a format change produces, and the relative floor is what catches it.
func TestWhitelistImportRefusesACliffEdgeDrop(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	seedWhitelist(t, db, 1000)

	// 300 entries clears the absolute floor of 100 but is a 70% drop.
	shrunk := make([]string, 0, 300)
	for i := range 300 {
		shrunk = append(shrunk, "d"+strconv.Itoa(i)+".example")
	}
	if err := db.UpdateWhitelist(ctx, shrunk); err == nil {
		t.Fatal("a 70% collapse must be refused")
	} else if !errors.Is(err, ErrWhitelistBelowFloor) {
		t.Fatalf("error = %v, want ErrWhitelistBelowFloor", err)
	}
	if count, _ := db.GetWhitelistCount(ctx); count != 1000 {
		t.Fatalf("live whitelist has %d entries, want 1000", count)
	}
}

// A legitimate reshrink — the operator retiring a source — must still be
// possible, or the floor turns into an outage generator.
func TestWhitelistImportAllowsALegitimateReshrink(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	seedWhitelist(t, db, 1000)

	// 800 of 1000 is a 20% drop: above the relative floor.
	shrunk := make([]string, 0, 800)
	for i := range 800 {
		shrunk = append(shrunk, "d"+strconv.Itoa(i)+".example")
	}
	if err := db.UpdateWhitelist(ctx, shrunk); err != nil {
		t.Fatalf("a legitimate shrink must be accepted: %v", err)
	}
	if count, _ := db.GetWhitelistCount(ctx); count != 800 {
		t.Fatalf("live whitelist has %d entries, want 800", count)
	}
}

// The floor must not apply before there is anything to protect, otherwise a
// small hand-written whitelist — a perfectly legitimate configuration — could
// never be installed.
func TestWhitelistFloorDoesNotBlockAFirstSmallImport(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	small := []string{"tpb.vn", "example.com"}
	if err := db.UpdateWhitelist(ctx, small); err != nil {
		t.Fatalf("a first import must not be floor-checked: %v", err)
	}
	if count, _ := db.GetWhitelistCount(ctx); count != 2 {
		t.Fatalf("live whitelist has %d entries, want 2", count)
	}
}

// The floors are operator-tunable, and setting them to zero restores the
// unconditional replace behaviour.
func TestWhitelistFloorsAreConfigurable(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	seedWhitelist(t, db, 1000)

	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "0")
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "0")
	if err := db.UpdateWhitelist(ctx, []string{"only.example"}); err != nil {
		t.Fatalf("a zero floor must allow any size: %v", err)
	}
	if count, _ := db.GetWhitelistCount(ctx); count != 1 {
		t.Fatalf("live whitelist has %d entries, want 1", count)
	}
}

func TestWhitelistFloorClampsInvalidConfig(t *testing.T) {
	db := newTestDB(t)
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_ENTRIES", "-5")
	if got := db.whitelistMinAbsolute(); got != 0 {
		t.Fatalf("whitelistMinAbsolute = %d, want 0 for a negative setting", got)
	}
	t.Setenv("SAFE_ZONE_WHITELIST_MIN_PERCENT", "500")
	if got := db.whitelistMinRelative(); got != 100 {
		t.Fatalf("whitelistMinRelative = %d, want 100 for an over-large percentage", got)
	}
}
