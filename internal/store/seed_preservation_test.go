package store

import (
	"context"
	"testing"

	"safe-zone/internal/analysis"
)

// PR-08a/M2: re-running the default seed (every DB open) must not clobber
// operator edits to default brands. New names are still inserted.
func TestSeedDefaultBrandsPreservesOperatorEdits(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	brands, err := db.ListBrands(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(brands) == 0 {
		t.Fatal("expected default trusted brands to be seeded")
	}
	target := brands[0]

	edited, err := db.UpdateBrand(ctx, target.ID, analysis.Brand{
		Name:           target.Name,
		OfficialDomain: "operator-edited.example.com",
		AltDomains:     target.AltDomains,
	})
	if err != nil {
		t.Fatal(err)
	}
	if edited.OfficialDomain != "operator-edited.example.com" {
		t.Fatalf("precondition: expected edited official domain, got %s", edited.OfficialDomain)
	}

	if err := db.SeedDefaultBrands(ctx); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetBrand(ctx, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.OfficialDomain != "operator-edited.example.com" {
		t.Fatalf("expected operator edit to survive re-seed, got %s", got.OfficialDomain)
	}
}
