package store

import (
	"context"
	"sync"
	"testing"

	"safe-zone/internal/analysis"
)

// Snapshots are shared, not cloned: consecutive reads within TTL must
// observe the same backing array. Callers must treat it as read-only.
func TestBrandSnapshotSharedAcrossReads(t *testing.T) {
	db := newTestDB(t)
	store := NewBrandStore(db, nil, 0, 0)
	ctx := context.Background()

	a, err := store.ListBrands(ctx)
	if err != nil || len(a) == 0 {
		t.Fatalf("list brands: %v %d", err, len(a))
	}
	// The first read populates the cache; steady-state reads share it.
	b, err := store.ListBrands(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c, err := store.ListBrands(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != len(c) || &b[0] != &c[0] {
		t.Fatal("reads within TTL must share the snapshot backing array")
	}
}

// Concurrent reads racing creates, updates, deletes and invalidations must
// stay race-free and always observe a consistent list.
func TestBrandSnapshotConcurrentUse(t *testing.T) {
	db := newTestDB(t)
	store := NewBrandStore(db, nil, 0, 0)
	ctx := context.Background()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				brands, err := store.ListBrands(ctx)
				if err != nil {
					t.Errorf("list brands: %v", err)
					return
				}
				for _, b := range brands {
					_ = b.Name + b.OfficialDomain
					_ = len(b.AltDomains)
				}
			}
		}()
	}
	for i := 0; i < 10; i++ {
		created, err := store.CreateBrand(ctx, analysis.Brand{
			Name:           "racebrand",
			OfficialDomain: "racebrand.example",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.UpdateBrand(ctx, created.ID, analysis.Brand{
			Name:           "racebrand",
			OfficialDomain: "racebrand.example",
			AltDomains:     []string{"alt-racebrand.example"},
		}); err != nil {
			t.Fatal(err)
		}
		if err := store.DeleteBrand(ctx, created.ID); err != nil {
			t.Fatal(err)
		}
		store.invalidate(ctx)
	}
	close(stop)
	wg.Wait()
}
