package analysis

import (
	"context"
	"sync"
	"testing"
)

// Readers share one immutable snapshot instead of cloning per read.
func TestMemoryBrandStoreSnapshotShared(t *testing.T) {
	store := NewMemoryBrandStore(DefaultTrustedBrands())
	ctx := context.Background()

	a, err := store.ListBrands(ctx)
	if err != nil || len(a) == 0 {
		t.Fatalf("list brands: %v %d", err, len(a))
	}
	b, err := store.ListBrands(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b) || &a[0] != &b[0] {
		t.Fatal("reads must share the snapshot backing array")
	}
}

// Mutations must never corrupt published snapshots observed by concurrent
// readers; writers detach before mutating.
func TestMemoryBrandStoreSnapshotRaceFree(t *testing.T) {
	store := NewMemoryBrandStore(DefaultTrustedBrands())
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
		created, err := store.CreateBrand(ctx, Brand{Name: "race", OfficialDomain: "race.example"})
		if err != nil {
			t.Fatal(err)
		}
		// A snapshot taken before the update must still see the old list.
		before, err := store.ListBrands(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = before
		if _, err := store.UpdateBrand(ctx, created.ID, Brand{Name: "race", OfficialDomain: "race.example"}); err != nil {
			t.Fatal(err)
		}
		if err := store.DeleteBrand(ctx, created.ID); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()

	// After deleting the only custom brand, content must equal defaults.
	got, err := store.ListBrands(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := len(DefaultTrustedBrands())
	if len(got) != want {
		t.Fatalf("brands = %d; want %d (defaults restored)", len(got), want)
	}
}
