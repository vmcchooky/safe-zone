package risk

import (
	"context"
	"path/filepath"
	"testing"

	"safe-zone/internal/store"
)

func newTestDB(tb testing.TB) *store.DB {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "test.db")
	db, err := store.New(path, 30)
	if err != nil {
		tb.Fatalf("failed to create test db: %v", err)
	}
	tb.Cleanup(func() {
		if err := db.Close(); err != nil {
			tb.Fatalf("failed to close test db: %v", err)
		}
	})
	return db
}

func TestWhitelistHybridCorrectness(t *testing.T) {
	db := newTestDB(t)
	wl := NewWhitelist(db)

	domains := []string{"google.com", "facebook.com", "my-awesome-domain.co.uk"}

	// Save to DB
	if err := db.UpdateWhitelist(context.Background(), domains); err != nil {
		t.Fatalf("failed to populate whitelist table: %v", err)
	}

	// Load into Bloom Filter
	if err := wl.LoadFromDB(); err != nil {
		t.Fatalf("failed to load Bloom Filter: %v", err)
	}

	tests := []struct {
		domain   string
		expected bool
	}{
		{"google.com", true},
		{"facebook.com", true},
		{"mail.google.com", true}, // subdomain inheritance
		{"deep.sub.facebook.com", true},
		{"my-awesome-domain.co.uk", true},
		{"sub.my-awesome-domain.co.uk", true},
		{"evil.com", false},
		{"google.co.uk", false},
		{"facebook.co", false},
	}

	for _, tc := range tests {
		t.Run(tc.domain, func(t *testing.T) {
			actual := wl.IsAllowed(tc.domain)
			if actual != tc.expected {
				t.Errorf("expected IsAllowed(%q) to be %v, got %v", tc.domain, tc.expected, actual)
			}
		})
	}
}

func TestWhitelistFallbackCorrectness(t *testing.T) {
	// Without SQLite DB
	wl := NewWhitelist(nil)

	// Fallback to allowed map
	wl.allowed["google.com"] = struct{}{}

	if !wl.IsAllowed("google.com") {
		t.Fatal("expected google.com to be allowed in fallback mode")
	}
	if !wl.IsAllowed("sub.google.com") {
		t.Fatal("expected sub.google.com to be allowed in fallback mode")
	}
	if wl.IsAllowed("evil.com") {
		t.Fatal("expected evil.com to not be allowed in fallback mode")
	}
}

func BenchmarkWhitelistLookup(b *testing.B) {
	db := newTestDB(b)
	wl := NewWhitelist(db)

	domains := []string{"google.com", "facebook.com", "apple.com", "amazon.com", "github.com"}
	_ = db.UpdateWhitelist(context.Background(), domains)
	_ = wl.LoadFromDB()

	b.ResetTimer()
	for b.Loop() {
		// Mostly negative hits in real-world DNS blocking (which skips SQLite lookup)
		wl.IsAllowed("not-whitelisted-domain.com")
	}
}
