package risk

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
	"safe-zone/internal/domaintrie"
	"safe-zone/internal/store"
)

// newFuzzService builds one Service shared by every fuzz iteration: a real
// SQLite store in a throwaway directory, adblock network sync disabled, and a
// manually populated adblock trie so MatchRuleDetail runs on every iteration.
func newFuzzService(f *testing.F) *Service {
	f.Helper()

	tempDir, err := os.MkdirTemp("", "fuzz-risk-*")
	if err != nil {
		f.Fatalf("create temp dir: %v", err)
	}
	storeDB, err := store.New(filepath.Join(tempDir, "fuzz.db"), 30)
	if err != nil {
		f.Fatalf("open store: %v", err)
	}
	f.Cleanup(func() {
		_ = storeDB.Close()
		_ = os.RemoveAll(tempDir)
	})

	f.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")
	service := NewService(Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		RedisTimeout:       10 * time.Millisecond,
		TTLAllowed:         time.Hour,
		TTLSuspicious:      time.Hour,
		TTLBlocked:         time.Hour,
		RecentLimit:        10,
		Store:              storeDB,
		AdblockFileRoot:    tempDir,
		PolicySemantics:    PolicySemanticsSeparated,
		DisableAdblockSync: true,
	})
	f.Cleanup(func() {
		_ = service.Close()
	})

	trie := domaintrie.NewTrie()
	for _, d := range []string{"ads.example", "*.tracker.example"} {
		trie.Add(d)
	}
	service.adblock.adblockTrie.Store(trie)
	return service
}

// FuzzPolicyMatch drives the whole policy pipeline with abnormal domains and
// client identities. DNS question names and client IDs are attacker-chosen
// bytes, so Policy must never panic, must answer only allow or block, and
// must be deterministic for the same input.
func FuzzPolicyMatch(f *testing.F) {
	service := newFuzzService(f)

	seeds := []struct{ domain, ip, clientID string }{
		{"example.com", "192.0.2.10", "smoke"},
		{"ads.example", "192.0.2.10", "smoke"},
		{"a.tracker.example", "192.0.2.10", "smoke"},
		{"", "192.0.2.10", ""},
		{".", "", ""},
		{"..", "not-an-ip", "client/../traversal"},
		{"UPPER.EXAMPLE.COM", "999.999.999.999", ""},
		{"xn--80ak6aa92e.com", "::1", "client with spaces"},
		{"a\x00b.example", "[::ffff:192.0.2.1]", "\x00\x01"},
	}
	for _, s := range seeds {
		f.Add(s.domain, s.ip, s.clientID)
	}

	f.Fuzz(func(t *testing.T, domain, ip, clientID string) {
		client := ClientInfo{IP: ip, ClientID: clientID}
		first := service.Policy(context.Background(), domain, client)
		second := service.Policy(context.Background(), domain, client)

		if first.Policy != "allow" && first.Policy != "block" {
			t.Fatalf("Policy(%q) returned %q, want allow or block", domain, first.Policy)
		}
		if first.Policy != second.Policy || first.CacheHit != second.CacheHit {
			t.Fatalf("Policy(%q) nondeterministic: %+v vs %+v", domain, first.Policy, second.Policy)
		}
		// The reported domain is either the caller's spelling or its
		// normalized form — never a different name.
		if first.Domain != domain {
			if normalized, err := analysis.NormalizeDomain(domain); err != nil || first.Domain != normalized {
				t.Fatalf("Policy(%q) reported domain %q", domain, first.Domain)
			}
		}
	})
}
