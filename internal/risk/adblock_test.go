package risk

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
	"safe-zone/internal/domaintrie"
	"safe-zone/internal/store"
)

// newTestServiceWithAdblock creates a service with a pre-populated adblock trie.
func newTestServiceWithAdblock(t *testing.T, domains []string) *Service {
	t.Helper()

	tempDir := t.TempDir()
	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")

	dbPath := filepath.Join(tempDir, "test.db")
	storeDB, err := store.New(dbPath, 30)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}

	// Enable adblock via system config
	if err := storeDB.SetSystemConfig(context.Background(), "adblock_enabled", "true"); err != nil {
		t.Fatalf("failed to set adblock_enabled: %v", err)
	}

	service := NewService(Options{
		AnalysisConfig:  config.DefaultAnalysisConfig(),
		RedisTimeout:    10 * time.Millisecond,
		TTLAllowed:      time.Hour,
		TTLSuspicious:   time.Hour,
		TTLBlocked:      time.Hour,
		RecentLimit:     10,
		Store:           storeDB,
		AdblockFileRoot: tempDir,
	})

	// Manually populate the adblock trie (bypass network sync)
	trie := domaintrie.NewTrie()
	for _, d := range domains {
		trie.Add(d)
	}
	service.adblockTrie.Store(trie)

	t.Cleanup(func() {
		_ = service.Close()
	})

	return service
}

func TestAdblockTrieMatchInAnalyze(t *testing.T) {
	service := newTestServiceWithAdblock(t, []string{
		"ads.example.com",
		"tracker.doubleclick.net",
	})

	result := service.Analyze(context.Background(), "ads.example.com", ClientInfo{})
	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected malicious verdict for adblocked domain, got %s", result.Verdict)
	}
	if result.Score != 100 {
		t.Fatalf("expected score 100, got %d", result.Score)
	}
	if len(result.Reasons) == 0 || result.Reasons[0] != "adblock" {
		t.Fatalf("expected reason 'adblock', got %v", result.Reasons)
	}
	if result.Result.Category != "adware" {
		t.Fatalf("expected category 'adware', got %s", result.Result.Category)
	}
}

func TestAdblockTrieMatchInPolicy(t *testing.T) {
	service := newTestServiceWithAdblock(t, []string{
		"ads.example.com",
	})

	pol := service.Policy(context.Background(), "ads.example.com", ClientInfo{})
	if pol.Policy != "block" {
		t.Fatalf("expected policy 'block' for adblocked domain, got %s", pol.Policy)
	}
	if pol.Result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected malicious verdict in policy, got %s", pol.Result.Verdict)
	}
	if pol.Result.Category != "adware" {
		t.Fatalf("expected category 'adware', got %s", pol.Result.Category)
	}
}

func TestAdblockDisabled(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")

	dbPath := filepath.Join(tempDir, "test.db")
	storeDB, err := store.New(dbPath, 30)
	if err != nil {
		t.Fatal(err)
	}
	// Explicitly disable adblock
	if err := storeDB.SetSystemConfig(context.Background(), "adblock_enabled", "false"); err != nil {
		t.Fatal(err)
	}

	service := NewService(Options{
		AnalysisConfig:  config.DefaultAnalysisConfig(),
		RedisTimeout:    10 * time.Millisecond,
		TTLAllowed:      time.Hour,
		TTLSuspicious:   time.Hour,
		TTLBlocked:      time.Hour,
		RecentLimit:     10,
		Store:           storeDB,
		AdblockFileRoot: tempDir,
	})
	t.Cleanup(func() { _ = service.Close() })

	// Manually add a domain to the trie
	trie := domaintrie.NewTrie()
	trie.Add("ads.example.com")
	service.adblockTrie.Store(trie)

	// Even though the trie has the domain, adblock is disabled
	result := service.Analyze(context.Background(), "ads.example.com", ClientInfo{})
	if result.Verdict == analysis.VerdictMalicious && len(result.Reasons) > 0 && result.Reasons[0] == "adblock" {
		t.Fatal("expected adblock to be disabled; domain should not be blocked via adblock")
	}
}

func TestAdblockWhitelistPriority(t *testing.T) {
	service := newTestServiceWithAdblock(t, []string{
		"ads.example.com",
	})

	// Whitelist the same domain via DB
	if err := service.store.UpdateWhitelist(context.Background(), []string{"ads.example.com"}); err != nil {
		t.Fatalf("failed to update whitelist: %v", err)
	}
	if err := service.whitelist.LoadFromDB(); err != nil {
		t.Fatalf("failed to reload whitelist: %v", err)
	}

	result := service.Analyze(context.Background(), "ads.example.com", ClientInfo{})
	// Whitelist check comes before adblock, so it should be safe
	if result.Verdict != analysis.VerdictSafe {
		t.Fatalf("expected whitelisted domain to bypass adblock, got verdict %s", result.Verdict)
	}
	if len(result.Reasons) == 0 || result.Reasons[0] != "whitelisted" {
		t.Fatalf("expected reason 'whitelisted', got %v", result.Reasons)
	}
}

func TestAdblockOverridePriority(t *testing.T) {
	service := newTestServiceWithAdblock(t, []string{
		"ads.example.com",
	})

	// Add admin override to allow the domain
	if err := service.UpsertOverride("ads.example.com", "allow", "false positive"); err != nil {
		t.Fatalf("upsert override failed: %v", err)
	}

	result := service.Analyze(context.Background(), "ads.example.com", ClientInfo{})
	// Override check comes before adblock, so it should be safe
	if result.Verdict != analysis.VerdictSafe {
		t.Fatalf("expected override-allowed domain to bypass adblock, got verdict %s", result.Verdict)
	}
	if len(result.Reasons) == 0 || result.Reasons[0] != "admin override: allow (false positive)" {
		t.Fatalf("expected admin override allow reason, got %v", result.Reasons)
	}
}

func TestAdblockSubdomainMatch(t *testing.T) {
	service := newTestServiceWithAdblock(t, []string{
		"ads.example.com",
	})

	// Subdomains of blocked domains should also be blocked
	result := service.Analyze(context.Background(), "sub.ads.example.com", ClientInfo{})
	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected subdomain of adblocked domain to be blocked, got %s", result.Verdict)
	}
	if len(result.Reasons) == 0 || result.Reasons[0] != "adblock" {
		t.Fatalf("expected reason 'adblock', got %v", result.Reasons)
	}
}

func TestAdblockSafetyGuardRejectsTLD(t *testing.T) {
	service := newTestServiceWithAdblock(t, []string{
		"com",    // single-label TLD
		"com.vn", // multi-label public suffix
	})

	// "com" should have been rejected at trie.Add level
	result := service.Analyze(context.Background(), "google.com", ClientInfo{})
	for _, r := range result.Reasons {
		if r == "adblock" {
			t.Fatal("single-label TLD 'com' should have been rejected by safety guard")
		}
	}

	result2 := service.Analyze(context.Background(), "example.com.vn", ClientInfo{})
	for _, r := range result2.Reasons {
		if r == "adblock" {
			t.Fatal("multi-label public suffix 'com.vn' should have been rejected by safety guard")
		}
	}
}

func TestAdblockPolicyWhitelistPriority(t *testing.T) {
	service := newTestServiceWithAdblock(t, []string{
		"ads.example.com",
	})

	// Whitelist the same domain via DB
	if err := service.store.UpdateWhitelist(context.Background(), []string{"ads.example.com"}); err != nil {
		t.Fatalf("failed to update whitelist: %v", err)
	}
	if err := service.whitelist.LoadFromDB(); err != nil {
		t.Fatalf("failed to reload whitelist: %v", err)
	}

	pol := service.Policy(context.Background(), "ads.example.com", ClientInfo{})
	if pol.Policy != "allow" {
		t.Fatalf("expected whitelisted domain to bypass adblock in Policy, got %s", pol.Policy)
	}
}
