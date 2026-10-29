package risk

import (
	"context"
	"testing"

	"safe-zone/internal/domaintrie"
)

// TestAdblockSyncRefusesBlockedSource proves the adblock consumer wiring
// honours the shared outbound guard: a source pointing into the metadata or
// private address space is refused before any dial, and the running rule set
// stays unchanged — a blocked source must never silently empty or alter the
// trie. The feed layer's own guard is tested in internal/feed; this test
// exists because the adblock path is a separate consumer that could drift.
func TestAdblockSyncRefusesBlockedSource(t *testing.T) {
	service := newManualAdblockSyncService(t, nil)
	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "http://169.254.169.254/latest/hosts,http://10.0.0.9/hosts")

	// Seed a known rule so "unchanged" is observable: the failed sync must
	// keep the previous trie rather than swapping in an empty one.
	seeded := domaintrie.NewTrie()
	seeded.Add("ads.example")
	service.adblock.adblockTrie.Store(seeded)

	service.adblock.syncAdblockLists(context.Background())

	trie := service.adblock.adblockTrie.Load()
	if trie == nil {
		t.Fatal("adblock trie disappeared after a blocked-source sync")
	}
	detail := trie.MatchRuleDetail("ads.example")
	if !detail.Matched {
		t.Fatal("failed sync replaced the rule set; the previous trie must be kept on refusal")
	}
}
