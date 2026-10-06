package risk

import (
	"context"
	"time"

	"safe-zone/internal/ai"
	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/domaintrie"
	"safe-zone/internal/osint"
	"safe-zone/internal/store"
)

// AdblockTrieOverride replaces the in-memory adblock trie. Production flows
// must go through syncAdblockLists; this seam exists so transport-level
// tests (e.g. the dns-resolver /v1/policy endpoint) can pin trie contents
// without a network sync. A nil trie is normalized to an empty trie so
// Policy never observes a nil pointer.
func (s *Service) AdblockTrieOverride(trie *domaintrie.Trie) {
	if trie == nil {
		trie = domaintrie.NewTrie()
	}
	s.adblockTrie.Store(trie)
}

// StoreDB returns the underlying SQLite store, or nil if not configured.
func (s *Service) StoreDB() *store.DB {
	if s == nil {
		return nil
	}
	return s.store
}

// AIClient returns the Gemini AI client, or nil if not configured.
func (s *Service) AIClient() *ai.Client {
	if s == nil {
		return nil
	}
	s.syncAIClient()
	s.aiMu.Lock()
	defer s.aiMu.Unlock()
	if s.ai == nil || !s.ai.Enabled() {
		return nil
	}
	return s.ai
}

// RedisCache returns the Redis cache client, or nil if not configured.
func (s *Service) RedisCache() *cache.Redis {
	if s == nil {
		return nil
	}
	return s.redis
}

// OSINT returns the public-evidence lookup service, or nil when disabled.
func (s *Service) OSINT() *osint.Service {
	if s == nil {
		return nil
	}
	return s.osint
}

func (s *Service) OSINTEvidence(ctx context.Context, domain string, force bool) (osint.Report, error) {
	if s == nil || s.osint == nil || !s.osint.Enabled() {
		return osint.Report{Domain: domain, Enabled: false}, nil
	}
	if !force {
		if report, ok := s.osint.Cached(ctx, domain); ok {
			report.CacheHit = true
			return report, nil
		}
		if report, ok := s.storedOSINTEvidence(domain); ok {
			return report, nil
		}
	}
	return s.osint.Lookup(ctx, domain, force)
}

func (s *Service) storedOSINTEvidence(domain string) (osint.Report, bool) {
	if s == nil || s.store == nil || !s.store.Enabled() {
		return osint.Report{}, false
	}
	normalized, err := analysis.NormalizeDomain(domain)
	if err != nil {
		return osint.Report{}, false
	}
	items, err := s.store.ListOSINTEvidence(context.Background(), normalized, time.Now())
	if err != nil || len(items) == 0 {
		return osint.Report{}, false
	}
	evidence := make([]osint.Evidence, 0, len(items))
	for _, item := range items {
		evidence = append(evidence, osint.Evidence{
			Domain:       item.Domain,
			SourceURL:    item.SourceURL,
			SourceTitle:  item.SourceTitle,
			SourceType:   item.SourceType,
			Confidence:   item.Confidence,
			MatchedTerms: item.MatchedTerms,
			RetrievedAt:  item.RetrievedAt,
		})
	}
	return osint.Report{
		Domain:      normalized,
		Enabled:     true,
		CacheHit:    true,
		ShouldBlock: osint.HasStrongWarning(evidence),
		Evidence:    evidence,
		CheckedAt:   evidence[0].RetrievedAt,
		ExpiresAt:   items[0].ExpiresAt,
		VerdictImpact: func() string {
			if osint.HasStrongWarning(evidence) {
				return "escalate_malicious"
			}
			return ""
		}(),
	}, true
}

// Whitelist returns the whitelist client.
func (s *Service) Whitelist() *Whitelist {
	if s == nil {
		return nil
	}
	return s.whitelist
}
