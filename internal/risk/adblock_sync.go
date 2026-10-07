package risk

import (
	"context"
	"net/http"
	"os"
	"time"

	"safe-zone/internal/config"
	"safe-zone/internal/domaintrie"
	"safe-zone/internal/feed"
	"safe-zone/internal/logjson"
	"safe-zone/internal/netguard"
)

func (s *Service) isAdblockEnabled() bool {
	return s.adblockEnabled.Load()
}

// refreshAdblockEnabled reads the adblock_enabled flag from store/env
// and caches it atomically. Safe to call from any goroutine.
func (s *Service) refreshAdblockEnabled() {
	if s.store == nil || !s.store.Enabled() {
		s.adblockEnabled.Store(config.Bool(envAdblockEnabled, true))
		return
	}
	val, err := s.store.GetSystemConfig(context.Background(), "adblock_enabled")
	if err != nil {
		// Keep the current value. Falling back to the environment here
		// re-enabled adblock 30 seconds after an operator disabled it, and a
		// read error must never move an operator's switch in either
		// direction.
		logjson.Warn("adblock enabled refresh failed; keeping the value in force", map[string]any{
			"service": "risk",
			"error":   err.Error(),
		})
		return
	}
	if val == "" {
		s.adblockEnabled.Store(config.Bool(envAdblockEnabled, true))
		return
	}
	s.adblockEnabled.Store(val == "true" || val == "1")
}

// refreshAdblockMatchMode reconciles the persisted match mode with the
// process default and caches the result.
//
// The store wins over the environment for the same reason the enable flag
// does: an operator switching the mode at runtime must not have it silently
// reverted by the next refresh. A read error keeps the current value rather
// than reverting to the environment.
func (s *Service) refreshAdblockMatchMode() {
	if s.store == nil || !s.store.Enabled() {
		s.adblockMatchMode.Store(string(parseAdblockMatchMode(config.String(envAdblockMatchMode, string(adblockMatchModeSuffix)))))
		return
	}
	val, err := s.store.GetSystemConfig(context.Background(), systemConfigAdblockMatchMode)
	if err != nil {
		logjson.Warn("adblock match mode refresh failed; keeping the mode in force", map[string]any{
			"service": "risk",
			"error":   err.Error(),
		})
		return
	}
	if val == "" {
		s.adblockMatchMode.Store(string(parseAdblockMatchMode(config.String(envAdblockMatchMode, string(adblockMatchModeSuffix)))))
		return
	}
	s.adblockMatchMode.Store(string(parseAdblockMatchMode(val)))
}

// runAdblockConfigSync periodically refreshes the adblock_enabled flag and
// the scoped content-exception snapshot. No extra goroutine is needed for
// exception reloads.
func (s *Service) runAdblockConfigSync() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.lifecycleCtx.Done():
			return
		case <-ticker.C:
			s.refreshAdblockEnabled()
			s.refreshAdblockMatchMode()
			s.refreshAdblockSourcePolicies()
			s.reloadAdblockExceptions()
		}
	}
}

func (s *Service) runAdblockSync() {
	// First initial sync immediately if enabled
	if s.isAdblockEnabled() {
		s.syncAdblockLists()
	}

	ticker := time.NewTicker(config.DurationSeconds("SAFE_ZONE_ADBLOCK_INTERVAL_SECONDS", 12*time.Hour))
	defer ticker.Stop()

	for {
		select {
		case <-s.lifecycleCtx.Done():
			return
		case <-s.adblockResync:
			// An operator changed a switch that only takes effect on a rebuilt
			// rule set. Rebuild now instead of making them wait out the
			// interval, which is hours in the default configuration.
			s.rebuildAdblockRules()
		case <-ticker.C:
			s.rebuildAdblockRules()
		}
	}
}

// rebuildAdblockRules rebuilds the trie with the switches currently in force.
//
// The match mode is deliberately NOT re-read from the environment here. The
// environment is process-scoped, so re-reading it returns the value the
// process started with and would silently revert an operator change that came
// from the store. refreshAdblockMatchMode already reconciles the two, and the
// resync path runs after that setter.
//
// When adblock is disabled the trie is emptied so a stale rule set cannot
// keep matching.
func (s *Service) rebuildAdblockRules() {
	if !s.isAdblockEnabled() {
		s.adblockTrie.Store(domaintrie.NewTrie())
		return
	}
	s.syncAdblockLists()
}

func (s *Service) syncAdblockLists() {
	sources := config.String("SAFE_ZONE_ADBLOCK_SOURCES", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")
	sourceList := splitAdblockSources(sources)
	if len(sourceList) == 0 {
		return
	}
	// #nosec G115 -- len(sourceList) will never exceed max int32
	s.adblockSrcCount.Store(int32(len(sourceList)))

	// Outbound fetches for adblock sources go through the shared outbound
	// guard; feed.OpenSourceResponseWithin validates every URL and redirect
	// hop against the same policy.
	client := s.adblockHTTPClient
	if client == nil {
		client = netguard.NewHTTPClient(nil, 60*time.Second, false)
	}
	metaPath := s.adblockMetaPath()
	currentMeta := loadAdblockMeta(metaPath)

	adTrie := s.adblockTrie.Load()
	currentCount := 0
	if adTrie != nil {
		currentCount = adTrie.Count()
	}

	newTrie := domaintrie.NewTrie()
	successCount := 0
	networkCount := 0
	cachedCount := 0
	nextMeta := make(map[string]adblockSourceMeta, len(sourceList))

	for _, source := range sourceList {
		sourceID := canonicalSourceID(source)
		sourceCategory, sourceScope, sourceOrigin := s.resolveAdblockSourcePolicy(source)
		func() {
			if !isRemoteAdblockSource(source) {
				reader, closeReader, err := feed.OpenSourceWithin(s.lifecycleCtx, source, client, s.adblockDataRoot, 100*1024*1024, false)
				if err != nil {
					logjson.Warn("failed to fetch adblock source", map[string]any{"source": source, "error": err.Error()})
					return
				}
				defer closeReader()
				if err := s.parseAdblockSource(reader, newTrie, sourceID, sourceCategory, sourceScope, sourceOrigin); err != nil {
					logjson.Warn("error while scanning adblock source", map[string]any{"source": source, "error": err.Error()})
					return
				}
				successCount++
				return
			}

			requestHeaders := make(http.Header)
			meta := currentMeta[source]
			if meta.ETag != "" {
				requestHeaders.Set("If-None-Match", meta.ETag)
			}
			if meta.LastModified != "" {
				requestHeaders.Set("If-Modified-Since", meta.LastModified)
			}

			response, err := feed.OpenSourceResponseWithin(s.lifecycleCtx, source, client, s.adblockDataRoot, 100*1024*1024, requestHeaders, false)
			if err == nil && response.StatusCode == http.StatusNotModified {
				if s.loadAdblockSourceCache(source, newTrie, sourceID, sourceCategory, sourceScope, sourceOrigin) {
					successCount++
					cachedCount++
					nextMeta[source] = meta
					return
				}
				response, err = feed.OpenSourceResponseWithin(s.lifecycleCtx, source, client, s.adblockDataRoot, 100*1024*1024, nil, false)
			}

			if err == nil {
				if response.Close != nil {
					defer response.Close()
				}
				if response.Reader != nil {
					if err := s.saveAdblockSourceCache(source, response.Reader, newTrie, sourceID, sourceCategory, sourceScope, sourceOrigin); err != nil {
						logjson.Warn("failed to refresh adblock source cache", map[string]any{"source": source, "error": err.Error()})
						return
					}
					successCount++
					networkCount++
					nextMeta[source] = adblockSourceMetaFromHeader(response.Header)
					return
				}
			} else {
				logjson.Warn("failed to fetch adblock source", map[string]any{"source": source, "error": err.Error()})
			}

			if s.loadAdblockSourceCache(source, newTrie, sourceID, sourceCategory, sourceScope, sourceOrigin) {
				successCount++
				cachedCount++
				nextMeta[source] = meta
				return
			}
		}()
	}

	// Publish only on at least one fully successful source. A non-zero rule
	// count alone never counts as success: failed sources contribute zero
	// rules through staging, and a scanner error must not publish a partial
	// trie with sources_ok=0.
	if successCount > 0 {
		s.adblockTrie.Store(newTrie)
		s.adblockOKCount.Store(int32(successCount))
		s.adblockLastSync.Store(time.Now())
		s.adblockLastSyncOK.Store(true)

		s.saveAdblockCache(newTrie)
		s.saveAdblockMeta(metaPath, nextMeta)

		logjson.Info("adblock trie synchronized", map[string]any{
			"domains":              newTrie.Count(),
			"sources_ok":           successCount,
			"sources_network":      networkCount,
			"sources_cached_reuse": cachedCount,
		})
	} else {
		s.adblockOKCount.Store(int32(successCount))
		s.adblockLastSync.Store(time.Now())
		if currentCount == 0 {
			if s.loadAdblockCache(newTrie) {
				s.adblockTrie.Store(newTrie)
				s.adblockLastSyncOK.Store(true)
				logjson.Info("adblock trie loaded from cache", map[string]any{"domains": newTrie.Count()})
			} else {
				s.adblockLastSyncOK.Store(false)
				logjson.Warn("adblock synchronization failed entirely", nil)
			}
		} else {
			s.adblockLastSyncOK.Store(false)
			logjson.Warn("adblock network sync failed, retaining existing rules", map[string]any{"domains": currentCount})
		}
	}
}

func (s *Service) saveAdblockCache(trie *domaintrie.Trie) {
	if err := s.ensureAdblockDataRoot(); err != nil {
		logjson.Warn("failed to create adblock data root", map[string]any{"error": err.Error()})
		return
	}
	finalPath := s.adblockCachePath()
	f, tmpPath, err := createReplaceTempFile(finalPath)
	if err != nil {
		logjson.Warn("failed to create adblock cache temp file", map[string]any{"error": err.Error()})
		return
	}
	_, err = trie.WriteToV2(f)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		logjson.Warn("failed to write adblock cache temp file", map[string]any{"error": err.Error()})
		return
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		logjson.Warn("failed to sync adblock cache temp file", map[string]any{"error": err.Error()})
		return
	}
	_ = f.Close()
	if err := replaceFile(tmpPath, finalPath); err != nil {
		logjson.Warn("failed to rename adblock cache temp file", map[string]any{"error": err.Error()})
		_ = os.Remove(tmpPath)
	}
}

func (s *Service) loadAdblockCache(trie *domaintrie.Trie) bool {
	f, err := os.Open(s.adblockCachePath())
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	// parseAdblockCache detects the v2 header; a legacy domains-only file
	// reloads with suffix/unknown/block/legacy-cache semantics so a degraded
	// network sync can never silently flip match behavior.
	return s.parseAdblockCache(f, trie)
}
