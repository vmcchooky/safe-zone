package risk

import (
	"time"

	"safe-zone/internal/analysis"
)

type CacheStatus struct {
	Configured         bool   `json:"configured"`
	Status             string `json:"status"`
	Error              string `json:"error,omitempty"`
	UsedMemoryBytes    uint64 `json:"used_memory_bytes,omitempty"`
	MaxMemoryBytes     uint64 `json:"maxmemory_bytes,omitempty"`
	MaxMemoryPolicy    string `json:"maxmemory_policy,omitempty"`
	EvictedKeys        uint64 `json:"evicted_keys"`
	EvictionPolicySafe *bool  `json:"eviction_policy_safe,omitempty"`
	ObservabilityError string `json:"observability_error,omitempty"`
}

type AnalysisConfigReloadStatus struct {
	Enabled          bool   `json:"enabled"`
	Channel          string `json:"channel,omitempty"`
	PollInterval     string `json:"poll_interval,omitempty"`
	NodeRole         string `json:"node_role,omitempty"`
	Revision         string `json:"revision,omitempty"`
	LastReloadSource string `json:"last_reload_source,omitempty"`
	LastReloadAt     string `json:"last_reload_at,omitempty"`
	RedisConfigured  bool   `json:"redis_configured"`
	StoreConfigured  bool   `json:"store_configured"`
	SubscriberActive bool   `json:"subscriber_active"`
	ReconcilerActive bool   `json:"reconciler_active"`
}

type analysisCacheEntry struct {
	Result           analysis.Result `json:"result"`
	FeedRevision     string          `json:"feed_revision,omitempty"`
	BrandRevision    string          `json:"brand_revision,omitempty"`
	AnalysisRevision string          `json:"analysis_revision,omitempty"`
	ConfigRevision   string          `json:"config_revision,omitempty"`
	ModelRevision    string          `json:"model_revision,omitempty"`
	OSINTCheckedAt   string          `json:"osint_checked_at,omitempty"`
	EnrichedAt       string          `json:"enriched_at,omitempty"`
	// AssessedAt marks when this evaluation was materialized. Background
	// writers compare it (with the markers above) against their snapshot
	// time and stand down when the cache is newer (PR-05/M1).
	AssessedAt string `json:"assessed_at,omitempty"`
}

type enrichmentJob struct {
	Domain         string
	Result         analysis.Result
	FeedRevision   string
	BrandRevision  string
	ConfigRevision string
	ModelRevision  string
	// QueuedAt marks when the job snapshot was taken. The worker refuses
	// to overwrite cache entries assessed after this time.
	QueuedAt string
}

// cacheEpoch is the set of revisions a cached entry must match. Known is
// false only when the revision could not be read: an unreadable revision
// never equals a stored one, so partial Redis failures fail closed to a
// miss instead of serving stale entries (PR-05/M2).
type cacheEpoch struct {
	AnalysisRevision string
	ConfigRevision   string
	ModelRevision    string
	FeedRevision     string
	FeedKnown        bool
	BrandRevision    string
	BrandKnown       bool
}

func entryMatchesRevision(entry analysisCacheEntry, current cacheEpoch) bool {
	if entry.Result.Domain == "" {
		return false
	}
	if entry.AnalysisRevision != current.AnalysisRevision ||
		entry.ConfigRevision != current.ConfigRevision ||
		entry.ModelRevision != current.ModelRevision {
		return false
	}
	if !current.FeedKnown || !current.BrandKnown {
		return false
	}
	return entry.FeedRevision == current.FeedRevision &&
		entry.BrandRevision == current.BrandRevision
}

// entryAssessedAt returns the newest materialization marker on an entry.
// Zero time when the entry predates markers.
func entryAssessedAt(entry analysisCacheEntry) time.Time {
	newest := time.Time{}
	for _, raw := range []string{entry.AssessedAt, entry.EnrichedAt, entry.OSINTCheckedAt} {
		if raw == "" {
			continue
		}
		if ts, err := time.Parse(time.RFC3339Nano, raw); err == nil && ts.After(newest) {
			newest = ts
		}
	}
	return newest
}

// jobQueuedAt parses a job snapshot time. Unparseable means oldest: the
// worker proceeds and the CAS guard decides against the live entry.
func jobQueuedAt(raw string) time.Time {
	ts, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}
	}
	return ts
}
