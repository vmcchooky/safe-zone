package risk

import (
	"net/http"
	"sync"
	"sync/atomic"

	"safe-zone/internal/domaintrie"
)

// AdblockEngine owns all adblock subsystem state: the rule trie, sync
// metadata, per-source policies, shadow observation counters and the content
// exception snapshot. Service holds exactly one, constructed in NewService;
// methods on Service that need adblock behavior delegate explicitly.
type AdblockEngine struct {
	adblockDataRoot   string
	adblockHTTPClient *http.Client

	// policySemantics is snapshotted from Service at construction.
	// Service.policySemantics is write-once in NewService, so the copy
	// cannot drift; the engine needs it for shadow-observation gating
	// without reaching back into the Service.
	policySemantics PolicySemantics

	// Adblock typed-rule state. adblockMatchMode mirrors
	// SAFE_ZONE_ADBLOCK_MATCH_MODE (default suffix); adblockSourcePolicies
	// holds the parsed per-source policies.
	//
	// adblockSourcePolicies is behind an atomic pointer because it is now
	// swappable at runtime: the store-backed refresh replaces the whole set
	// when an operator changes it, while the adblock sync goroutine may be
	// concurrently reading it to scope an incoming rule. The set itself is
	// treated as immutable once published; a change publishes a new set
	// rather than mutating the existing map.
	adblockMatchMode      atomic.Value // string (adblockMatchMode)
	adblockSourcePolicies atomic.Pointer[adblockSourcePolicySet]

	adblockTrie       atomic.Pointer[domaintrie.Trie]
	adblockEnabled    atomic.Bool
	adblockLastSync   atomic.Value
	adblockLastSyncOK atomic.Bool
	adblockSrcCount   atomic.Int32
	adblockOKCount    atomic.Int32

	// adblockResync lets an operator request a rule rebuild without blocking
	// the caller. A one-slot buffer coalesces repeated requests, so flipping
	// match mode several times still costs at most one rebuild.
	adblockResync chan struct{}

	// Shadow exact/suffix observation (PR3B-lite). The enable flag is
	// startup-only; the counters below are observation-only aggregates and
	// never feed back into enforcement.
	adblockShadowExactEnabled bool
	adblockShadowStillBlock   atomic.Uint64
	adblockShadowWouldAllow   atomic.Uint64
	adblockShadowPreserved    atomic.Uint64
	adblockShadowUnavailable  atomic.Uint64
	adblockShadowExcOverlap   atomic.Uint64

	// Scoped content exceptions (PR3A). The snapshot pointer is published
	// atomically; reload writers are serialized by adblockExcMu. Request
	// paths only Load plus RAM lookup.
	adblockExceptionsFile       string
	adblockExceptionsPinned     bool
	adblockExceptions           atomic.Pointer[adblockExceptionSnapshot]
	adblockExcMu                sync.Mutex
	adblockExceptionsConfigured atomic.Bool
	adblockExcLastReload        atomic.Value // time.Time
	adblockExcLastOK            atomic.Bool
	adblockExcLastErr           atomic.Value // string (bounded error class)
	adblockExcReloadSuccesses   atomic.Uint64
	adblockExcReloadFailures    atomic.Uint64
	adblockExcMatches           atomic.Uint64
}
