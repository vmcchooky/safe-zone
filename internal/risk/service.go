package risk

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"safe-zone/internal/ai"
	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/config"
	"safe-zone/internal/correlation"
	"safe-zone/internal/domaintrie"
	"safe-zone/internal/feed"
	"safe-zone/internal/logjson"
	"safe-zone/internal/netguard"
	"safe-zone/internal/osint"
	"safe-zone/internal/store"
	"safe-zone/internal/tlsinspect"
	"safe-zone/internal/whois"

	"github.com/redis/go-redis/v9"
)

const recentAnalysisKey = "safe-zone:analysis:recent"
const defaultThreatFeedKey = "safe-zone:threat:feed"
const brandRevisionKey = "safe-zone:analysis:trusted-brands:revision"
const defaultAnalysisConfigReloadChannel = "safe-zone:config:analysis:updated"
const threatFeedReason = "matched local threat feed"

// sharedFeedApexReason marks an exact feed IOC on shared infrastructure as
// contextual evidence (FP-guard 2026-09, M7): the host was reported, but a
// whole CDN apex is never host-blocked on that alone.
const sharedFeedApexReason = "shared infrastructure host in threat feed (contextual, needs corroboration)"
const analysisAlgorithmRevision = "2026-09-cdn-fp-guard-v2"
const geminiKeySyncCooldown = 10 * time.Second
const defaultAnalysisConfigReloadPollInterval = 30 * time.Second
const analysisConfigReloadBackoffMin = 250 * time.Millisecond
const analysisConfigReloadBackoffMax = 5 * time.Second

// Fallbacks for the durations a caller can supply through Options without also
// supplying a default.
//
// The cache TTLs and the Redis timeout are used as-is, so a zero or negative value
// has a real and opposite effect at each site. go-redis attaches no expiry when the
// duration is not positive, so a zero TTL turns the analysis-verdict cache into a set
// of immortal keys; the config helper that supplies these values only falls back when
// the variable is unset or unparseable, so an explicit "0" reaches us intact. A zero
// Redis timeout is worse still: every cache call is wrapped in
// context.WithTimeout(ctx, 0), which is already expired.
//
// These match the defaults in env.go, and match the treatment RecentTTL and
// BrandCacheTTL already receive a few lines below in NewService.
const (
	defaultRedisTimeout       = 250 * time.Millisecond
	defaultCacheTTLAllowed    = 3 * time.Hour
	defaultCacheTTLSuspicious = time.Hour
	defaultCacheTTLBlocked    = 6 * time.Hour
)

const (
	analysisConfigReloadEventType = "analysis_config_updated"
	configReloadSourceStartup     = "startup"
	configReloadSourceLocalWrite  = "local_write"
	configReloadSourcePubSub      = "pubsub"
	configReloadSourceReconcile   = "reconcile"
)

var replaceFileLocks sync.Map

type Options struct {
	Redis           *cache.Redis
	RedisTimeout    time.Duration
	TTLAllowed      time.Duration
	TTLSuspicious   time.Duration
	TTLBlocked      time.Duration
	RecentLimit     int64
	RecentTTL       time.Duration
	ThreatFeedKey   string
	AIClient        *ai.Client
	AIProvider      string
	GeminiBaseURL   string
	GeminiAPIKey    string
	GeminiModel     string
	GeminiTimeout   time.Duration
	OllamaBaseURL   string
	OllamaModel     string
	OllamaTimeout   time.Duration
	WhitelistPath   string
	AdblockFileRoot string
	// AdblockHTTPClient optionally overrides the HTTP client used to fetch
	// remote adblock sources (tests inject a loopback-dialing client). When
	// nil, a shared outbound-guarded client is used.
	AdblockHTTPClient *http.Client
	// DisableAdblockSync prevents background source/cache synchronization for
	// isolated replay and tests that must not perform external I/O.
	DisableAdblockSync bool
	AnalysisConfig     config.AnalysisConfig
	Store              *store.DB
	BrandCacheTTL      time.Duration
	// Analysis config hot-reload orchestration.
	ConfigReloadChannel      string
	ConfigReloadPollInterval time.Duration
	ConfigReloadEnabled      bool
	NodeRole                 string
	// Enrichment (TLS + WHOIS)
	EnrichEnabled   bool
	EnrichTimeout   time.Duration
	EnrichQueueSize int
	WhoisCacheTTL   time.Duration
	// OSINT evidence lookup for API/dashboard paths.
	OSINT *osint.Service
	// Enrichment worker pool size. Defaults to 1 if not set.
	EnrichWorkers int
	// Immutable model bundle classifier and merge policy.
	MLClassifier analysis.DomainClassifier
	MLMode       analysis.MLMode
	MLCanary     MLCanaryConfig
	// URL ML is an independent, shadow-only specialist for caller-supplied URL
	// context. It never changes DNS or domain-only decisions.
	URLMLClassifier analysis.URLClassifier
	URLMLMode       analysis.MLMode
	URLMLShadow     URLMLShadowConfig
	// URLOpsBaseline is an optional frozen operational monitoring reference
	// (real shadow traffic, never the offline proxy). Nil means drift
	// monitoring falls back to the bundle reference.
	URLOpsBaseline *URLOperationalBaseline
	// URLOpsBaselineFailed marks a configured-but-unloadable baseline so the
	// status endpoint can report fail_open with a stable error class. The
	// failure state is injected by the env loader instead of a mutable global.
	URLOpsBaselineFailed     bool
	URLOpsBaselineErrorClass string
	// URLMLFeedback configures durable, privacy-safe label correlation. An
	// empty secret keeps the legacy ephemeral in-memory buffer.
	URLMLFeedback URLMLFeedbackConfig
	// PolicySemantics selects between fused adblock/security reporting
	// (legacy) and the separated content-policy decision (default).
	PolicySemantics PolicySemantics
	// AdblockExceptionsFile optionally pins the scoped content-exception
	// config path. Empty means the env loader decides
	// (SAFE_ZONE_ADBLOCK_EXCEPTIONS_FILE); empty/unset disables exceptions.
	AdblockExceptionsFile string
	// AdblockShadowExactEnabled turns on shadow exact/suffix observation
	// (PR3B-lite). Startup-only: read once at construction from this option
	// or SAFE_ZONE_ADBLOCK_SHADOW_EXACT_ENABLED (default false). Observation
	// never changes enforcement.
	AdblockShadowExactEnabled bool
}

type adblockSourceMeta struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

type Service struct {
	lifecycleCtx      context.Context
	lifecycleCancel   context.CancelFunc
	redis             *cache.Redis
	redisTimeout      time.Duration
	ttlAllowed        time.Duration
	ttlSuspicious     time.Duration
	ttlBlocked        time.Duration
	recentLimit       int64
	recentTTL         time.Duration
	threatFeedKey     string
	feedRevisionKey   string
	aiMu              sync.Mutex
	ai                *ai.Client
	aiShared          bool
	cachedGeminiKey   string
	lastGeminiKeySync time.Time
	whitelist         *Whitelist
	analyzer          *analysis.Analyzer
	analyzerMu        sync.RWMutex
	analysisConfig    config.AnalysisConfig
	configRevision    string
	lastReloadSource  string
	lastReloadTime    time.Time
	configReloadWG    sync.WaitGroup
	configReloadChan  string
	configReloadPoll  time.Duration
	configReloadOn    bool
	nodeRole          string
	subscribeReload   func(context.Context, string) (<-chan string, func() error, error)
	reloadBackoffMin  time.Duration
	reloadBackoffMax  time.Duration
	store             *store.DB
	brandStore        analysis.BrandStore
	enrichEnabled     bool
	enrichTimeout     time.Duration
	enrichQueue       chan enrichmentJob
	enrichDone        chan struct{}
	enrichWG          sync.WaitGroup
	enrichMu          sync.Mutex
	enrichInFlight    map[string]struct{}
	enrichmentLookup  func(context.Context, string) enrichmentSignals
	whoisCacheTTL     time.Duration
	osint             *osint.Service
	adblockDataRoot   string
	adblockHTTPClient *http.Client
	mlClassifier      analysis.DomainClassifier
	mlMode            analysis.MLMode
	mlCanary          MLCanaryConfig
	mlTelemetry       mlTelemetry
	urlMLClassifier   analysis.URLClassifier
	urlMLMode         analysis.MLMode
	urlMLShadow       URLMLShadowConfig
	urlMLTelemetry    urlMLTelemetry
	// urlMLOpsBaseline is an optional frozen operational drift reference
	// loaded from real shadow traffic. Load failures are fail-open.
	urlMLOpsBaseline           *URLOperationalBaseline
	urlMLOpsBaselineFailed     bool
	urlMLOpsBaselineErrorClass string
	// urlMLFeedback correlates opaque event fingerprints with caller labels.
	// Backed by memory (ephemeral) or SQLite (durable, bounded) depending on
	// URLMLFeedbackConfig.
	urlMLFeedback urlFeedbackBackend

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

	// overrideLookupFailures counts admin-override reads that failed. The
	// decision pipeline stays fail-open so a store error cannot block all
	// traffic, but every failure used to be invisible; this makes "my block
	// did not take effect" a number the operator can alert on.
	//
	// overrideConsecutiveFailures and the two timestamps are what make that
	// number actionable: a monotonic total cannot distinguish "broken right
	// now" from "broke three times since Tuesday", and the last-failure stamp
	// is what an alert rule can compare against.
	overrideLookupFailures      atomic.Int64
	overrideConsecutiveFailures atomic.Int64
	overrideLastFailureUnix     atomic.Int64
	overrideLastSuccessUnix     atomic.Int64

	// closeMu and closed make Close idempotent; a second call would otherwise
	// panic on the already-closed enrichDone channel.
	closeMu sync.Mutex
	closed  bool

	// overrideLookup is the seam through which override reads are made. It is
	// nil in production, so readEffectiveOverride calls the store directly; a
	// test installs a reader to drive the failure path, which is otherwise
	// unreachable because GetEffectiveOverride reports (nil, nil) — not an
	// error — once the store is disabled.
	//
	// It holds an interface rather than a bare func for a specific reason:
	// atomic.Pointer[T] can only store *T, so a func-typed T means "pointer to
	// nil func" is representable, and a caller that checks only the pointer
	// would invoke a nil function on the DNS hot path. An interface value
	// stored behind a pointer is nil only when the pointer is nil, which is
	// the state Store(nil) produces. Mirrors the counters above, which are
	// atomic for the same family of reasons.
	overrideLookup atomic.Pointer[overrideReader]

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

type ClientInfo struct {
	IP       string `json:"ip"`
	ClientID string `json:"client_id"`
}

type Analysis struct {
	analysis.Result
	CacheHit   bool              `json:"cache_hit"`
	AnalyzedAt string            `json:"analyzed_at"`
	Evidence   []osint.Evidence  `json:"evidence,omitempty"`
	URLML      *URLMLObservation `json:"url_ml,omitempty"`
	// Decision carries a policy action when this response already resolved
	// one (admin override/allowlist admission, legacy fused adblock). Nil
	// on pure engine paths: no content or admin policy was involved.
	Decision *PolicyDecision `json:"decision,omitempty"`
	// DecisionID identifies this evaluation. It reuses the request
	// correlation ID when present, otherwise a generated eval ID, so logs
	// join to telemetry rows carrying the same value.
	DecisionID string `json:"decision_id"`
	// Assessment declares what was evaluated for the security verdict.
	// Coverage is always "domain_only" until website inspection exists;
	// Skipped uses bare layer names for short-circuited stages and
	// "layer:reason" for conditional ones.
	Assessment Assessment `json:"assessment"`
}

type Policy struct {
	Domain string          `json:"domain"`
	Policy string          `json:"policy"`
	Result analysis.Result `json:"result"`
	// Decision explains the policy action independently of the security
	// verdict. Nil on paths that have not adopted the separated decision
	// model yet, and absent from legacy serialized payloads.
	Decision *PolicyDecision `json:"decision,omitempty"`
	CacheHit bool            `json:"cache_hit"`
	// DecisionID mirrors Analysis.DecisionID for the same evaluation.
	DecisionID string `json:"decision_id"`
	// Assessment mirrors Analysis.Assessment for the security Result.
	Assessment Assessment `json:"assessment"`
}

// Assessment coverage. Only domain_only exists today: no request path
// observes website content yet.
const AssessmentCoverageDomainOnly = "domain_only"

// Evaluation layers named in assessments. Bounded vocabulary so coverage
// stays measurable across API and DNS paths.
const (
	LayerIdentity      = "identity"
	LayerOverride      = "override"
	LayerWhitelist     = "whitelist"
	LayerAdblock       = "adblock"
	LayerContentPolicy = "content_policy"
	LayerThreatFeed    = "threat_feed"
	LayerLexical       = "lexical"
	LayerLexicalLocal  = "lexical_local"
	LayerDomainML      = "domain_ml"
	LayerAIRefine      = "ai_refine"
	LayerEnrichment    = "enrichment"
	LayerOSINT         = "osint"
	LayerURLML         = "url_ml"
	LayerGroupPolicy   = "group_policy"
	LayerResultCache   = "result_cache"
	LayerWebsite       = "website_content"
	// LayerClientGroup times client-to-group resolution (SQLite lookup).
	LayerClientGroup = "client_group"
)

// Skipped-layer reasons. Bare layer names mean short-circuited.
const (
	SkipNotObserved   = "not_observed"
	SkipNoURLContext  = "no_url_context"
	SkipLegacyFused   = "legacy_policy_fused"
	SkipAsync         = "async_background"
	SkipOutOfRange    = "score_out_of_range"
	SkipCacheOnly     = "cache_only"
	SkipNotApplicable = "not_applicable"
)

// Assessment describes which layers produced a security Result.
type Assessment struct {
	Coverage  string           `json:"coverage"`
	Evaluated []string         `json:"evaluated_layers"`
	Skipped   []string         `json:"skipped_layers"`
	Timings   map[string]int64 `json:"timings_us,omitempty"`
	// Feed records how the threat-feed layer resolved this evaluation:
	// exact hit, parent hit at a depth, or trusted-suffix bypass.
	// Nil when the layer missed without a bypass (miss-vs-skip already
	// lives in Evaluated/Skipped) or when the verdict came from cache.
	// Observability only; never gates a verdict (PR-08b/M7 shadow).
	Feed *FeedScope `json:"feed_scope,omitempty"`
}

// FeedScope describes one threat-feed layer resolution. Depth counts
// labels from the queried domain: 0 is the exact host.
type FeedScope struct {
	ExactMatch    bool   `json:"exact_match,omitempty"`
	Candidate     string `json:"candidate,omitempty"`
	Depth         int    `json:"depth,omitempty"`
	TrustBypassed bool   `json:"trust_bypassed,omitempty"`
	// SharedApex marks an exact IOC on shared infrastructure that was
	// downgraded to contextual evidence (FP-guard 2026-09, M7).
	SharedApex bool `json:"shared_apex,omitempty"`
}

type enrichmentSignals struct {
	// DNS classifies the apex NS lookup performed during background
	// enrichment. DNS metadata is availability evidence only: no outcome
	// may promote the security score or verdict on its own (PR-01/H1).
	// The zero value means the lookup succeeded with usable NS records.
	DNS   DNSOutcome
	TLS   tlsinspect.Result
	WHOIS whois.Result
}

// DNSOutcome is the closed set of apex nameserver lookup results observed
// by background enrichment. Reason prose is derived from String, so the
// telemetry vocabulary stays bounded.
type DNSOutcome int

const (
	// DNSOutcomeOK means the apex returned usable NS records.
	DNSOutcomeOK DNSOutcome = iota
	// DNSOutcomeNXDOMAIN means the apex authoritatively does not exist.
	DNSOutcomeNXDOMAIN
	// DNSOutcomeNoData means the apex answered without usable NS records.
	DNSOutcomeNoData
	// DNSOutcomeTimeout means the lookup exceeded its deadline.
	DNSOutcomeTimeout
	// DNSOutcomeServerFailure covers SERVFAIL, refused and other
	// server-side lookup errors.
	DNSOutcomeServerFailure
	// DNSOutcomeCanceled means the lookup context was canceled.
	DNSOutcomeCanceled
	// DNSOutcomeUnknownError is the catch-all for unclassified errors.
	DNSOutcomeUnknownError
)

// String returns the bounded availability note for a non-OK outcome.
func (o DNSOutcome) String() string {
	switch o {
	case DNSOutcomeNXDOMAIN:
		return "dns: apex has no NS records (authoritative NXDOMAIN)"
	case DNSOutcomeNoData:
		return "dns: apex answered without usable NS records"
	case DNSOutcomeTimeout:
		return "dns: apex NS lookup timed out"
	case DNSOutcomeServerFailure:
		return "dns: apex NS lookup failed (server error)"
	case DNSOutcomeCanceled:
		return "dns: apex NS lookup canceled"
	case DNSOutcomeUnknownError:
		return "dns: apex NS lookup failed"
	default:
		return "dns: apex NS lookup unavailable"
	}
}

// classifyDNSLookupErr maps a LookupNS error to a DNSOutcome. A nil error
// with an empty answer set is classified by the caller as NoData.
func classifyDNSLookupErr(err error) DNSOutcome {
	if err == nil {
		return DNSOutcomeOK
	}
	if errors.Is(err, context.Canceled) {
		return DNSOutcomeCanceled
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return DNSOutcomeNXDOMAIN
		case dnsErr.IsTimeout:
			return DNSOutcomeTimeout
		default:
			return DNSOutcomeServerFailure
		}
	}
	if os.IsTimeout(err) {
		return DNSOutcomeTimeout
	}
	return DNSOutcomeUnknownError
}

type analysisConfigReloadEvent struct {
	Type      string `json:"type"`
	Revision  string `json:"revision"`
	UpdatedAt string `json:"updated_at"`
	Source    string `json:"source"`
}

type AnalyzeOptions struct {
	IncludeEvidence bool
	ForceOSINT      bool
	URLContext      *URLAnalysisContext
	// MissingContextReason classifies analysis requests that carry no URL
	// context (bounded set: get_domain_only|post_not_provided). It feeds the
	// aggregate coverage breakdown only; it never stores caller data.
	MissingContextReason string
}

type osintLookupMode int

const (
	osintLookupNone osintLookupMode = iota
	osintLookupCachedOnly
	osintLookupOnDemand
)

func NewService(options Options) *Service {
	analysisConfig := options.AnalysisConfig
	if err := analysisConfig.Validate(); err != nil {
		analysisConfig = config.DefaultAnalysisConfig()
	}
	if options.Store != nil && options.Store.Enabled() {
		if storedConfig, err := options.Store.GetAnalysisConfig(context.Background()); err == nil && storedConfig != nil {
			analysisConfig = storedConfig.Clone()
		} else if err != nil {
			logjson.Warn("stored analysis config invalid; using configured defaults", map[string]any{
				"service": "risk",
				"error":   err.Error(),
			})
		}
	}

	recentLimit := options.RecentLimit
	if recentLimit <= 0 {
		recentLimit = 25
	}
	configReloadChannel := strings.TrimSpace(options.ConfigReloadChannel)
	if configReloadChannel == "" {
		configReloadChannel = defaultAnalysisConfigReloadChannel
	}
	threatFeedKey := options.ThreatFeedKey
	if threatFeedKey == "" {
		threatFeedKey = defaultThreatFeedKey
	}
	adblockDataRoot := strings.TrimSpace(options.AdblockFileRoot)
	if adblockDataRoot == "" {
		adblockDataRoot = config.FeedFileRoot()
	}
	aiClient := options.AIClient
	aiShared := aiClient != nil
	if aiClient == nil {
		aiClient = ai.NewClient(ai.Config{
			Provider:      options.AIProvider,
			GeminiBaseURL: options.GeminiBaseURL,
			GeminiAPIKey:  options.GeminiAPIKey,
			GeminiModel:   options.GeminiModel,
			GeminiTimeout: options.GeminiTimeout,
			OllamaBaseURL: options.OllamaBaseURL,
			OllamaModel:   options.OllamaModel,
			OllamaTimeout: options.OllamaTimeout,
		})
	}
	if !aiClient.Enabled() && !aiShared {
		aiClient = nil
	}
	mlMode := options.MLMode
	if mlMode != analysis.MLModeShadow && mlMode != analysis.MLModeEnforce {
		mlMode = analysis.MLModeDisabled
	}
	if options.MLClassifier == nil || !options.MLClassifier.Enabled() {
		mlMode = analysis.MLModeDisabled
	}
	mlCanary := options.MLCanary
	if err := mlCanary.validate(); err != nil {
		mlCanary = MLCanaryConfig{}
	}
	// Direct constructor callers cannot return a startup error. Degrade an
	// unbounded enforce request to shadow; env-based startup rejects it earlier.
	if mlMode == analysis.MLModeEnforce && !mlCanary.enabled() {
		mlMode = analysis.MLModeShadow
	}
	urlMLMode := options.URLMLMode
	if urlMLMode != analysis.MLModeShadow {
		urlMLMode = analysis.MLModeDisabled
	}
	urlMLShadow := options.URLMLShadow
	if urlMLShadow.Percent == 0 {
		urlMLShadow.Percent = 100
	}
	if err := urlMLShadow.validate(); err != nil {
		urlMLShadow = URLMLShadowConfig{Percent: 100}
	}
	urlFeedback := options.URLMLFeedback
	// Created before the feedback backend so the backend can be handed the
	// service lifecycle: the durable store's background prune stops on
	// shutdown rather than outliving the service.
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	var urlFeedbackBackendImpl urlFeedbackBackend
	switch urlFeedback.Secret {
	case "":
		// No secret injected: keep the ephemeral in-memory buffer. Labels are
		// best-effort diagnostics and never survive a restart.
		urlFeedbackBackendImpl = newURLFeedbackStore(8192)
	default:
		if urlFeedback.KeyVersion == 0 {
			urlFeedback.KeyVersion = 1
		}
		if urlFeedback.Retention == 0 {
			urlFeedback.Retention = defaultURLFeedbackRetentionHours * time.Hour
		}
		if urlFeedback.MaxRows == 0 {
			urlFeedback.MaxRows = defaultURLFeedbackMaxRows
		}
		if err := urlFeedback.validate(); err != nil {
			logjson.Warn("invalid URL ML feedback configuration; feedback fails closed", map[string]any{
				"service": "risk",
				"error":   err.Error(),
			})
			urlFeedbackBackendImpl = newDurableURLFeedbackStore(nil, URLMLFeedbackConfig{
				KeyVersion: 1,
				Retention:  defaultURLFeedbackRetentionHours * time.Hour,
				MaxRows:    defaultURLFeedbackMaxRows,
			}, lifecycleCtx)
		} else {
			// Durable mode. A nil/disabled store keeps failing closed for
			// labels while analysis stays unaffected.
			urlFeedbackBackendImpl = newDurableURLFeedbackStore(options.Store, urlFeedback, lifecycleCtx)
		}
	}

	wl := NewWhitelist(options.Store)
	if options.WhitelistPath != "" {
		_ = wl.LoadFromFile(options.WhitelistPath)
	} else if options.Store != nil && options.Store.Enabled() {
		_ = wl.LoadFromDB()
	}

	brandStore := analysis.BrandStore(store.NewBrandStore(
		options.Store,
		options.Redis,
		options.RedisTimeout,
		configDuration(options.BrandCacheTTL, 5*time.Minute),
	))

	enrichQueueSize := options.EnrichQueueSize
	if enrichQueueSize <= 0 {
		enrichQueueSize = 256
	}
	enrichWorkers := options.EnrichWorkers
	if enrichWorkers <= 0 {
		enrichWorkers = 1
	}

	svc := &Service{
		lifecycleCtx:               lifecycleCtx,
		lifecycleCancel:            lifecycleCancel,
		redis:                      options.Redis,
		redisTimeout:               configDuration(options.RedisTimeout, defaultRedisTimeout),
		ttlAllowed:                 configDuration(options.TTLAllowed, defaultCacheTTLAllowed),
		ttlSuspicious:              configDuration(options.TTLSuspicious, defaultCacheTTLSuspicious),
		ttlBlocked:                 configDuration(options.TTLBlocked, defaultCacheTTLBlocked),
		recentLimit:                recentLimit,
		recentTTL:                  configDuration(options.RecentTTL, 24*time.Hour),
		threatFeedKey:              threatFeedKey,
		feedRevisionKey:            feed.RevisionKey(threatFeedKey),
		ai:                         aiClient,
		aiShared:                   aiShared,
		whitelist:                  wl,
		store:                      options.Store,
		brandStore:                 brandStore,
		configReloadChan:           configReloadChannel,
		configReloadPoll:           configDuration(options.ConfigReloadPollInterval, defaultAnalysisConfigReloadPollInterval),
		configReloadOn:             options.ConfigReloadEnabled,
		nodeRole:                   strings.TrimSpace(options.NodeRole),
		reloadBackoffMin:           analysisConfigReloadBackoffMin,
		reloadBackoffMax:           analysisConfigReloadBackoffMax,
		enrichEnabled:              options.EnrichEnabled,
		enrichTimeout:              options.EnrichTimeout,
		enrichDone:                 make(chan struct{}),
		enrichInFlight:             make(map[string]struct{}),
		whoisCacheTTL:              configDuration(options.WhoisCacheTTL, 7*24*time.Hour),
		osint:                      options.OSINT,
		adblockDataRoot:            adblockDataRoot,
		adblockHTTPClient:          options.AdblockHTTPClient,
		mlClassifier:               options.MLClassifier,
		mlMode:                     mlMode,
		mlCanary:                   mlCanary,
		urlMLClassifier:            options.URLMLClassifier,
		urlMLMode:                  urlMLMode,
		urlMLShadow:                urlMLShadow,
		urlMLOpsBaseline:           options.URLOpsBaseline,
		urlMLOpsBaselineFailed:     options.URLOpsBaselineFailed,
		urlMLOpsBaselineErrorClass: options.URLOpsBaselineErrorClass,
		urlMLFeedback:              urlFeedbackBackendImpl,
		policySemantics:            NormalizePolicySemantics(string(options.PolicySemantics)),
	}
	svc.adblockMatchMode.Store(string(parseAdblockMatchMode(config.String(envAdblockMatchMode, string(adblockMatchModeSuffix)))))
	svc.adblockSourcePolicies.Store(&adblockSourcePolicySet{})
	svc.adblockTrie.Store(domaintrie.NewTrie())
	svc.adblockResync = make(chan struct{}, 1)
	svc.adblockShadowExactEnabled = options.AdblockShadowExactEnabled || config.Bool(envAdblockShadowExactEnabled, false)
	svc.adblockExceptionsFile = strings.TrimSpace(options.AdblockExceptionsFile)
	if svc.adblockExceptionsFile == "" {
		svc.adblockExceptionsFile = strings.TrimSpace(config.String(envAdblockExceptionsFile, ""))
	} else {
		svc.adblockExceptionsPinned = true
	}
	svc.adblockExceptions.Store(newEmptyAdblockExceptionSnapshot())
	svc.reloadAdblockExceptions()
	svc.refreshAdblockEnabled()
	// Reconcile the persisted match mode at startup so an operator change
	// survives a restart instead of reverting to the environment default.
	svc.refreshAdblockMatchMode()
	// Same reconciliation for per-source policies: a persisted change must
	// survive a restart, and the periodic refresh keeps both processes in step
	// afterwards so the policy no longer needs a two-service restart to apply.
	svc.refreshAdblockSourcePolicies()
	if svc.redis != nil {
		svc.subscribeReload = svc.redis.Subscribe
	}
	svc.enrichmentLookup = svc.defaultEnrichmentLookup
	svc.applyAnalysisConfig(analysisConfig, configReloadSourceStartup)
	if svc.enrichEnabled && svc.redis != nil && svc.redis.Enabled() && svc.enrichTimeout > 0 {
		svc.enrichQueue = make(chan enrichmentJob, enrichQueueSize)
		svc.enrichWG.Add(enrichWorkers)
		for i := 0; i < enrichWorkers; i++ {
			go svc.enrichmentWorker()
		}
	}
	if svc.shouldRunConfigReloadSubscriber() {
		svc.configReloadWG.Add(1)
		go svc.runConfigReloadSubscriber()
	}
	if svc.shouldRunConfigReloadReconciler() {
		svc.configReloadWG.Add(1)
		go svc.runConfigReloadReconciler()
	}

	if !options.DisableAdblockSync {
		go svc.runAdblockSync()
		go svc.runAdblockConfigSync()
	}

	return svc
}

func configDuration(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}

func (s *Service) shouldRunConfigReloadSubscriber() bool {
	if s == nil {
		return false
	}
	if !s.configReloadOn || s.configReloadChan == "" || s.subscribeReload == nil {
		return false
	}
	if s.redis == nil || !s.redis.Enabled() {
		return false
	}
	if s.store == nil || !s.store.Enabled() {
		return false
	}
	return true
}

func (s *Service) shouldRunConfigReloadReconciler() bool {
	if s == nil {
		return false
	}
	if !s.configReloadOn {
		return false
	}
	if s.store == nil || !s.store.Enabled() {
		return false
	}
	return configDuration(s.configReloadPoll, defaultAnalysisConfigReloadPollInterval) > 0
}

func (s *Service) runConfigReloadSubscriber() {
	defer s.configReloadWG.Done()

	backoff := configDuration(s.reloadBackoffMin, analysisConfigReloadBackoffMin)
	maxBackoff := configDuration(s.reloadBackoffMax, analysisConfigReloadBackoffMax)
	if maxBackoff < backoff {
		maxBackoff = backoff
	}

	for {
		if s.lifecycleCtx.Err() != nil {
			return
		}

		messages, closeSub, err := s.subscribeReload(s.lifecycleCtx, s.configReloadChan)
		if err != nil {
			if s.lifecycleCtx.Err() != nil {
				return
			}
			logjson.Warn("analysis config reload subscribe failed; retrying", map[string]any{
				"service":   "risk",
				"channel":   s.configReloadChan,
				"backoff":   backoff.String(),
				"error":     err.Error(),
				"node_role": s.nodeRole,
			})
			if !waitForContextOrTimeout(s.lifecycleCtx, backoff) {
				return
			}
			backoff = nextConfigReloadBackoff(backoff, maxBackoff)
			continue
		}

		backoff = configDuration(s.reloadBackoffMin, analysisConfigReloadBackoffMin)
		err = s.consumeConfigReloadMessages(messages)
		if closeSub != nil {
			_ = closeSub()
		}
		if s.lifecycleCtx.Err() != nil {
			return
		}

		logFields := map[string]any{
			"service":   "risk",
			"channel":   s.configReloadChan,
			"backoff":   backoff.String(),
			"node_role": s.nodeRole,
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			logFields["error"] = err.Error()
		}
		logjson.Warn("analysis config reload subscriber disconnected; retrying", logFields)

		if !waitForContextOrTimeout(s.lifecycleCtx, backoff) {
			return
		}
		backoff = nextConfigReloadBackoff(backoff, maxBackoff)
	}
}

func (s *Service) consumeConfigReloadMessages(messages <-chan string) error {
	for {
		select {
		case <-s.lifecycleCtx.Done():
			return s.lifecycleCtx.Err()
		case raw, ok := <-messages:
			if !ok {
				return errors.New("subscription closed")
			}
			s.handleConfigReloadMessage(raw)
		}
	}
}

func (s *Service) runConfigReloadReconciler() {
	defer s.configReloadWG.Done()

	interval := configDuration(s.configReloadPoll, defaultAnalysisConfigReloadPollInterval)
	if interval <= 0 {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.lifecycleCtx.Done():
			return
		case <-ticker.C:
			s.reconcileAnalysisConfig()
		}
	}
}

func (s *Service) handleConfigReloadMessage(raw string) {
	if s == nil {
		return
	}

	var event analysisConfigReloadEvent
	if err := json.Unmarshal([]byte(raw), &event); err != nil {
		logjson.Warn("analysis config reload event decode failed", map[string]any{
			"service": "risk",
			"channel": s.configReloadChan,
			"error":   err.Error(),
		})
		return
	}
	if event.Type != analysisConfigReloadEventType || event.Revision == "" {
		return
	}
	currentRevision := s.currentConfigRevision()
	if event.Revision == currentRevision {
		logjson.Info("analysis config reload ignored", map[string]any{
			"service":          "risk",
			"channel":          s.configReloadChan,
			"event_revision":   event.Revision,
			"current_revision": currentRevision,
			"event_source":     event.Source,
			"event_time":       event.UpdatedAt,
			"ignore_reason":    "duplicate_or_self_loop",
			"node_role":        s.nodeRole,
		})
		return
	}

	oldRevision, newRevision, applied, err := s.reloadAnalysisConfigFromStore(configReloadSourcePubSub)
	if err != nil {
		logjson.Warn("analysis config reload from store failed", map[string]any{
			"service":        "risk",
			"channel":        s.configReloadChan,
			"event_revision": event.Revision,
			"event_source":   event.Source,
			"error":          err.Error(),
		})
		return
	}
	if !applied {
		return
	}

	logjson.Info("analysis config reload applied", map[string]any{
		"service":       "risk",
		"channel":       s.configReloadChan,
		"old_revision":  oldRevision,
		"new_revision":  newRevision,
		"event_source":  event.Source,
		"event_time":    event.UpdatedAt,
		"reload_source": configReloadSourcePubSub,
		"node_role":     s.nodeRole,
	})
}

func (s *Service) reconcileAnalysisConfig() {
	if s == nil {
		return
	}

	oldRevision, newRevision, applied, err := s.reloadAnalysisConfigFromStore(configReloadSourceReconcile)
	if err != nil {
		logjson.Warn("analysis config reconciliation failed", map[string]any{
			"service":       "risk",
			"poll_interval": configDuration(s.configReloadPoll, defaultAnalysisConfigReloadPollInterval).String(),
			"error":         err.Error(),
			"node_role":     s.nodeRole,
		})
		return
	}
	if !applied {
		return
	}

	logjson.Info("analysis config reconciliation applied", map[string]any{
		"service":       "risk",
		"old_revision":  oldRevision,
		"new_revision":  newRevision,
		"poll_interval": configDuration(s.configReloadPoll, defaultAnalysisConfigReloadPollInterval).String(),
		"reload_source": configReloadSourceReconcile,
		"node_role":     s.nodeRole,
	})
}

func (s *Service) reloadAnalysisConfigFromStore(source string) (string, string, bool, error) {
	if s == nil || s.store == nil || !s.store.Enabled() {
		return "", "", false, store.ErrDisabled
	}

	storedConfig, err := s.store.GetAnalysisConfig(context.Background())
	if err != nil {
		return "", "", false, err
	}
	if storedConfig == nil {
		currentRevision := s.currentConfigRevision()
		return currentRevision, currentRevision, false, nil
	}

	cfg := storedConfig.Clone()
	nextRevision := analysisConfigRevision(cfg)
	currentRevision := s.currentConfigRevision()
	if nextRevision == currentRevision {
		return currentRevision, nextRevision, false, nil
	}

	appliedRevision := s.applyAnalysisConfig(cfg, source)
	return currentRevision, appliedRevision, true, nil
}

func nextConfigReloadBackoff(current, max time.Duration) time.Duration {
	if current <= 0 {
		return max
	}
	next := current * 2
	if next < current || next > max {
		return max
	}
	return next
}

func waitForContextOrTimeout(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return ctx.Err() == nil
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// Close stops background work and releases resources. It is safe to call more
// than once.
//
// It used to be a bare `close(s.enrichDone)`, so a second call panicked with
// "close of closed channel". That is reachable in practice: the enrichment
// goroutine closes the channel on its own error path, and several tests plus
// the deferred cleanup in the constructors call Close as well.
func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return nil
	}
	s.closed = true
	s.closeMu.Unlock()

	s.lifecycleCancel()
	if s.enrichDone != nil {
		close(s.enrichDone)
	}
	s.enrichWG.Wait()
	s.configReloadWG.Wait()
	// The durable URL-feedback prune runs on its own goroutine and holds the
	// SQLite connection; wait for it before closing the store, or it observes
	// a closed database and records a spurious persistence error.
	s.urlMLFeedback.waitForPrune()
	var err error
	if s.redis != nil {
		err = s.redis.Close()
	}
	if s.store != nil {
		err = errors.Join(err, s.store.Close())
	}
	return err
}

// resolvedLayer is the outcome of one of the administrative layers that both
// decision paths consult: an admin override or a whitelist match.
//
// The two paths build identical Results and identical Decisions from these
// layers, and each had grown its own copy of the construction. The Assessment
// bookkeeping stays with the caller on purpose: Analyze appends its layer list
// eagerly before consulting anything, while Policy appends per branch as it
// returns, and Assessment is serialized into API responses and telemetry. Sharing
// that would change output, so only the computation is shared here.
type resolvedLayer struct {
	result   analysis.Result
	cacheHit bool
	decision *PolicyDecision
}

// resolveClientGroup returns the policy group for a client, defaulting when the
// store is unavailable or the lookup fails.
//
// Client-supplied identifiers (DoH client_id) are unauthenticated, so policy is
// derived from the trusted client IP only. The request context bounds this lookup
// so a disconnected caller stops consuming database work.
func (s *Service) resolveClientGroup(ctx context.Context, client ClientInfo, t *layerTimer) *store.ClientGroup {
	var group *store.ClientGroup
	if s.store != nil && s.store.Enabled() {
		var g *store.ClientGroup
		var groupErr error
		t.measure(LayerClientGroup, func() {
			g, groupErr = s.store.GetGroupForClient(ctx, client.IP, client.ClientID, false)
		})
		if groupErr == nil {
			group = g
		}
	}
	if group == nil {
		group = &store.ClientGroup{ID: 1, Name: "default", StrictMalware: true}
	}
	return group
}

// resolveOverride consults the administrative override chain. It returns nil when
// no override applies.
//
// A lookup error resolves to "no override" rather than propagating: the layer is
// fail-open by design so a transient store failure cannot block every domain for
// every client. lookupEffectiveOverride counts and publishes those failures.
func (s *Service) resolveOverride(ctx context.Context, group *store.ClientGroup, normalized string, t *layerTimer) *resolvedLayer {
	if s.store == nil || !s.store.Enabled() {
		return nil
	}
	var override *store.Override
	t.measure(LayerOverride, func() {
		var overrideErr error
		override, overrideErr = s.lookupEffectiveOverride(ctx, group.ID, normalized)
		if overrideErr != nil {
			override = nil
		}
	})
	if override == nil {
		return nil
	}

	verdict := analysis.VerdictSafe
	score := 0
	if override.Action == "block" {
		verdict = analysis.VerdictMalicious
		score = 100
	}
	reason := fmt.Sprintf("admin override: %s", override.Action)
	if override.Reason != "" {
		reason = fmt.Sprintf("admin override: %s (%s)", override.Action, override.Reason)
	}
	return &resolvedLayer{
		result: analysis.Result{
			Domain:     normalized,
			Verdict:    verdict,
			Confidence: 1.0,
			Score:      score,
			Reasons:    []string{reason},
			Category:   analysis.ClassifyCategory(normalized),
		},
		cacheHit: false,
		decision: adminPolicyDecision(override.Action),
	}
}

// resolveWhitelist consults the allowlist. It returns nil when the domain is not
// allowlisted.
func (s *Service) resolveWhitelist(ctx context.Context, normalized string, t *layerTimer) *resolvedLayer {
	whitelisted := false
	t.measure(LayerWhitelist, func() {
		whitelisted = s.whitelist.IsAllowed(ctx, normalized)
	})
	if !whitelisted {
		return nil
	}
	return &resolvedLayer{
		result: analysis.Result{
			Domain:     normalized,
			Verdict:    analysis.VerdictSafe,
			Confidence: 1.0,
			Score:      0,
			Reasons:    []string{"whitelisted"},
			Category:   "uncategorized",
		},
		cacheHit: false,
		decision: allowlistPolicyDecision(),
	}
}

func (s *Service) Analyze(ctx context.Context, domain string, client ClientInfo) Analysis {
	return s.AnalyzeWithOptions(ctx, domain, client, AnalyzeOptions{})
}

func (s *Service) AnalyzeWithOptions(ctx context.Context, domain string, client ClientInfo, options AnalyzeOptions) Analysis {
	s.urlMLTelemetry.analyzeRequests.Add(1)
	if options.URLContext == nil {
		s.urlMLTelemetry.noteMissingContext(options.MissingContextReason)
	}
	normalized, err := analysis.NormalizeDomain(domain)
	var result analysis.Result
	var cacheHit bool
	var evidence []osint.Evidence
	var decision *PolicyDecision
	assess := newDomainAssessment()
	decisionID := decisionIDFor(ctx)
	var preTimer layerTimer

	if err != nil {
		result = s.analyzeLexical(domain)
		cacheHit = false
		assess.Evaluated = append(assess.Evaluated, LayerIdentity)
		assess.Skipped = append(assess.Skipped, LayerOverride, LayerWhitelist,
			LayerAdblock, LayerGroupPolicy)
		assess.Skipped = append(assess.Skipped, engineSkippedLayers()...)
		assess.Timings = preTimer.timings
	} else {
		group := s.resolveClientGroup(ctx, client, &preTimer)

		assess.Evaluated = append(assess.Evaluated, LayerIdentity, LayerOverride)
		// 1. Check Overrides
		if override := s.resolveOverride(ctx, group, normalized, &preTimer); override != nil {
			result = override.result
			cacheHit = override.cacheHit
			decision = override.decision
			assess.Skipped = append(assess.Skipped, LayerWhitelist, LayerAdblock)
			assess.Skipped = append(assess.Skipped, engineSkippedLayers()...)
		}

		// 2. Check Whitelist
		if result.Domain == "" {
			if allow := s.resolveWhitelist(ctx, normalized, &preTimer); allow != nil {
				result = allow.result
				cacheHit = allow.cacheHit
				decision = allow.decision
				assess.Evaluated = append(assess.Evaluated, LayerWhitelist)
				assess.Skipped = append(assess.Skipped, LayerAdblock)
				assess.Skipped = append(assess.Skipped, engineSkippedLayers()...)
			}
		}

		if result.Domain == "" {
			// 2.5 Check Adblock Trie
			adTrie := s.adblockTrie.Load()
			assess.Evaluated = append(assess.Evaluated, LayerWhitelist, LayerAdblock)
			if s.isAdblockEnabled() && adTrie != nil && adTrie.Match(normalized) {
				if s.policySemantics == PolicySemanticsLegacy {
					result = analysis.Result{
						Domain:     normalized,
						Verdict:    analysis.VerdictMalicious,
						Confidence: 1.0,
						Score:      100,
						Reasons:    []string{"adblock"},
						Category:   "adware",
					}
					cacheHit = false
					decision = legacyPolicyDecision()
					assess.Skipped = append(assess.Skipped, engineSkippedLayers()...)
					assess.Skipped = append(assess.Skipped, skippedLayer("security_assessment", SkipLegacyFused))
				}
				// Separated semantics: an adblock match is content-policy
				// evidence, not security evidence. The security pipeline below
				// still runs so the verdict only reflects independent signals.
			}
		}

		if result.Domain == "" {
			// 3. Fallback to threat assessment
			var engineAssess Assessment
			result, cacheHit, evidence, engineAssess = s.analyze(ctx, normalized, osintLookupOnDemand, options.ForceOSINT)
			assess.Evaluated = prependLayers(engineAssess.Evaluated,
				[]string{LayerIdentity, LayerOverride, LayerWhitelist, LayerAdblock})
			assess.Skipped = engineAssess.Skipped
			assess.Timings = engineAssess.Timings
			assess.Feed = engineAssess.Feed
		}
	}

	a := Analysis{
		Result:     result,
		CacheHit:   cacheHit,
		AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Decision:   decision,
		DecisionID: decisionID,
		Assessment: assess,
	}
	a.Assessment.Timings = mergeTimings(preTimer.timings, assess.Timings)
	if options.IncludeEvidence {
		a.Evidence = evidence
	}
	if options.URLContext != nil {
		a.URLML = s.observeURLML(ctx, normalized, result.Verdict, *options.URLContext)
		a.Assessment.Evaluated = append(a.Assessment.Evaluated, LayerURLML)
	} else {
		a.Assessment.Skipped = append(a.Assessment.Skipped, skippedLayer(LayerURLML, SkipNoURLContext))
	}
	s.recordTelemetry(a, client)
	return a
}

func (s *Service) Policy(ctx context.Context, domain string, client ClientInfo) Policy {
	normalized, err := analysis.NormalizeDomain(domain)
	assess := newDomainAssessment()
	decisionID := decisionIDFor(ctx)
	var preTimer layerTimer
	if err != nil {
		res := s.analyzeLexical(domain)
		assess.Evaluated = append(assess.Evaluated, LayerIdentity)
		assess.Skipped = append(assess.Skipped, LayerOverride, LayerWhitelist,
			LayerAdblock, LayerGroupPolicy)
		assess.Skipped = append(assess.Skipped, engineSkippedLayers()...)
		assess.Timings = preTimer.timings
		return Policy{
			Domain:     domain,
			Policy:     "block",
			Result:     res,
			CacheHit:   false,
			DecisionID: decisionID,
			Assessment: assess,
		}
	}

	// 1. Get Group for Client
	group := s.resolveClientGroup(ctx, client, &preTimer)

	// 2. Check Overrides
	if override := s.resolveOverride(ctx, group, normalized, &preTimer); override != nil {
		decision := override.decision
		policyResult := Policy{
			Domain:     normalized,
			Policy:     override.decision.Action,
			Result:     override.result,
			Decision:   decision,
			CacheHit:   override.cacheHit,
			Assessment: assess,
		}
		policyResult.Assessment.Evaluated = append(policyResult.Assessment.Evaluated,
			LayerIdentity, LayerOverride)
		policyResult.Assessment.Skipped = append(policyResult.Assessment.Skipped,
			LayerWhitelist, LayerAdblock, LayerGroupPolicy)
		policyResult.Assessment.Skipped = append(policyResult.Assessment.Skipped, engineSkippedLayers()...)
		policyResult.Assessment.Timings = preTimer.timings
		policyResult.DecisionID = decisionID
		s.recordTelemetry(Analysis{
			Result:     policyResult.Result,
			CacheHit:   policyResult.CacheHit,
			AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Decision:   decision,
			DecisionID: decisionID,
			Assessment: policyResult.Assessment,
		}, client)
		return policyResult
	}

	// 3. Check Whitelist
	if allow := s.resolveWhitelist(ctx, normalized, &preTimer); allow != nil {
		decision := allow.decision
		policyResult := Policy{
			Domain:     normalized,
			Policy:     "allow",
			Result:     allow.result,
			Decision:   decision,
			CacheHit:   allow.cacheHit,
			Assessment: assess,
		}
		policyResult.Assessment.Evaluated = append(policyResult.Assessment.Evaluated,
			LayerIdentity, LayerOverride, LayerWhitelist)
		policyResult.Assessment.Skipped = append(policyResult.Assessment.Skipped,
			LayerAdblock, LayerGroupPolicy)
		policyResult.Assessment.Skipped = append(policyResult.Assessment.Skipped, engineSkippedLayers()...)
		policyResult.Assessment.Timings = preTimer.timings
		policyResult.DecisionID = decisionID
		s.recordTelemetry(Analysis{
			Result:     policyResult.Result,
			CacheHit:   policyResult.CacheHit,
			AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Decision:   decision,
			DecisionID: decisionID,
			Assessment: policyResult.Assessment,
		}, client)
		return policyResult
	}

	// 3.5 Check Adblock Trie. Group/override lookups above may already have
	// touched the store; only the post-match lexical assessment below is
	// backend-free. Check enabled and trie presence before MatchRule so a
	// nil trie never dereferences and the hot path stays lock/allocation/
	// I/O-free after the match.
	var adDetail domaintrie.MatchDetail
	if s.isAdblockEnabled() {
		if adTrie := s.adblockTrie.Load(); adTrie != nil {
			adDetail = adTrie.MatchRuleDetail(normalized)
		}
	}
	adMatched := adDetail.Matched
	// 3.6 Scoped content exception (separated mode only). It suppresses
	// exactly this adblock match — no early return — so the request falls
	// through to the full security pipeline below. The legacy branch above
	// runs unchanged before any exception is consulted.
	var excRule *domaintrie.Rule
	excID := ""
	if adMatched {
		if s.policySemantics == PolicySemanticsLegacy {
			// Pinned rollback shape: Result stays fused MALICIOUS and no
			// separated Decision is attached. Provenance flows to telemetry
			// only, via the Analysis decision below.
			legacyDecision := legacyPolicyDecision()
			policyResult := Policy{
				Domain: normalized,
				Policy: "block",
				Result: analysis.Result{
					Domain:     normalized,
					Verdict:    analysis.VerdictMalicious,
					Confidence: 1.0,
					Score:      100,
					Reasons:    []string{"adblock"},
					Category:   "adware",
				},
				CacheHit: false,
			}
			policyResult.Assessment = assess
			policyResult.Assessment.Evaluated = append(policyResult.Assessment.Evaluated,
				LayerIdentity, LayerOverride, LayerWhitelist, LayerAdblock)
			policyResult.Assessment.Skipped = append(policyResult.Assessment.Skipped, LayerGroupPolicy)
			policyResult.Assessment.Skipped = append(policyResult.Assessment.Skipped, engineSkippedLayers()...)
			policyResult.Assessment.Skipped = append(policyResult.Assessment.Skipped,
				skippedLayer("security_assessment", SkipLegacyFused))
			policyResult.Assessment.Timings = preTimer.timings
			policyResult.DecisionID = decisionID
			s.recordTelemetry(Analysis{
				Result:     policyResult.Result,
				CacheHit:   false,
				AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
				Decision:   legacyDecision,
				DecisionID: decisionID,
				Assessment: policyResult.Assessment,
			}, client)
			return policyResult
		}

		excMatched := false
		if id, ok := s.matchAdblockException(normalized, &adDetail.Rule); ok {
			excRule = &adDetail.Rule
			excID = id
			excMatched = true
			s.adblockExcMatches.Add(1)
		}
		// 3.7 Shadow exact/suffix observation (PR3B-lite). Records what a
		// prospective global suffix→exact flip would do to this hit. Pure
		// observation: it never influences Policy, Result or telemetry.
		s.observeShadowExact(adDetail, excMatched)
		if !excMatched {
			// Separated semantics: after the match above, adblock stays a fast
			// content-policy block on a strict post-match local-only path — no
			// s.analyze(), no BrandStore.ListBrands, no Redis, no SQLite, no
			// HTTP, no AI/OSINT, no enrichment enqueue.
			// The security Result is scored by the in-process lexical analyzer
			// against the built-in brand seed only (lexical_local_default_brands);
			// it is explicitly not a full security assessment. The matched rule's
			// provenance (normalized domain, scope, source, category) flows into
			// the Decision so FP triage never has to guess which rule fired.
			lexicalResult := s.analyzeLexicalLocal(normalized)
			decision := adblockDecision(adblockAssessmentLocalDefaultBrands, &adDetail.Rule)
			policyResult := Policy{
				Domain:   normalized,
				Policy:   "block",
				Result:   lexicalResult,
				Decision: &decision,
				CacheHit: false,
			}
			policyResult.Assessment = assess
			policyResult.Assessment.Evaluated = append(policyResult.Assessment.Evaluated,
				LayerIdentity, LayerOverride, LayerWhitelist, LayerAdblock,
				LayerLexicalLocal, LayerContentPolicy)
			policyResult.Assessment.Skipped = append(policyResult.Assessment.Skipped, LayerGroupPolicy)
			policyResult.Assessment.Skipped = append(policyResult.Assessment.Skipped, engineSkippedLayers()...)
			policyResult.Assessment.Timings = preTimer.timings
			policyResult.DecisionID = decisionID
			s.recordTelemetryWithSource(Analysis{
				Result:     lexicalResult,
				CacheHit:   false,
				AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
				Decision:   &decision,
				DecisionID: decisionID,
				Assessment: policyResult.Assessment,
			}, client, "adblock")
			return policyResult
		}
	}

	// 4. Get Threat Assessment
	result, cacheHit, _, engineAssess := s.analyze(ctx, normalized, osintLookupCachedOnly, false)

	// 5. Dynamic enforcement
	policy := "allow"
	preTimer.measure(LayerGroupPolicy, func() {
		if result.Verdict == analysis.VerdictMalicious && group.StrictMalware {
			policy = "block"
		}

		if group.StrictPhishing {
			isPhishing := false
			for _, r := range result.Reasons {
				if strings.Contains(strings.ToLower(r), "phishing") {
					isPhishing = true
					break
				}
			}
			if result.Score >= 40 && (isPhishing || result.Category == "phishing") {
				policy = "block"
			}
		}

		if len(group.BlockCategories) > 0 && result.Category != "" && result.Category != "uncategorized" {
			for _, blockedCat := range group.BlockCategories {
				if strings.EqualFold(strings.TrimSpace(blockedCat), result.Category) {
					policy = "block"
					break
				}
			}
		}
	})

	policyResult := Policy{
		Domain:     result.Domain,
		Policy:     policy,
		Result:     result,
		CacheHit:   cacheHit,
		DecisionID: decisionID,
	}
	policyResult.Assessment.Evaluated = prependLayers(engineAssess.Evaluated,
		[]string{LayerIdentity, LayerOverride, LayerWhitelist, LayerAdblock, LayerGroupPolicy})
	policyResult.Assessment.Coverage = engineAssess.Coverage
	policyResult.Assessment.Skipped = engineAssess.Skipped
	policyResult.Assessment.Timings = mergeTimings(preTimer.timings, engineAssess.Timings)
	policyResult.Assessment.Feed = engineAssess.Feed
	if excRule != nil {
		// Content axis only: the exception suppresses the adblock block, so
		// the decision is allow while the overall policy above still follows
		// the security Result plus dynamic enforcement. Telemetry below keeps
		// the real inferred source; the config reason is never exposed.
		decision := adblockExceptionDecision(excRule, excID)
		policyResult.Decision = &decision
	}

	s.recordTelemetry(Analysis{
		Result:     result,
		CacheHit:   cacheHit,
		AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Decision:   policyResult.Decision,
		DecisionID: decisionID,
		Assessment: policyResult.Assessment,
	}, client)

	return policyResult
}

func (s *Service) RecordRecent(ctx context.Context, item Analysis) {
	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		if err := s.redis.PushJSON(redisCtx, recentAnalysisKey, item, s.recentLimit); err != nil {
			return err
		}
		if s.recentTTL > 0 {
			return s.redis.Expire(redisCtx, recentAnalysisKey, s.recentTTL)
		}
		return nil
	})
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		logjson.Warn("recent analysis cache write failed", correlation.Fields(ctx, map[string]any{
			"service": "risk",
			"error":   err.Error(),
		}))
	}
}

func (s *Service) Recent(ctx context.Context) []Analysis {
	recent := make([]Analysis, 0, s.recentLimit)
	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		return s.redis.ListJSON(redisCtx, recentAnalysisKey, 0, s.recentLimit-1, func(data []byte) error {
			var item Analysis
			if err := json.Unmarshal(data, &item); err != nil {
				return err
			}
			recent = append(recent, item)
			return nil
		})
	})
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		logjson.Warn("recent analysis cache read failed", correlation.Fields(ctx, map[string]any{
			"service": "risk",
			"error":   err.Error(),
		}))
	}

	return recent
}

func (s *Service) CacheStatus(ctx context.Context) CacheStatus {
	if s == nil || s.redis == nil || !s.redis.Enabled() {
		return CacheStatus{
			Configured: false,
			Status:     "disabled",
		}
	}

	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		return s.redis.Ping(redisCtx)
	})
	if err != nil {
		return CacheStatus{
			Configured: true,
			Status:     "unavailable",
			Error:      err.Error(),
		}
	}

	status := CacheStatus{
		Configured: true,
		Status:     "ok",
	}
	var runtimeStats cache.RedisRuntimeStats
	statsErr := s.withRedis(ctx, func(redisCtx context.Context) error {
		var err error
		runtimeStats, err = s.redis.RuntimeStats(redisCtx)
		return err
	})
	if statsErr != nil {
		status.ObservabilityError = statsErr.Error()
		return status
	}

	status.UsedMemoryBytes = runtimeStats.UsedMemoryBytes
	status.MaxMemoryBytes = runtimeStats.MaxMemoryBytes
	status.MaxMemoryPolicy = runtimeStats.MaxMemoryPolicy
	status.EvictedKeys = runtimeStats.EvictedKeys
	if safe, known := runtimeStats.ProtectsNonExpiringKeys(); known {
		status.EvictionPolicySafe = &safe
	}
	return status
}

const negativeCacheTTL = 2 * time.Minute

func analysisCacheKey(domain, modelRevision string) string {
	base := fmt.Sprintf("safe-zone:analysis:%s", domain)
	if modelRevision == "" {
		return base
	}
	return base + ":model:" + modelRevision
}

func (s *Service) analyze(ctx context.Context, domain string, lookupMode osintLookupMode, forceOSINT bool) (analysis.Result, bool, []osint.Evidence, Assessment) {
	normalized, err := analysis.NormalizeDomain(domain)
	if err != nil {
		return s.analyzeLexical(domain), false, nil, newDomainAssessment()
	}

	// 1. Check Cache
	var timer layerTimer
	modelRevision := s.currentMLPolicyRevision()
	cacheKey := analysisCacheKey(normalized, modelRevision)
	currentRevision, feedKnown := s.currentFeedRevision(ctx)
	currentBrandRevision, brandKnown := s.currentBrandRevision(ctx)
	currentConfigRevision := s.currentConfigRevision()
	epoch := cacheEpoch{
		AnalysisRevision: analysisAlgorithmRevision,
		ConfigRevision:   currentConfigRevision,
		ModelRevision:    modelRevision,
		FeedRevision:     currentRevision,
		FeedKnown:        feedKnown,
		BrandRevision:    currentBrandRevision,
		BrandKnown:       brandKnown,
	}
	var cached analysis.Result
	var cachedEntry analysisCacheEntry
	timer.measure(LayerResultCache, func() {
		err = s.withRedis(ctx, func(redisCtx context.Context) error {
			var entry analysisCacheEntry
			found, err := s.redis.GetJSON(redisCtx, cacheKey, &entry)
			if err == nil && found && entryMatchesRevision(entry, epoch) {
				cached = entry.Result
				cachedEntry = entry
				return nil
			}

			var legacy analysis.Result
			found, err = s.redis.GetJSON(redisCtx, cacheKey, &legacy)
			if err != nil || !found {
				return err
			}
			return nil
		})
	})
	if err == nil && cached.Domain != "" {
		assess := newDomainAssessment()
		assess.Evaluated = append(assess.Evaluated, LayerResultCache)
		assess.Skipped = append(assess.Skipped,
			LayerThreatFeed, LayerLexical, LayerDomainML, LayerAIRefine)
		if lookupMode == osintLookupOnDemand {
			assess.Evaluated = append(assess.Evaluated, LayerOSINT)
		} else {
			assess.Skipped = append(assess.Skipped, skippedLayer(LayerOSINT, SkipCacheOnly))
		}
		var report osint.Report
		var updated analysis.Result
		timer.measure(LayerOSINT, func() {
			report = s.lookupOSINT(ctx, normalized, cached, lookupMode, forceOSINT)
			updated = s.applyOSINT(ctx, normalized, cached, report, currentRevision)
		})
		// Enqueue after the OSINT section so the worker snapshot is the
		// latest evaluation, and after a cache entry is known to exist:
		// the worker must never read an entry older than its own
		// snapshot's prerequisites. QueuedAt ordering plus the in-flight
		// guard gives exactly one lookup per episode.
		if shouldEnqueueEnrichment(updated) && cachedEntryNeedsEnrichment(cachedEntry) {
			s.enqueueEnrichment(ctx, enrichmentJob{
				Domain:         normalized,
				Result:         updated,
				FeedRevision:   cachedEntry.FeedRevision,
				BrandRevision:  cachedEntry.BrandRevision,
				ConfigRevision: cachedEntry.ConfigRevision,
				ModelRevision:  cachedEntry.ModelRevision,
				QueuedAt:       time.Now().UTC().Format(time.RFC3339Nano),
			})
		}
		assess.Timings = timer.timings
		return updated, true, report.Evidence, assess
	}
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		logjson.Warn("analysis cache read failed", correlation.Fields(ctx, map[string]any{
			"service": "risk",
			"domain":  normalized,
			"error":   err.Error(),
		}))
	}

	// 2. Check Threat Feed
	assess := newDomainAssessment()
	assess.Evaluated = append(assess.Evaluated, LayerThreatFeed)
	var result analysis.Result
	var feedScope FeedScope
	timer.measure(LayerThreatFeed, func() {
		result, feedScope = s.feedResult(ctx, normalized)
	})
	// Shadow scope trace (PR-08b/M7): record hits and trust bypasses in
	// telemetry. Misses stay nil (miss-vs-skip already in the layer lists).
	if feedHit := result.Domain != ""; feedHit || feedScope.TrustBypassed {
		assess.Feed = &feedScope
	}
	feedHit := result.Domain != ""
	if !feedHit {
		// 3. Lexical Analysis
		timer.measure(LayerLexical, func() {
			result = s.analyzeLexical(normalized)
		})
		assess.Evaluated = append(assess.Evaluated, LayerLexical)
	} else {
		assess.Skipped = append(assess.Skipped, LayerLexical)
	}
	// 4. ML refinement/promotion, followed by the existing AI refinement unless
	// ML enforce mode already promoted this suspicious result.
	aiContributed := false
	mlPromoted := false
	if result.Verdict == analysis.VerdictSuspicious {
		assess.Evaluated = append(assess.Evaluated, LayerDomainML)
		timer.measure(LayerDomainML, func() {
			result, mlPromoted = s.classifyML(ctx, result)
		})
		if !mlPromoted {
			assess.Evaluated = append(assess.Evaluated, LayerAIRefine)
			var refined analysis.Result
			timer.measure(LayerAIRefine, func() {
				refined = s.refineWithAI(ctx, result)
			})
			if refined.Verdict != result.Verdict || len(refined.Reasons) > len(result.Reasons) {
				aiContributed = true
			}
			result = refined
			if s.mlMode != analysis.MLModeDisabled && s.mlClassifier != nil && s.mlClassifier.Enabled() {
				s.mlTelemetry.fallbacks.Add(1)
			}
		}
	}
	if !assessedLayer(assess.Evaluated, LayerDomainML) {
		assess.Skipped = append(assess.Skipped, LayerDomainML, LayerAIRefine)
	}
	// 5. OSINT public-warning evidence. API/dashboard can fetch on demand;
	// resolver policy uses cached evidence only via lookupMode.
	if lookupMode == osintLookupOnDemand {
		assess.Evaluated = append(assess.Evaluated, LayerOSINT)
	} else {
		assess.Skipped = append(assess.Skipped, skippedLayer(LayerOSINT, SkipCacheOnly))
	}
	var report osint.Report
	timer.measure(LayerOSINT, func() {
		report = s.lookupOSINT(ctx, normalized, result, lookupMode, forceOSINT)
		result = s.applyOSINT(ctx, normalized, result, report, currentRevision)
	})

	// Cache the final result
	err = nil
	timer.measure(LayerResultCache, func() {
		err = s.withRedis(ctx, func(redisCtx context.Context) error {
			ttl := s.ttlFor(result.Verdict)
			// Nếu AI không contribute (timeout/lỗi), dùng TTL ngắn để retry sớm
			if !aiContributed && result.Verdict == analysis.VerdictSuspicious {
				ttl = negativeCacheTTL
			}
			return s.redis.SetJSON(redisCtx, cacheKey, analysisCacheEntry{
				Result:           result,
				FeedRevision:     currentRevision,
				BrandRevision:    currentBrandRevision,
				AnalysisRevision: analysisAlgorithmRevision,
				ConfigRevision:   currentConfigRevision,
				ModelRevision:    modelRevision,
				// NOTE: no AssessedAt here on purpose. The enrichment job for
				// this evaluation is enqueued below with a later QueuedAt; a
				// stamp here is unnecessary and would only confuse recency
				// comparisons. AssessedAt is set by writers that add new
				// evidence after the snapshot: worker enrichment and OSINT.
			}, ttl)
		})
	})
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		logjson.Warn("analysis cache write failed", correlation.Fields(ctx, map[string]any{
			"service": "risk",
			"domain":  normalized,
			"error":   err.Error(),
		}))
	}

	// Enqueue after the cache write (and after OSINT, whose output is now
	// part of result): the worker must always find a cache entry, and its
	// snapshot must include every synchronous signal, so a worker write
	// can never clobber a same-request OSINT upgrade it never saw.
	if shouldEnqueueEnrichment(result) {
		assess.Skipped = append(assess.Skipped, skippedLayer(LayerEnrichment, SkipAsync))
		s.enqueueEnrichment(ctx, enrichmentJob{
			Domain:         normalized,
			Result:         result,
			FeedRevision:   currentRevision,
			BrandRevision:  currentBrandRevision,
			ConfigRevision: currentConfigRevision,
			ModelRevision:  modelRevision,
			QueuedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		})
	} else {
		assess.Skipped = append(assess.Skipped, skippedLayer(LayerEnrichment, SkipOutOfRange))
	}

	assess.Timings = timer.timings
	return result, false, report.Evidence, assess
}

func assessedLayer(layers []string, layer string) bool {
	for _, l := range layers {
		if l == layer {
			return true
		}
	}
	return false
}

func (s *Service) feedResult(ctx context.Context, domain string) (analysis.Result, FeedScope) {
	// PR-08a/H2 scope authority: a live *exact* IOC is scoped evidence for
	// this host and wins over the trusted-brand suffix bypass (a compromised
	// tenant host stays blockable). A *parent-only* match under a trusted
	// root keeps the bypass: one noisy IOC must not block a whole shared
	// root. Redis errors stay fail-open, as before.
	// PR-08b/M7 shadow: the returned scope is observability only and never
	// gates the verdict.
	exactHit, err := s.matchExactThreatFeed(ctx, domain)
	if err != nil {
		if !errors.Is(err, cache.ErrDisabled) {
			logjson.Warn("threat feed lookup failed", correlation.Fields(ctx, map[string]any{
				"service": "risk",
				"domain":  domain,
				"error":   err.Error(),
			}))
		}
		return analysis.Result{}, FeedScope{}
	}
	if exactHit {
		// FP-guard 2026-09/M7: an exact feed IOC on shared
		// infrastructure (a whole CDN apex, github.com) is contextual,
		// not authoritative. URL-only IOCs ingested as host entries must
		// not block shared apexes; tenant subdomains beneath them still
		// match exactly and keep full weight.
		if isSharedFeedApex(domain) {
			return sharedApexFeedHit(domain), FeedScope{ExactMatch: true, Candidate: domain, SharedApex: true}
		}
		return threatFeedHit(domain), FeedScope{ExactMatch: true, Candidate: domain}
	}

	if analysis.IsTrustedBrandSuffix(domain, s.trustedBrands(ctx)) || analysis.IsTrustedInfraSuffix(domain) {
		return analysis.Result{}, FeedScope{TrustBypassed: true}
	}

	candidate, err := s.matchParentCandidate(ctx, domain)
	if err != nil {
		if !errors.Is(err, cache.ErrDisabled) {
			logjson.Warn("threat feed lookup failed", correlation.Fields(ctx, map[string]any{
				"service": "risk",
				"domain":  domain,
				"error":   err.Error(),
			}))
		}
		return analysis.Result{}, FeedScope{}
	}
	if candidate == "" {
		return analysis.Result{}, FeedScope{}
	}

	return threatFeedHit(domain), FeedScope{Candidate: candidate, Depth: feedMatchDepth(domain, candidate)}
}

// feedMatchDepth counts labels from the queried domain up to the matched
// parent candidate: 0 is the exact host.
func feedMatchDepth(domain, candidate string) int {
	depth := 0
	for d := domain; d != candidate; {
		idx := strings.IndexByte(d, '.')
		if idx < 0 {
			break
		}
		d = d[idx+1:]
		depth++
	}
	return depth
}

// threatFeedHit builds the malicious verdict for a live threat-feed match.
func threatFeedHit(domain string) analysis.Result {
	return analysis.Result{
		Domain:     domain,
		Verdict:    analysis.VerdictMalicious,
		Confidence: 1,
		Score:      100,
		Reasons:    []string{threatFeedReason},
	}
}

// sharedApexFeedHit builds the contextual verdict for a live threat-feed
// member that IS shared infrastructure. The report is preserved as
// evidence (SUSPICIOUS so policy never hard-blocks on it alone) while the
// apex keeps serving.
func sharedApexFeedHit(domain string) analysis.Result {
	return analysis.Result{
		Domain:     domain,
		Verdict:    analysis.VerdictSuspicious,
		Confidence: 0.6,
		Score:      40,
		Reasons:    []string{threatFeedReason, sharedFeedApexReason},
	}
}

// isSharedFeedApex reports whether host is shared infrastructure whose own
// feed membership (or inheritance by its children) must stay contextual:
// an explicitly listed multi-tenant serving hostname (delegated to
// analysis.IsSharedServingHost), or a known CDN/cloud root queried at the root
// itself. Tenant subdomains (evil.github.io, x.amazonaws.com) are never apexes:
// exact IOCs on them still block.
func isSharedFeedApex(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return false
	}
	if analysis.IsSharedServingHost(h) {
		return true
	}
	return h == whois.RegisteredDomain(h) && analysis.IsSharedHostingRoot(h)
}

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

// AdblockStatus holds runtime telemetry for the adblock subsystem.
// lookupEffectiveOverride reads the operator override for a domain.
//
// The previous code assigned the error to a variable that was never read: a
// SQLite lock, a busy database, or any I/O failure silently turned "this
// domain is administratively blocked" into "evaluate it normally", with no log,
// no counter, and no signal anywhere. That is a fail-open on the one control an
// operator set deliberately, on the DNS hot path.
//
// Failing closed instead is not an option: a transient store error would then
// block every domain for every client, which is a self-inflicted outage. So the
// policy is fail-open but loud — count it, log it, and publish it.
//
// An earlier version retried once after a short pause. That was removed: SQLite
// is opened with a single connection and busy_timeout=5000, so genuine lock
// contention already resolves inside the driver and the retry almost never
// helped. Meanwhile a *sustained* store failure — a full disk, a stuck WAL — is
// exactly the case where it hurt most, adding the delay to every request on
// the hot path. Measured at 16 ms per failed request, which under load means
// thousands of goroutines sleeping to fail anyway.
//
// consecutiveOverrideFailures is what lets an operator tell "broken right now"
// from "broke three times since Tuesday", and it is reset by the first
// success.
func (s *Service) lookupEffectiveOverride(ctx context.Context, groupID int64, domain string) (*store.Override, error) {
	override, err := s.readEffectiveOverride(ctx, groupID, domain)
	if err == nil {
		if s.overrideConsecutiveFailures.Load() > 0 {
			s.overrideConsecutiveFailures.Store(0)
			s.overrideLastSuccessUnix.Store(time.Now().Unix())
		}
		return override, nil
	}

	s.overrideLookupFailures.Add(1)
	s.overrideConsecutiveFailures.Add(1)
	s.overrideLastFailureUnix.Store(time.Now().Unix())
	logjson.Warn("override lookup failed; evaluating without the operator override", map[string]any{
		"service":     "risk",
		"domain":      domain,
		"group_id":    groupID,
		"error":       err.Error(),
		"fail_open":   true,
		"consecutive": s.overrideConsecutiveFailures.Load(),
	})
	return nil, err
}

func (s *Service) OverrideLookupFailures() int64 {
	if s == nil {
		return 0
	}
	return s.overrideLookupFailures.Load()
}

// overrideReader is what the override seam must satisfy. *store.DB implements
// it directly, so production reads through the store with no wrapper.
type overrideReader interface {
	GetEffectiveOverride(ctx context.Context, groupID int64, domain string) (*store.Override, error)
}

// readEffectiveOverride is the seam the override lookup goes through. It exists
// so a test can drive the failure path directly: closing the store is not a
// usable substitute, because GetEffectiveOverride returns (nil, nil) once
// Enabled() is false rather than an error, and a cancelled context only
// exercises the caller's own context. Without this seam the failure branch of
// the hot path had no coverage at all.
func (s *Service) readEffectiveOverride(ctx context.Context, groupID int64, domain string) (*store.Override, error) {
	// Both halves are checked, and the interface type does not remove the need.
	// atomic.Pointer can only hold *T, so a pointer to a nil interface value
	// is representable, and calling through it panics on the DNS hot path.
	// Store(nil) is the only way to clear the seam.
	if injected := s.overrideLookup.Load(); injected != nil && *injected != nil {
		return (*injected).GetEffectiveOverride(ctx, groupID, domain)
	}
	return s.store.GetEffectiveOverride(ctx, groupID, domain)
}

// DecisionPipelineStatus reports fail-open degradations on the hot path.
type DecisionPipelineStatus struct {
	// OverrideLookupFailures counts every admin-override read that failed
	// since start-up. Each one means a domain the operator had blocked was
	// evaluated normally, because failing closed would block all traffic
	// instead of just this. Zero is the healthy state.
	OverrideLookupFailures int64 `json:"override_lookup_failures"`
	// OverrideConsecutiveFailures is the number that actually distinguishes
	// "currently broken" from "failed a few times since last boot": it resets
	// on the first success. Alert on this being non-zero for a sustained
	// period, not on the total.
	OverrideConsecutiveFailures int64 `json:"override_consecutive_failures"`
	// LastFailureAt and LastSuccessAt are RFC3339 stamps, empty until the
	// corresponding event has happened at least once.
	LastFailureAt string `json:"last_failure_at,omitempty"`
	LastSuccessAt string `json:"last_success_at,omitempty"`
	// OutboundProxyEnabled reports whether the address guard has been
	// deliberately switched off. With a proxy configured, netguard validates
	// the proxy's address instead of the destination's, so every outbound
	// fetch runs unchecked. That is a deliberate operator choice, but it is
	// invisible in logs alone — a transport is built per fetch for the agent
	// paths, so the one-shot warning is easy to miss. Publish it as state.
	OutboundProxyEnabled bool `json:"outbound_proxy_enabled"`
}

func (s *Service) DecisionPipelineStatus() DecisionPipelineStatus {
	if s == nil {
		return DecisionPipelineStatus{}
	}
	status := DecisionPipelineStatus{
		OverrideLookupFailures:      s.overrideLookupFailures.Load(),
		OverrideConsecutiveFailures: s.overrideConsecutiveFailures.Load(),
		OutboundProxyEnabled:        netguard.OutboundProxyEnabled(),
	}
	if unix := s.overrideLastFailureUnix.Load(); unix > 0 {
		status.LastFailureAt = time.Unix(unix, 0).UTC().Format(time.RFC3339)
	}
	if unix := s.overrideLastSuccessUnix.Load(); unix > 0 {
		status.LastSuccessAt = time.Unix(unix, 0).UTC().Format(time.RFC3339)
	}
	return status
}

type AdblockStatus struct {
	Enabled         bool   `json:"enabled"`
	MatchMode       string `json:"match_mode"`
	DomainCount     int    `json:"domain_count"`
	ExactRuleCount  int    `json:"exact_rule_count"`
	SuffixRuleCount int    `json:"suffix_rule_count"`
	LastSyncAt      string `json:"last_sync_at,omitempty"`
	LastSyncOK      bool   `json:"last_sync_ok"`
	SourceCount     int    `json:"source_count"`
	SuccessCount    int    `json:"success_count"`
	// SourcePoliciesFingerprint digests the effective per-source policy set.
	// core-api and dns-resolver each hold their own copy, so comparing this
	// value across the two is how an operator confirms the nodes agree rather
	// than assuming it. An empty set digests to a stable value, not an empty
	// string, so "no policies" is still comparable.
	SourcePoliciesFingerprint string                   `json:"source_policies_fingerprint"`
	SourcePolicyCount         int                      `json:"source_policy_count"`
	Exceptions                AdblockExceptionStatus   `json:"exceptions"`
	ShadowExact               AdblockShadowExactStatus `json:"shadow_exact"`
}

// AdblockStatus returns a snapshot of the adblock subsystem state.
func (s *Service) AdblockStatus() AdblockStatus {
	matchMode := "suffix"
	if v := s.adblockMatchMode.Load(); v != nil {
		if mode, ok := v.(string); ok && mode != "" {
			matchMode = mode
		}
	}
	status := AdblockStatus{
		Enabled:      s.isAdblockEnabled(),
		MatchMode:    matchMode,
		LastSyncOK:   s.adblockLastSyncOK.Load(),
		SourceCount:  int(s.adblockSrcCount.Load()),
		SuccessCount: int(s.adblockOKCount.Load()),
		Exceptions:   s.AdblockExceptionStatus(),
		ShadowExact:  s.AdblockShadowExactStatus(),
	}
	if policies := s.currentAdblockSourcePolicies(); policies != nil {
		status.SourcePoliciesFingerprint = adblockSourcePoliciesFingerprint(policies)
		status.SourcePolicyCount = len(policies)
	}
	if t := s.adblockTrie.Load(); t != nil {
		status.DomainCount = t.Count()
		status.ExactRuleCount = t.ExactCount()
		status.SuffixRuleCount = t.SuffixCount()
	}
	if v := s.adblockLastSync.Load(); v != nil {
		if ts, ok := v.(time.Time); ok {
			status.LastSyncAt = ts.UTC().Format(time.RFC3339)
		}
	}
	return status
}

func splitAdblockSources(sources string) []string {
	parts := strings.Split(sources, ",")
	result := make([]string, 0, len(parts))
	for _, source := range parts {
		source = strings.TrimSpace(source)
		if source != "" {
			result = append(result, source)
		}
	}
	return result
}

func (s *Service) adblockMetaPath() string {
	return filepath.Join(s.adblockDataRoot, "adblock_meta.json")
}

func (s *Service) adblockCachePath() string {
	return filepath.Join(s.adblockDataRoot, "adblock_cache.txt")
}

func (s *Service) adblockSourceCacheRoot() string {
	return filepath.Join(s.adblockDataRoot, "adblock_sources")
}

// adblockSourceCachePath derives the on-disk location of a source's download
// cache. Keyed by the canonical source key so it matches canonicalSourceID,
// which stamps the same identity into rule provenance: hashing the raw string
// here while provenance used the canonical form gave one source two
// identities, and two cache files for a case change that meant the same source.
func (s *Service) adblockSourceCachePath(source string) string {
	sum := sha256.Sum256([]byte(canonicalSourceKey(strings.TrimSpace(source))))
	return filepath.Join(s.adblockSourceCacheRoot(), fmt.Sprintf("%x.txt", sum[:]))
}

func (s *Service) ensureAdblockDataRoot() error {
	if strings.TrimSpace(s.adblockDataRoot) == "" {
		return nil
	}
	return os.MkdirAll(s.adblockDataRoot, 0o750)
}

func (s *Service) ensureAdblockSourceCacheRoot() error {
	if err := s.ensureAdblockDataRoot(); err != nil {
		return err
	}
	return os.MkdirAll(s.adblockSourceCacheRoot(), 0o750)
}

func replaceFile(tmpPath, finalPath string) error {
	lock, _ := replaceFileLocks.LoadOrStore(finalPath, &sync.Mutex{})
	mu := lock.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	if err := os.Remove(finalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(tmpPath, finalPath)
}

func createReplaceTempFile(finalPath string) (*os.File, string, error) {
	dir := filepath.Dir(finalPath)
	pattern := filepath.Base(finalPath) + ".tmp-*"
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, "", err
	}
	return f, f.Name(), nil
}

func isRemoteAdblockSource(source string) bool {
	return strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://")
}

func loadAdblockMeta(metaPath string) map[string]adblockSourceMeta {
	meta := make(map[string]adblockSourceMeta)
	// #nosec G304 -- metaPath is constructed safely internally
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		return meta
	}
	_ = json.Unmarshal(metaData, &meta)
	return meta
}

func adblockSourceMetaFromHeader(header http.Header) adblockSourceMeta {
	if header == nil {
		return adblockSourceMeta{}
	}
	return adblockSourceMeta{
		ETag:         header.Get("ETag"),
		LastModified: header.Get("Last-Modified"),
	}
}

func (s *Service) saveAdblockMeta(metaPath string, meta map[string]adblockSourceMeta) {
	metaData, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return
	}
	if err := s.ensureAdblockDataRoot(); err != nil {
		logjson.Warn("failed to create adblock data root", map[string]any{"error": err.Error()})
		return
	}
	f, tmpMeta, err := createReplaceTempFile(metaPath)
	if err != nil {
		return
	}
	if _, err := f.Write(metaData); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpMeta)
		return
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpMeta)
		return
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpMeta)
		return
	}
	if err := replaceFile(tmpMeta, metaPath); err != nil {
		logjson.Warn("failed to rename adblock meta temp file", map[string]any{"error": err.Error()})
		_ = os.Remove(tmpMeta)
	}
}

// parseAdblockSourceInto decodes one feed stream into the provided staging
// trie without touching any global destination. It returns the Scanner/I/O
// error (if any) so callers can decide whether the staging state is committable.
// The stream itself is never buffered as []Rule/[]byte; only parsed rules
// accumulate in the staging trie.
// adblockSectionCategories maps merged-list section names (the "# Start
// <name>" markers of composite hosts files such as StevenBlack's unified
// list) to closed-vocab content categories. Every mapping is evidenced by
// the section's own documented purpose, quoted below. Sections without an
// unambiguous documented purpose keep the source-level category (unknown
// by default): the parser never infers from entry text, so a reorganized
// upstream degrades to today's behavior instead of mislabeling.
var adblockSectionCategories = map[string]string{
	// "Blocking mobile ad providers and some analytics providers"
	"adaway.org": "tracking",
	// "Only include advertisers in Vietnam"
	"hostsVN": "ads",
	// "minecraft-hosts - Tracking Domains"
	"minecraft-hosts": "tracking",
}

func parseAdblockSectionMarker(raw string) (name string, end bool) {
	line := strings.TrimSpace(raw)
	if !strings.HasPrefix(line, "#") {
		return "", false
	}
	fields := strings.Fields(strings.TrimSpace(line[1:]))
	if len(fields) == 0 {
		return "", false
	}
	switch fields[0] {
	case "Start":
		// Single-token names only: "# Start your engines" prose must
		// never flip section state.
		if len(fields) == 2 {
			return fields[1], false
		}
		return "", false
	case "End":
		return "", true
	default:
		return "", false
	}
}

func (s *Service) parseAdblockSourceInto(reader io.Reader, staging *domaintrie.Trie, sourceID string, category string, scope domaintrie.RuleScope, origin domaintrie.ScopeOrigin) error {
	if staging == nil {
		return errors.New("adblock staging trie is nil")
	}
	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)
	section := ""
	for scanner.Scan() {
		raw := scanner.Text()
		if name, end := parseAdblockSectionMarker(raw); name != "" || end {
			if end {
				section = ""
			} else {
				section = name
			}
			continue
		}
		ruleCategory := category
		if section != "" {
			if mapped, ok := adblockSectionCategories[section]; ok {
				ruleCategory = mapped
			}
		}
		line := strings.TrimSpace(raw)
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		startIdx := 0
		if ip := net.ParseIP(parts[0]); ip != nil {
			startIdx = 1
		}

		for _, domain := range parts[startIdx:] {
			domain = strings.ToLower(domain)
			if domain != "" && domain != "localhost" && domain != "local" && domain != "broadcasthost" {
				staging.AddRule(domaintrie.Rule{
					Domain:   domain,
					Scope:    scope,
					SourceID: sourceID,
					Category: ruleCategory,
					Action:   domaintrie.RuleActionBlock,
					Origin:   origin,
				})
			}
		}
	}
	return scanner.Err()
}

// parseAdblockSource parses one feed stream with source-level atomicity: the
// stream is decoded into a staging trie and merged into trie only after the
// whole source scans without a Scanner/I/O error, so a source that fails
// partway contributes zero rules. Merging in SAFE_ZONE_ADBLOCK_SOURCES order
// preserves first-wins per (domain, scope). Remote fetches must not use this
// helper directly: saveAdblockSourceCache parses into staging and merges only
// after the cache commit (Close, Sync, replace) succeeds.
func (s *Service) parseAdblockSource(reader io.Reader, trie *domaintrie.Trie, sourceID string, category string, scope domaintrie.RuleScope, origin domaintrie.ScopeOrigin) error {
	if trie == nil {
		return errors.New("adblock destination trie is nil")
	}
	staging := domaintrie.NewTrie()
	if err := s.parseAdblockSourceInto(reader, staging, sourceID, category, scope, origin); err != nil {
		return err
	}
	trie.MergeFrom(staging)
	return nil
}

// parseAdblockCache loads the global cache with whole-load atomicity: records
// decode into a staging trie and merge only when the Scanner reaches EOF
// without an I/O/token-too-long error. A Scanner error fails the entire load
// (false, destination untouched) so a partially read cache is never
// published. Individual malformed v2 records are still skipped by design.
// Legacy v1 domain-only content is lossy (exact/suffix provenance is dropped
// on write) and reloads as suffix/unknown/block for degraded-mode continuity,
// never as a lossless typed restore.
func (s *Service) parseAdblockCache(reader io.Reader, trie *domaintrie.Trie) bool {
	if trie == nil {
		return false
	}
	staging := domaintrie.NewTrie()
	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	firstLine := true
	v2 := false
	malformed := 0
	total := 0
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if firstLine {
			firstLine = false
			if strings.HasPrefix(line, domaintrie.CacheV2Header) {
				v2 = true
				continue
			}
			// Legacy v1 cache: the first line is already a domain.
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if v2 {
			total++
			rule, ok := domaintrie.ParseCacheV2Line(line)
			if !ok {
				malformed++
				continue
			}
			staging.AddRule(rule)
			continue
		}
		// Legacy degraded-mode semantics: domains-only cache reloads as
		// suffix/unknown/block rules from a synthetic provenance label, so a
		// degraded network sync never silently changes match behavior to the
		// configured exact default.
		total++
		staging.AddRule(domaintrie.Rule{
			Domain:   strings.TrimSpace(line),
			Scope:    domaintrie.RuleScopeSuffix,
			SourceID: domaintrie.CacheV2LegacySourceID,
			Category: domaintrie.DefaultRuleCategory,
			Action:   domaintrie.RuleActionBlock,
			Origin:   domaintrie.OriginLegacyCache,
		})
	}
	if err := scanner.Err(); err != nil {
		logjson.Warn("error reading adblock cache file", map[string]any{"error": err.Error()})
		return false
	}
	if malformed > 0 {
		logjson.Warn("skipped malformed adblock cache records", map[string]any{
			"records":   total,
			"malformed": malformed,
		})
	}
	if staging.Count() == 0 {
		return false
	}
	trie.MergeFrom(staging)
	return true
}

// saveAdblockSourceCache persists one remote source body to its per-source
// cache file and merges its rules into trie only after parse, Close, Sync and
// replace all succeed. A cache persistence failure therefore contributes
// exactly zero rules; the sync loop's fallback to the old cache file then
// merges only old data, never a mix of uncommitted refresh plus old cache.
func (s *Service) saveAdblockSourceCache(source string, reader io.Reader, trie *domaintrie.Trie, sourceID string, category string, scope domaintrie.RuleScope, origin domaintrie.ScopeOrigin) error {
	if trie == nil {
		return errors.New("adblock destination trie is nil")
	}
	if err := s.ensureAdblockSourceCacheRoot(); err != nil {
		return err
	}
	finalPath := s.adblockSourceCachePath(source)
	f, tmpPath, err := createReplaceTempFile(finalPath)
	if err != nil {
		return err
	}

	staging := domaintrie.NewTrie()
	tee := io.TeeReader(reader, f)
	parseErr := s.parseAdblockSourceInto(tee, staging, sourceID, category, scope, origin)
	closeErr := f.Close()
	if parseErr != nil {
		_ = os.Remove(tmpPath)
		return parseErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return closeErr
	}
	if err := commitAdblockSourceCache(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	trie.MergeFrom(staging)
	return nil
}

// commitAdblockSourceCache fsyncs the staged per-source cache temp file and
// publishes it at the final cache path via replaceFile. replaceFile is a
// remove-then-rename sequence serialized in-process per path, not a
// crash-atomic rename: a crash between remove and rename can leave the final
// path momentarily absent. Concurrent readers therefore observe either the
// old file or an error, never a torn write, since the temp file is fully
// synced before the swap.
func commitAdblockSourceCache(tmpPath, finalPath string) error {
	if err := syncPath(tmpPath); err != nil {
		return err
	}
	return replaceFile(tmpPath, finalPath)
}

func syncPath(path string) error {
	// #nosec G304 -- path is constructed safely internally
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}

func (s *Service) loadAdblockSourceCache(source string, trie *domaintrie.Trie, sourceID string, category string, scope domaintrie.RuleScope, origin domaintrie.ScopeOrigin) bool {
	f, err := os.Open(s.adblockSourceCachePath(source))
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	if err := s.parseAdblockSource(f, trie, sourceID, category, scope, origin); err != nil {
		logjson.Warn("error reading adblock source cache", map[string]any{"source": source, "error": err.Error()})
		return false
	}
	return true
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
					if err := s.saveAdblockSourceCache(source, response.Reader, newTrie, sourceID, sourceCategory, sourceScope, sourceOrigin); err == nil {
						successCount++
						networkCount++
						nextMeta[source] = adblockSourceMetaFromHeader(response.Header)
						return
					} else {
						logjson.Warn("failed to refresh adblock source cache", map[string]any{"source": source, "error": err.Error()})
					}
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

func (s *Service) syncAIClient() {
	if s == nil || s.store == nil || !s.store.Enabled() {
		return
	}

	s.aiMu.Lock()
	defer s.aiMu.Unlock()

	now := time.Now()
	if !s.lastGeminiKeySync.IsZero() && now.Sub(s.lastGeminiKeySync) < geminiKeySyncCooldown {
		return
	}
	s.lastGeminiKeySync = now

	customKey, err := s.store.GetSystemConfig(context.Background(), "gemini_api_key")
	if err != nil {
		return
	}
	customKey = strings.TrimSpace(customKey)

	if customKey == s.cachedGeminiKey {
		if customKey != "" && s.ai == nil {
			s.ai = ai.NewClient(ai.Config{Provider: "gemini"})
			s.ai.SetGeminiAPIKey(customKey)
		}
		return
	}

	if customKey == "" {
		if s.cachedGeminiKey != "" && s.ai != nil {
			s.ai.SetGeminiAPIKey("")
			if !s.ai.Enabled() && !s.aiShared {
				s.ai = nil
			}
		}
		s.cachedGeminiKey = ""
		return
	}

	if s.ai == nil {
		s.ai = ai.NewClient(ai.Config{Provider: "gemini"})
	}
	s.ai.SetGeminiAPIKey(customKey)
	s.cachedGeminiKey = customKey
}

func (s *Service) refineWithAI(ctx context.Context, current analysis.Result) analysis.Result {
	if s == nil {
		return current
	}
	if current.Verdict != analysis.VerdictSuspicious {
		return current
	}
	s.syncAIClient()

	s.aiMu.Lock()
	client := s.ai
	if client == nil || !client.Enabled() {
		s.aiMu.Unlock()
		return current
	}
	aiResult, err := client.Refine(ctx, current.Domain, current)
	s.aiMu.Unlock()

	if err != nil {
		logjson.Warn("local ai refinement failed", correlation.Fields(ctx, map[string]any{
			"service": "risk",
			"domain":  current.Domain,
			"error":   err.Error(),
		}))
		return current
	}
	if aiResult.Verdict != analysis.VerdictMalicious {
		if len(aiResult.Reasons) > 0 {
			current.Reasons = append(current.Reasons, aiResult.Reasons...)
		}
		return current
	}

	current.Verdict = analysis.VerdictMalicious
	if aiResult.Score > current.Score {
		current.Score = aiResult.Score
	}
	if aiResult.Confidence > current.Confidence {
		current.Confidence = aiResult.Confidence
	}
	current.Reasons = append(current.Reasons, aiResult.Reasons...)
	return current
}

func (s *Service) trustedBrands(ctx context.Context) []analysis.Brand {
	if s == nil || s.brandStore == nil {
		return analysis.DetectionBrands(analysis.DefaultTrustedBrands())
	}
	if ctx == nil {
		ctx = context.Background()
	}
	brands, err := s.brandStore.ListBrands(ctx)
	if err != nil || len(brands) == 0 {
		return analysis.DetectionBrands(analysis.DefaultTrustedBrands())
	}
	return analysis.DetectionBrands(brands)
}

func (s *Service) lookupOSINT(ctx context.Context, domain string, result analysis.Result, mode osintLookupMode, force bool) osint.Report {
	if s == nil || s.osint == nil || !s.osint.Enabled() || mode == osintLookupNone {
		return osint.Report{}
	}
	if !force && !osint.ShouldLookup(domain, result) {
		return osint.Report{}
	}

	switch mode {
	case osintLookupCachedOnly:
		report, ok := s.osint.Cached(ctx, domain)
		if !ok {
			return osint.Report{}
		}
		report.CacheHit = true
		return report
	case osintLookupOnDemand:
		report, err := s.osint.Lookup(ctx, domain, force)
		if err != nil {
			logjson.Warn("osint lookup failed", correlation.Fields(ctx, map[string]any{
				"service": "risk",
				"domain":  domain,
				"error":   err.Error(),
			}))
		}
		s.recordOSINTEvidence(report)
		return report
	default:
		return osint.Report{}
	}
}

func (s *Service) applyOSINT(ctx context.Context, domain string, result analysis.Result, report osint.Report, feedRevision string) analysis.Result {
	if s == nil || s.osint == nil || !report.ShouldBlock {
		return result
	}
	updated := s.osint.Apply(result, report)
	if updated.Verdict == result.Verdict && updated.Score == result.Score {
		return updated
	}

	modelRevision := s.currentMLPolicyRevision()
	cacheKey := analysisCacheKey(domain, modelRevision)
	brandRevision, _ := s.currentBrandRevision(ctx)
	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		return s.redis.SetJSON(redisCtx, cacheKey, analysisCacheEntry{
			Result:           updated,
			FeedRevision:     feedRevision,
			BrandRevision:    brandRevision,
			AnalysisRevision: analysisAlgorithmRevision,
			ConfigRevision:   s.currentConfigRevision(),
			ModelRevision:    modelRevision,
			OSINTCheckedAt:   report.CheckedAt,
			AssessedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		}, s.ttlFor(updated.Verdict))
	})
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		logjson.Warn("analysis cache osint write failed", correlation.Fields(ctx, map[string]any{
			"service": "risk",
			"domain":  domain,
			"error":   err.Error(),
		}))
	}
	return updated
}

func (s *Service) recordOSINTEvidence(report osint.Report) {
	if s == nil || s.store == nil || !s.store.Enabled() || len(report.Evidence) == 0 {
		return
	}
	expiresAt := report.ExpiresAt
	if expiresAt == "" {
		expiresAt = time.Now().Add(6 * time.Hour).UTC().Format(time.RFC3339Nano)
	}
	items := make([]store.OSINTEvidence, 0, len(report.Evidence))
	for _, ev := range report.Evidence {
		items = append(items, store.OSINTEvidence{
			Domain:       ev.Domain,
			SourceURL:    ev.SourceURL,
			SourceTitle:  ev.SourceTitle,
			SourceType:   ev.SourceType,
			Confidence:   ev.Confidence,
			MatchedTerms: ev.MatchedTerms,
			RetrievedAt:  ev.RetrievedAt,
			ExpiresAt:    expiresAt,
		})
	}
	if err := s.store.ReplaceOSINTEvidence(context.Background(), report.Domain, items); err != nil {
		logjson.Warn("osint evidence store write failed", map[string]any{
			"service": "risk",
			"domain":  report.Domain,
			"error":   err.Error(),
		})
	}
}

func shouldEnqueueEnrichment(result analysis.Result) bool {
	if result.Domain == "" || result.Score < 20 || result.Score >= 70 {
		return false
	}
	// Contextual shared-infrastructure verdicts (FP-guard 2026-09, M7)
	// never spend inspection budget: TLS/WHOIS metadata must not promote
	// them, so there is nothing for the worker to add.
	for _, reason := range result.Reasons {
		if reason == sharedFeedApexReason {
			return false
		}
	}
	return true
}

func cachedEntryNeedsEnrichment(entry analysisCacheEntry) bool {
	return entry.EnrichedAt == ""
}

func (s *Service) enqueueEnrichment(ctx context.Context, job enrichmentJob) {
	if s == nil || !s.enrichEnabled || s.enrichQueue == nil || s.enrichTimeout <= 0 {
		return
	}
	s.enrichMu.Lock()
	if _, ok := s.enrichInFlight[job.Domain]; ok {
		s.enrichMu.Unlock()
		return
	}
	s.enrichInFlight[job.Domain] = struct{}{}
	s.enrichMu.Unlock()

	select {
	case s.enrichQueue <- job:
	case <-ctx.Done():
		s.clearEnrichmentInFlight(job.Domain)
	default:
		s.clearEnrichmentInFlight(job.Domain)
		logjson.Warn("enrichment queue full; skipping background job", correlation.Fields(ctx, map[string]any{
			"service": "risk",
			"domain":  job.Domain,
		}))
	}
}

func (s *Service) clearEnrichmentInFlight(domain string) {
	s.enrichMu.Lock()
	delete(s.enrichInFlight, domain)
	s.enrichMu.Unlock()
}

func (s *Service) enrichmentWorker() {
	defer s.enrichWG.Done()
	for {
		select {
		case <-s.enrichDone:
			return
		case job := <-s.enrichQueue:
			s.processEnrichmentJob(job)
			s.clearEnrichmentInFlight(job.Domain)
		}
	}
}

func (s *Service) processEnrichmentJob(job enrichmentJob) {
	if s == nil || s.redis == nil || !s.redis.Enabled() {
		return
	}
	if current, known := s.currentFeedRevision(s.lifecycleCtx); known && current != "" && job.FeedRevision != "" && current != job.FeedRevision {
		return
	}
	if current, known := s.currentBrandRevision(s.lifecycleCtx); known && current != "" && job.BrandRevision != "" && current != job.BrandRevision {
		return
	}
	if current := s.currentConfigRevision(); current != job.ConfigRevision {
		return
	}
	if current := s.currentMLPolicyRevision(); current != job.ModelRevision {
		return
	}

	enrichCtx, cancel := context.WithTimeout(s.lifecycleCtx, s.enrichTimeout)
	defer cancel()

	signals := s.enrichmentLookup(enrichCtx, job.Domain)
	enriched := job.Result
	applyEnrichmentSignals(&enriched, signals)

	now := time.Now().UTC().Format(time.RFC3339Nano)
	cacheKey := analysisCacheKey(job.Domain, job.ModelRevision)
	// Recency guard (M1/PR-05): a job snapshot must not overwrite an
	// evaluation materialized after the snapshot was taken. The read and
	// the conditional write run inside one WATCH transaction, so even
	// cross-process races between two services sharing Redis converge on
	// the fresher entry instead of last-writer-wins.
	skippedStale := false
	queuedAt := jobQueuedAt(job.QueuedAt)
	err := s.withRedis(s.lifecycleCtx, func(redisCtx context.Context) error {
		swapped, err := s.redis.CompareAndSwapJSON(redisCtx, cacheKey,
			func(raw []byte, found bool) (bool, error) {
				if !found {
					return true, nil
				}
				var current analysisCacheEntry
				if err := json.Unmarshal(raw, &current); err != nil {
					return false, err
				}
				if current.Result.Domain != "" &&
					entryAssessedAt(current).After(queuedAt) {
					return false, nil
				}
				return true, nil
			}, analysisCacheEntry{
				Result:           enriched,
				FeedRevision:     job.FeedRevision,
				BrandRevision:    job.BrandRevision,
				AnalysisRevision: analysisAlgorithmRevision,
				ConfigRevision:   job.ConfigRevision,
				ModelRevision:    job.ModelRevision,
				EnrichedAt:       now,
				AssessedAt:       now,
			}, s.ttlFor(enriched.Verdict))
		if err != nil {
			if errors.Is(err, cache.ErrCASConflict) {
				skippedStale = true
				return nil
			}
			return err
		}
		if !swapped {
			skippedStale = true
		}
		return nil
	})
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		logjson.Warn("background enrichment cache write failed", map[string]any{
			"service": "risk",
			"domain":  job.Domain,
			"error":   err.Error(),
		})
	}
	if skippedStale {
		logjson.Info("background enrichment skipped stale snapshot", map[string]any{
			"service": "risk",
			"domain":  job.Domain,
		})
	}
}

func (s *Service) defaultEnrichmentLookup(ctx context.Context, domain string) enrichmentSignals {
	var (
		dnsOutcome  = DNSOutcomeOK
		tlsResult   tlsinspect.Result
		whoisResult whois.Result
		wg          sync.WaitGroup
	)
	wg.Add(3)
	go func() {
		defer wg.Done()
		apex := whois.RegisteredDomain(domain)
		if apex == "" {
			return
		}
		nsCtx, cancel := context.WithTimeout(ctx, minDuration(2*time.Second, enrichContextTimeout(ctx, 2*time.Second)))
		defer cancel()
		nss, err := net.DefaultResolver.LookupNS(nsCtx, apex)
		if outcome := classifyDNSLookupErr(err); outcome != DNSOutcomeOK {
			dnsOutcome = outcome
			return
		}
		if len(nss) == 0 {
			dnsOutcome = DNSOutcomeNoData
		}
	}()
	go func() {
		defer wg.Done()
		tlsResult = tlsinspect.Inspect(ctx, domain)
	}()
	go func() {
		defer wg.Done()
		whoisResult = whois.LookupWithCache(ctx, domain, s.store, s.whoisCacheTTL)
	}()
	wg.Wait()
	return enrichmentSignals{
		DNS:   dnsOutcome,
		TLS:   tlsResult,
		WHOIS: whoisResult,
	}
}

func applyEnrichmentSignals(result *analysis.Result, signals enrichmentSignals) {
	if result == nil {
		return
	}
	// DNS outcomes are availability notes only. They never add to the
	// security score: an unreachable, slow or failing resolver says
	// nothing about malice (PR-01/H1).
	if signals.DNS != DNSOutcomeOK {
		result.Reasons = append(result.Reasons, signals.DNS.String())
	}
	tlsScore := signals.TLS.Score
	registeredDomain := whois.RegisteredDomain(result.Domain)
	isCDNOrTrustedInfra := analysis.IsCDNRoot(registeredDomain) || analysis.IsTrustedInfraSuffix(result.Domain)
	if signals.TLS.AdvisoryScore > 0 && (result.Score < minScoreForFullTLSWeight || isCDNOrTrustedInfra) {
		strong := tlsScore - signals.TLS.AdvisoryScore
		if strong < 0 {
			strong = 0
		}
		if tlsScore > strong+maxTLSAdvisoryPromotion {
			tlsScore = strong + maxTLSAdvisoryPromotion
		}
	}
	result.Score += tlsScore + signals.WHOIS.Score
	result.Reasons = append(result.Reasons, signals.TLS.Reasons...)
	result.Reasons = append(result.Reasons, signals.WHOIS.Reasons...)
	if result.Score > 100 {
		result.Score = 100
	}
	switch {
	case result.Score >= 70:
		result.Verdict = analysis.VerdictMalicious
	case result.Score >= 40:
		result.Verdict = analysis.VerdictSuspicious
	default:
		result.Verdict = analysis.VerdictSafe
	}
	result.Confidence = math.Min(1, 0.45+float64(result.Score)/120)
}

// maxTLSAdvisoryPromotion bounds how many weak-TLS points (SAN mismatch,
// fresh certificate) can add when the pre-enrichment assessment shows no
// independent suspicion (FP-guard 2026-09, M5). CDN edges serve default
// certificates for CNAME chains and rotate constantly, so mismatch/fresh
// metadata alone must never create a MALICIOUS verdict; it can only add a
// small advisory bump or promote an already-suspicious host. Strong TLS
// signals (expired, self-signed) keep full weight.
const maxTLSAdvisoryPromotion = 10

// minScoreForFullTLSWeight is the pre-enrichment score at or above which
// weak TLS metadata applies at full weight (the host is already
// SUSPICIOUS on lexical/feed merit).
const minScoreForFullTLSWeight = 40

func enrichContextTimeout(ctx context.Context, fallback time.Duration) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return fallback
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return fallback
	}
	return remaining
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// matchExactThreatFeed reports whether the exact domain itself is a live
// (unexpired) threat-feed member. Used by feedResult before the
// trusted-suffix bypass so scoped IOC evidence wins (PR-08a/H2).
func (s *Service) matchExactThreatFeed(parent context.Context, domain string) (bool, error) {
	candidates := ThreatFeedCandidates(domain)
	if len(candidates) == 0 {
		return false, nil
	}
	matched, err := s.matchAnyThreatFeedCandidate(parent, candidates[:1])
	return matched != "", err
}

// matchParentCandidate walks only the parent suffixes, skipping the exact
// domain, and returns the nearest live member ("" on miss). A parent-only
// hit is noisy evidence: under a trusted root it is bypassed by feedResult
// (PR-08a/H2). Shared-infrastructure apexes are skipped as candidates so a
// noisy apex IOC cannot block its tenants (FP-guard 2026-09, M7). The
// returned candidate feeds the shadow scope trace (PR-08b/M7).
func (s *Service) matchParentCandidate(parent context.Context, domain string) (string, error) {
	candidates := ThreatFeedCandidates(domain)
	if len(candidates) <= 1 {
		return "", nil
	}
	parents := candidates[1:]
	kept := parents[:0]
	for _, c := range parents {
		if isSharedFeedApex(c) {
			continue
		}
		kept = append(kept, c)
	}
	if len(kept) == 0 {
		return "", nil
	}
	return s.matchAnyThreatFeedCandidate(parent, kept)
}

func (s *Service) matchAnyThreatFeedCandidate(parent context.Context, candidates []string) (string, error) {
	var matched string
	currentTime := float64(time.Now().Unix())
	// Single round trip for the whole suffix walk: a 253-octet normalized
	// input fans out to at most ~127 candidates, and sequential ZSCOREs
	// would multiply Redis RTT by attacker-controlled input length
	// (PR-02/H4). Nearest-first and expiry semantics are unchanged.
	err := s.withRedis(parent, func(ctx context.Context) error {
		scores, ok, err := s.redis.ZScores(ctx, s.threatFeedKey, candidates)
		if err != nil {
			return err
		}
		for i, candidate := range candidates {
			if ok[i] && scores[i] >= currentTime {
				matched = candidate
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	return matched, nil
}

// ThreatFeedCandidates returns the exact domain followed by every parent
// suffix considered by the runtime threat-feed matcher.
//
// Unlike the whitelist and admin-override lookups, this deliberately walks all
// the way to the top-level domain. The threat feed is a list of *observed
// malicious hosts*, so blocking the namespace behind a listed host is the
// intended semantics: if "evil.example" is listed, "sub.evil.example" is
// compromised too, and a feed that lists a bare public suffix ("com") is a
// feed bug that would surface as a very broad block rather than a missed one.
//
// That is the opposite risk profile to the other two lookups, where a
// public-suffix row is an *operator* action that would silently disable
// protection (whitelist) or override the pipeline (override). Do not add a
// registrable-label floor here without re-reading those three functions.
func ThreatFeedCandidates(domain string) []string {
	parts := strings.Split(domain, ".")
	candidates := make([]string, 0, len(parts))
	for i := 0; i < len(parts); i++ {
		candidate := strings.Join(parts[i:], ".")
		if candidate != "" {
			candidates = append(candidates, candidate)
		}
	}

	return candidates
}

func (s *Service) ttlFor(verdict analysis.Verdict) time.Duration {
	switch verdict {
	case analysis.VerdictMalicious:
		return s.ttlBlocked
	case analysis.VerdictSuspicious:
		return s.ttlSuspicious
	default:
		return s.ttlAllowed
	}
}

func (s *Service) analyzeLexical(domain string) analysis.Result {
	s.analyzerMu.RLock()
	analyzer := s.analyzer
	s.analyzerMu.RUnlock()
	return analyzer.Analyze(domain)
}

// analyzeLexicalLocal scores a domain with the local-only lexical path
// (Analyzer.AnalyzeLocal): it never touches BrandStore.ListBrands, Redis,
// SQLite, HTTP, AI/OSINT or enrichment, and uses no context. Brand spoofing
// is evaluated against the built-in brand seed only, not operator-managed
// brands — an accepted PR1 limitation, surfaced in the decision's
// assessment_mode.
func (s *Service) analyzeLexicalLocal(domain string) analysis.Result {
	s.analyzerMu.RLock()
	analyzer := s.analyzer
	s.analyzerMu.RUnlock()
	return analyzer.AnalyzeLocal(domain)
}

func analysisConfigRevision(cfg config.AnalysisConfig) string {
	encoded, _ := json.Marshal(cfg.Clone())
	sum := sha256.Sum256(encoded)
	return fmt.Sprintf("%x", sum[:8])
}

func (s *Service) applyAnalysisConfigLocked(cfg config.AnalysisConfig) {
	s.analysisConfig = cfg
	s.configRevision = analysisConfigRevision(cfg)
	s.analyzer = analysis.NewAnalyzerWithBrandStore(cfg, s.brandStore)
}

func (s *Service) applyAnalysisConfig(cfg config.AnalysisConfig, source string) string {
	if s == nil {
		return ""
	}
	cfg = cfg.Clone()
	appliedAt := time.Now().UTC()

	s.analyzerMu.Lock()
	defer s.analyzerMu.Unlock()

	s.applyAnalysisConfigLocked(cfg)
	s.lastReloadSource = source
	s.lastReloadTime = appliedAt
	return s.configRevision
}

func (s *Service) currentConfigRevision() string {
	s.analyzerMu.RLock()
	defer s.analyzerMu.RUnlock()
	return s.configRevision
}

func (s *Service) currentConfigReloadState() (string, string, time.Time) {
	if s == nil {
		return "", "", time.Time{}
	}
	s.analyzerMu.RLock()
	defer s.analyzerMu.RUnlock()
	return s.configRevision, s.lastReloadSource, s.lastReloadTime
}

func (s *Service) GetAnalysisConfig() config.AnalysisConfig {
	if s == nil {
		return config.DefaultAnalysisConfig()
	}
	s.analyzerMu.RLock()
	defer s.analyzerMu.RUnlock()
	return s.analysisConfig.Clone()
}

func (s *Service) AnalysisConfigReloadStatus() AnalysisConfigReloadStatus {
	if s == nil {
		return AnalysisConfigReloadStatus{}
	}

	revision, source, reloadedAt := s.currentConfigReloadState()
	status := AnalysisConfigReloadStatus{
		Enabled:          s.configReloadOn,
		Channel:          s.configReloadChan,
		PollInterval:     configDuration(s.configReloadPoll, defaultAnalysisConfigReloadPollInterval).String(),
		NodeRole:         s.nodeRole,
		Revision:         revision,
		LastReloadSource: source,
		RedisConfigured:  s.redis != nil && s.redis.Enabled(),
		StoreConfigured:  s.store != nil && s.store.Enabled(),
		SubscriberActive: s.shouldRunConfigReloadSubscriber(),
		ReconcilerActive: s.shouldRunConfigReloadReconciler(),
	}
	if !reloadedAt.IsZero() {
		status.LastReloadAt = reloadedAt.UTC().Format(time.RFC3339Nano)
	}
	return status
}

func (s *Service) publishAnalysisConfigReloadEvent(ctx context.Context, revision string) {
	if s == nil || revision == "" {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	channel := s.configReloadChan
	if channel == "" {
		channel = defaultAnalysisConfigReloadChannel
	}
	eventSource := configReloadSourceLocalWrite
	if s.nodeRole != "" {
		eventSource = s.nodeRole
	}

	event := analysisConfigReloadEvent{
		Type:      analysisConfigReloadEventType,
		Revision:  revision,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Source:    eventSource,
	}
	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		return s.redis.PublishJSON(redisCtx, channel, event)
	})
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		logjson.Warn("analysis config reload publish failed", correlation.Fields(ctx, map[string]any{
			"service":  "risk",
			"channel":  channel,
			"revision": revision,
			"error":    err.Error(),
		}))
		return
	}
	if err == nil {
		logjson.Info("analysis config reload published", correlation.Fields(ctx, map[string]any{
			"service":      "risk",
			"channel":      channel,
			"revision":     revision,
			"event_source": eventSource,
			"node_role":    s.nodeRole,
		}))
	}
}

func (s *Service) UpdateAnalysisConfig(ctx context.Context, cfg config.AnalysisConfig) error {
	if s == nil {
		return fmt.Errorf("risk service not configured")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cfg = cfg.Clone()
	if s.store == nil || !s.store.Enabled() {
		return store.ErrDisabled
	}
	if err := s.store.SetAnalysisConfig(ctx, cfg); err != nil {
		return err
	}
	revision := s.applyAnalysisConfig(cfg, configReloadSourceLocalWrite)
	s.publishAnalysisConfigReloadEvent(ctx, revision)
	return nil
}

func (s *Service) ResetAnalysisConfig(ctx context.Context) (config.AnalysisConfig, error) {
	defaults := config.DefaultAnalysisConfig()
	if err := s.UpdateAnalysisConfig(ctx, defaults); err != nil {
		return config.AnalysisConfig{}, err
	}
	return defaults.Clone(), nil
}

func (s *Service) withRedis(parent context.Context, fn func(context.Context) error) error {
	if s == nil || s.redis == nil || !s.redis.Enabled() {
		return cache.ErrDisabled
	}

	ctx, cancel := context.WithTimeout(parent, s.redisTimeout)
	defer cancel()
	return fn(ctx)
}

func (s *Service) currentFeedRevision(ctx context.Context) (string, bool) {
	if s == nil || s.feedRevisionKey == "" {
		return "", true
	}

	var revision string
	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		value, err := s.redis.GetString(redisCtx, s.feedRevisionKey)
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return nil
			}
			return err
		}
		revision = value
		return nil
	})
	if err != nil {
		return "", false
	}
	return revision, true
}

func (s *Service) currentBrandRevision(ctx context.Context) (string, bool) {
	if s == nil {
		return "", true
	}
	var revision string
	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		value, err := s.redis.GetString(redisCtx, brandRevisionKey)
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return nil
			}
			return err
		}
		revision = value
		return nil
	})
	if err != nil {
		return "", false
	}
	return revision, true
}

func (s *Service) bumpBrandRevision(ctx context.Context) {
	if s == nil {
		return
	}
	revision := time.Now().UTC().Format(time.RFC3339Nano)
	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		return s.redis.SetString(redisCtx, brandRevisionKey, revision, 0)
	})
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		logjson.Warn("brand revision cache write failed", correlation.Fields(ctx, map[string]any{
			"service": "risk",
			"error":   err.Error(),
		}))
	}
}

// --- Local Overrides ---

// --- Telemetry ---

func (s *Service) recordTelemetry(a Analysis, client ClientInfo) {
	s.recordTelemetryWithSource(a, client, "")
}

// recordTelemetryWithSource records telemetry with an explicit source,
// overriding the Reasons-based inference. Policy paths that do not inject
// their reason into Result.Reasons (e.g. the separated adblock branch) use
// this so the telemetry source stays accurate without polluting the security
// reasons.
//
// PR1 limitation: telemetry stores the security result (verdict/score/
// reasons) and the source label only. The policy action, category and
// assessment_mode carried by PolicyDecision are not persisted yet; adding
// columns would be a schema migration, deferred to a later PR.
func (s *Service) recordTelemetryWithSource(a Analysis, client ClientInfo, source string) {
	if s.store == nil {
		return
	}
	if source == "" {
		source = inferSource(a)
	}
	policyAction, policyCategory := "", ""
	if a.Decision != nil {
		policyAction, policyCategory = a.Decision.Action, a.Decision.Category
	}
	s.store.RecordAnalysis(store.TelemetryEntry{
		Domain:         a.Domain,
		Verdict:        string(a.Verdict),
		Score:          a.Score,
		Confidence:     a.Confidence,
		Reasons:        a.Reasons,
		CacheHit:       a.CacheHit,
		Source:         source,
		PolicyAction:   policyAction,
		PolicyCategory: policyCategory,
		DecisionID:     a.DecisionID,
		Trace:          encodeTrace(a.Assessment),
		AnalyzedAt:     a.AnalyzedAt,
		ClientIP:       client.IP,
		ClientID:       client.ClientID,
	})
}

func inferSource(a Analysis) string {
	if a.CacheHit {
		return "cache"
	}
	for _, r := range a.Reasons {
		if strings.HasPrefix(r, "admin override") {
			return "override"
		}
		if r == "whitelisted" {
			return "whitelist"
		}
		if r == threatFeedReason {
			return "feed"
		}
		if r == "adblock" {
			return "adblock"
		}
	}
	return "lexical"
}

// --- Store API wrappers ---

// ListOverrides returns all local overrides, optionally filtered by action.
// ListOverrides returns the configured overrides, optionally filtered by
// action. ctx bounds the query so an operator who navigated away does not leave
// it running on the single store connection.
func (s *Service) ListOverrides(ctx context.Context, action string) ([]store.Override, error) {
	if s.store == nil {
		return nil, nil
	}
	return s.store.ListOverrides(ctx, action)
}

// UpsertOverride creates or updates a local override for a domain.
// UpsertOverride creates or updates a local override for a domain. ctx bounds
// the write; see ListOverrides.
func (s *Service) UpsertOverride(ctx context.Context, domain, action, reason string) error {
	if s.store == nil {
		return store.ErrDisabled
	}
	normalized, err := analysis.NormalizeDomain(domain)
	if err != nil {
		return fmt.Errorf("invalid domain: %w", err)
	}
	return s.store.UpsertOverride(ctx, normalized, action, reason)
}

// DeleteOverride removes a local override for a domain.
// DeleteOverride removes a local override. ctx bounds the write; see
// ListOverrides.
func (s *Service) DeleteOverride(ctx context.Context, domain string) error {
	if s.store == nil {
		return store.ErrDisabled
	}
	normalized, err := analysis.NormalizeDomain(domain)
	if err != nil {
		return fmt.Errorf("invalid domain: %w", err)
	}
	return s.store.DeleteOverride(ctx, normalized)
}

func (s *Service) ListBrands(ctx context.Context) ([]analysis.Brand, error) {
	if s == nil || s.brandStore == nil {
		return nil, fmt.Errorf("brand store not configured")
	}
	return s.brandStore.ListBrands(ctx)
}

func (s *Service) GetBrand(ctx context.Context, id int64) (analysis.Brand, error) {
	if s == nil || s.brandStore == nil {
		return analysis.Brand{}, fmt.Errorf("brand store not configured")
	}
	return s.brandStore.GetBrand(ctx, id)
}

func (s *Service) CreateBrand(ctx context.Context, brand analysis.Brand) (analysis.Brand, error) {
	if s == nil || s.brandStore == nil {
		return analysis.Brand{}, fmt.Errorf("brand store not configured")
	}
	created, err := s.brandStore.CreateBrand(ctx, brand)
	if err != nil {
		return analysis.Brand{}, err
	}
	s.bumpBrandRevision(ctx)
	return created, nil
}

func (s *Service) UpdateBrand(ctx context.Context, id int64, brand analysis.Brand) (analysis.Brand, error) {
	if s == nil || s.brandStore == nil {
		return analysis.Brand{}, fmt.Errorf("brand store not configured")
	}
	updated, err := s.brandStore.UpdateBrand(ctx, id, brand)
	if err != nil {
		return analysis.Brand{}, err
	}
	s.bumpBrandRevision(ctx)
	return updated, nil
}

func (s *Service) DeleteBrand(ctx context.Context, id int64) error {
	if s == nil || s.brandStore == nil {
		return fmt.Errorf("brand store not configured")
	}
	if err := s.brandStore.DeleteBrand(ctx, id); err != nil {
		return err
	}
	s.bumpBrandRevision(ctx)
	return nil
}

// TelemetryRecentFiltered returns recent telemetry entries constrained at the store layer.
func (s *Service) TelemetryRecentFiltered(filter store.TelemetryFilter, limit, offset int) ([]store.TelemetryEntry, error) {
	if s.store == nil {
		return nil, nil
	}
	return s.store.QueryRecentFiltered(context.Background(), filter, limit, offset)
}

// TelemetryStats returns aggregate telemetry statistics.
func (s *Service) TelemetryStats(period string) (store.Stats, error) {
	if s.store == nil {
		return store.Stats{}, nil
	}
	return s.store.QueryStats(context.Background(), period)
}

// --- Accessors for Agent Engine ---

// RawInspection holds the full DNS/TLS/WHOIS inspection data for a domain.
type RawInspection struct {
	Domain    string            `json:"domain"`
	DNS       RawDNS            `json:"dns"`
	TLS       tlsinspect.Result `json:"tls"`
	WHOIS     whois.Result      `json:"whois"`
	InspectAt string            `json:"inspect_at"`
}

// RawDNS contains the DNS resolution result for a domain.
type RawDNS struct {
	Resolved    bool     `json:"resolved"`
	Nameservers []string `json:"nameservers,omitempty"`
	Error       string   `json:"error,omitempty"`
}

// InspectRawData performs on-demand DNS, TLS, and WHOIS lookups concurrently
// and returns the full enrichment data for the given domain.
func (s *Service) InspectRawData(ctx context.Context, domain string) RawInspection {
	var (
		dnsResult   RawDNS
		tlsResult   tlsinspect.Result
		whoisResult whois.Result
		wg          sync.WaitGroup
	)

	apex := whois.RegisteredDomain(domain)
	if apex == "" {
		apex = domain
	}

	wg.Add(3)
	go func() {
		defer wg.Done()
		nsCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		records, err := net.DefaultResolver.LookupNS(nsCtx, apex)
		if err != nil {
			dnsResult = RawDNS{Resolved: false, Error: err.Error()}
			return
		}
		dnsResult.Resolved = true
		for _, ns := range records {
			dnsResult.Nameservers = append(dnsResult.Nameservers, ns.Host)
		}
	}()
	go func() {
		defer wg.Done()
		tlsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		tlsResult = tlsinspect.Inspect(tlsCtx, domain)
	}()
	go func() {
		defer wg.Done()
		whoisCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		whoisResult = whois.LookupWithCache(whoisCtx, domain, s.store, s.whoisCacheTTL)
	}()
	wg.Wait()

	return RawInspection{
		Domain:    domain,
		DNS:       dnsResult,
		TLS:       tlsResult,
		WHOIS:     whoisResult,
		InspectAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
}
