package risk

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"safe-zone/internal/ai"
	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/config"
	"safe-zone/internal/domaintrie"
	"safe-zone/internal/feed"
	"safe-zone/internal/logjson"
	"safe-zone/internal/osint"
	"safe-zone/internal/store"
	"safe-zone/internal/tlsinspect"
	"safe-zone/internal/whois"
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

const negativeCacheTTL = 2 * time.Minute
