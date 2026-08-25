package risk

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"safe-zone/internal/ai"
	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/config"
	"safe-zone/internal/logjson"
	"safe-zone/internal/osint"
	"safe-zone/internal/store"
)

func NewServiceFromEnv() *Service {
	return NewServiceFromEnvForRole("")
}

func NewServiceFromEnvForRole(nodeRole string) *Service {
	service, err := NewServiceFromEnvForRoleE(nodeRole)
	if err != nil {
		// The existing constructor has no error return and is used directly by
		// both service binaries. A required/enforce bundle failure must still
		// fail startup instead of silently serving without ML.
		panic(err)
	}
	return service
}

// NewServiceFromEnvForRoleE is the error-returning constructor used by tests
// and by callers that want explicit startup error handling.
func NewServiceFromEnvForRoleE(nodeRole string) (*Service, error) {
	readSecret := func(key string) string {
		value, err := config.SecretStringE(key)
		if err != nil {
			logjson.Warn("secret load failed; using fallback behavior", map[string]any{
				"service": "risk",
				"key":     key,
				"error":   err.Error(),
			})
			return ""
		}
		return value
	}
	whoisCacheDays := config.Int("SAFE_ZONE_WHOIS_CACHE_TTL_DAYS", 7)
	if whoisCacheDays < 1 || whoisCacheDays > 365 {
		logjson.Warn("invalid WHOIS cache TTL; using 7 days", map[string]any{
			"service": "risk",
			"value":   whoisCacheDays,
		})
		whoisCacheDays = 7
	}

	redisCache := cache.NewRedis(
		config.String("SAFE_ZONE_REDIS_ADDR", ""),
		readSecret("SAFE_ZONE_REDIS_PASSWORD"),
		config.Int("SAFE_ZONE_REDIS_DB", 0),
	)

	sqlitePath := config.String("SAFE_ZONE_SQLITE_PATH", "./data/safe-zone.db")
	retentionDays := config.Int("SAFE_ZONE_TELEMETRY_RETENTION_DAYS", 30)
	storeDB, err := store.New(sqlitePath, retentionDays)
	if err != nil {
		logjson.Warn("sqlite store initialization failed; continuing without persistence", map[string]any{
			"service": "risk",
			"path":    sqlitePath,
			"error":   err.Error(),
		})
	}

	aiClient := ai.NewClient(ai.Config{
		Provider:      config.String("SAFE_ZONE_AI_PROVIDER", "gemini"),
		GeminiBaseURL: config.String("SAFE_ZONE_GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta"),
		GeminiAPIKey:  readSecret("SAFE_ZONE_GEMINI_API_KEY"),
		GeminiModel:   config.String("SAFE_ZONE_GEMINI_MODEL", "gemini-2.5-flash-lite"),
		GeminiTimeout: config.DurationMillis("SAFE_ZONE_GEMINI_TIMEOUT_MS", 3*time.Second),
		OllamaBaseURL: config.String("SAFE_ZONE_OLLAMA_BASE_URL", "http://localhost:11434"),
		OllamaModel:   config.String("SAFE_ZONE_OLLAMA_MODEL", "gemma2:2b"),
		OllamaTimeout: config.DurationMillis("SAFE_ZONE_OLLAMA_TIMEOUT_MS", 5000*time.Millisecond),
	})

	osintService := osint.NewService(osint.Options{
		Enabled:        config.Bool("SAFE_ZONE_OSINT_ENABLED", false),
		Mode:           config.String("SAFE_ZONE_OSINT_MODE", "background_on_demand"),
		Timeout:        config.DurationMillis("SAFE_ZONE_OSINT_TIMEOUT_MS", 2*time.Second),
		CacheTTL:       config.DurationSeconds("SAFE_ZONE_OSINT_CACHE_TTL_SECONDS", 6*time.Hour),
		TrustedDomains: osint.SplitList(config.String("SAFE_ZONE_OSINT_TRUSTED_DOMAINS", "")),
		Sources:        osint.SplitList(config.String("SAFE_ZONE_OSINT_SOURCES", "")),
		Redis:          redisCache,
		RedisTimeout:   config.DurationMillis("SAFE_ZONE_REDIS_TIMEOUT_MS", 250*time.Millisecond),
		RoleClassifier: aiClient,
	})

	mlMode, mlClassifier, err := loadMLFromEnv()
	if err != nil {
		return nil, err
	}
	mlCanary, err := loadMLCanaryFromEnv(mlMode)
	if err != nil {
		return nil, err
	}
	urlMLMode, urlMLClassifier, err := loadURLMLFromEnv()
	if err != nil {
		return nil, err
	}

	return NewService(Options{
		Redis:                    redisCache,
		RedisTimeout:             config.DurationMillis("SAFE_ZONE_REDIS_TIMEOUT_MS", 250*time.Millisecond),
		TTLAllowed:               config.DurationSeconds("SAFE_ZONE_CACHE_TTL_ALLOWED_SECONDS", 3*time.Hour),
		TTLSuspicious:            config.DurationSeconds("SAFE_ZONE_CACHE_TTL_SUSPICIOUS_SECONDS", time.Hour),
		TTLBlocked:               config.DurationSeconds("SAFE_ZONE_CACHE_TTL_BLOCKED_SECONDS", 6*time.Hour),
		RecentLimit:              int64(config.Int("SAFE_ZONE_DASHBOARD_RECENT_LIMIT", 25)),
		RecentTTL:                config.DurationSeconds("SAFE_ZONE_RECENT_ANALYSIS_TTL_SECONDS", 24*time.Hour),
		ThreatFeedKey:            config.String("SAFE_ZONE_THREAT_FEED_KEY", defaultThreatFeedKey),
		AIClient:                 aiClient,
		AIProvider:               config.String("SAFE_ZONE_AI_PROVIDER", "gemini"),
		GeminiBaseURL:            config.String("SAFE_ZONE_GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta"),
		GeminiAPIKey:             readSecret("SAFE_ZONE_GEMINI_API_KEY"),
		GeminiModel:              config.String("SAFE_ZONE_GEMINI_MODEL", "gemini-2.5-flash-lite"),
		GeminiTimeout:            config.DurationMillis("SAFE_ZONE_GEMINI_TIMEOUT_MS", 3*time.Second),
		OllamaBaseURL:            config.String("SAFE_ZONE_OLLAMA_BASE_URL", "http://localhost:11434"),
		OllamaModel:              config.String("SAFE_ZONE_OLLAMA_MODEL", "gemma2:2b"),
		OllamaTimeout:            config.DurationMillis("SAFE_ZONE_OLLAMA_TIMEOUT_MS", 5000*time.Millisecond),
		WhitelistPath:            config.String("SAFE_ZONE_WHITELIST_PATH", "./data/whitelist.txt"),
		AdblockFileRoot:          config.FeedFileRoot(),
		AnalysisConfig:           config.LoadAnalysisConfig(config.String("SAFE_ZONE_ANALYSIS_CONFIG_PATH", "")),
		Store:                    storeDB,
		BrandCacheTTL:            config.DurationSeconds("SAFE_ZONE_BRAND_CACHE_TTL_SECONDS", 5*time.Minute),
		ConfigReloadChannel:      config.String("SAFE_ZONE_CONFIG_RELOAD_CHANNEL", defaultAnalysisConfigReloadChannel),
		ConfigReloadPollInterval: config.DurationSeconds("SAFE_ZONE_CONFIG_RELOAD_POLL_SECONDS", defaultAnalysisConfigReloadPollInterval),
		ConfigReloadEnabled:      config.Bool("SAFE_ZONE_CONFIG_RELOAD_ENABLED", true),
		NodeRole:                 strings.TrimSpace(nodeRole),
		EnrichEnabled:            config.Bool("SAFE_ZONE_ENRICH_ENABLED", true),
		EnrichTimeout:            config.DurationMillis("SAFE_ZONE_ENRICH_TIMEOUT_MS", 3*time.Second),
		EnrichQueueSize:          config.Int("SAFE_ZONE_ENRICH_QUEUE_SIZE", 256),
		EnrichWorkers:            config.Int("SAFE_ZONE_ENRICH_WORKERS", 2),
		WhoisCacheTTL:            time.Duration(whoisCacheDays) * 24 * time.Hour,
		OSINT:                    osintService,
		MLClassifier:             mlClassifier,
		MLMode:                   mlMode,
		MLCanary:                 mlCanary,
		URLMLClassifier:          urlMLClassifier,
		URLMLMode:                urlMLMode,
	}), nil
}

func loadURLMLFromEnv() (analysis.MLMode, analysis.URLClassifier, error) {
	rawMode := strings.ToLower(strings.TrimSpace(config.String("SAFE_ZONE_URL_ML_MODE", string(analysis.MLModeDisabled))))
	mode := analysis.MLMode(rawMode)
	if mode != analysis.MLModeDisabled && mode != analysis.MLModeShadow {
		return analysis.MLModeDisabled, nil, fmt.Errorf("invalid SAFE_ZONE_URL_ML_MODE %q: only disabled or shadow are supported", rawMode)
	}
	if mode == analysis.MLModeDisabled {
		return mode, nil, nil
	}
	bundleDir := strings.TrimSpace(config.String("SAFE_ZONE_URL_ML_BUNDLE_DIR", ""))
	required := config.Bool("SAFE_ZONE_URL_ML_REQUIRED", false)
	if bundleDir == "" {
		if required {
			return analysis.MLModeDisabled, nil, errors.New("URL ML bundle is required for shadow mode")
		}
		logjson.Warn("URL ML bundle not configured; requested shadow mode is unavailable", map[string]any{"service": "risk"})
		return mode, nil, nil
	}
	classifier, err := analysis.NewURLBundleClassifier(bundleDir)
	if err != nil {
		if required {
			return analysis.MLModeDisabled, nil, fmt.Errorf("URL ML bundle load failed: %w", err)
		}
		logjson.Warn("URL ML bundle load failed; requested shadow mode is unavailable", map[string]any{
			"service":     "risk",
			"error_class": "bundle_load",
		})
		return mode, nil, nil
	}
	logjson.Info("URL ML classifier loaded", map[string]any{
		"service":              "risk",
		"url_ml_mode":          mode,
		"url_ml_model_version": classifier.ModelVersion(),
		"url_ml_revision":      classifier.Revision(),
	})
	return mode, classifier, nil
}

func loadMLCanaryFromEnv(mode analysis.MLMode) (MLCanaryConfig, error) {
	if mode == analysis.MLModeDisabled {
		return MLCanaryConfig{}, nil
	}
	rawPercent := strings.TrimSpace(config.String("SAFE_ZONE_ML_CANARY_PERCENT", "0"))
	percent, err := strconv.Atoi(rawPercent)
	if err != nil {
		return MLCanaryConfig{}, fmt.Errorf("invalid SAFE_ZONE_ML_CANARY_PERCENT %q", rawPercent)
	}
	canary := MLCanaryConfig{
		Percent: percent,
		Seed:    strings.TrimSpace(config.String("SAFE_ZONE_ML_CANARY_SEED", "")),
	}
	if err := canary.validate(); err != nil {
		return MLCanaryConfig{}, fmt.Errorf("invalid ML canary configuration: %w", err)
	}
	if mode == analysis.MLModeEnforce && !canary.enabled() {
		return MLCanaryConfig{}, fmt.Errorf("SAFE_ZONE_ML_MODE=enforce requires a bounded ML canary percent and seed")
	}
	return canary, nil
}

func loadMLFromEnv() (analysis.MLMode, analysis.DomainClassifier, error) {
	rawMode := strings.ToLower(strings.TrimSpace(config.String("SAFE_ZONE_ML_MODE", string(analysis.MLModeDisabled))))
	mode := analysis.MLMode(rawMode)
	if mode != analysis.MLModeDisabled && mode != analysis.MLModeShadow && mode != analysis.MLModeEnforce {
		return analysis.MLModeDisabled, nil, fmt.Errorf("invalid SAFE_ZONE_ML_MODE %q", rawMode)
	}
	if mode == analysis.MLModeDisabled {
		return mode, nil, nil
	}

	bundleDir := strings.TrimSpace(config.String("SAFE_ZONE_ML_BUNDLE_DIR", ""))
	required := config.Bool("SAFE_ZONE_ML_REQUIRED", false)
	var thresholdOverride *float64
	if rawThreshold, ok := os.LookupEnv("SAFE_ZONE_ML_BLOCK_THRESHOLD"); ok && strings.TrimSpace(rawThreshold) != "" {
		value, err := strconv.ParseFloat(strings.TrimSpace(rawThreshold), 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 || value >= 1 {
			return analysis.MLModeDisabled, nil, fmt.Errorf("invalid SAFE_ZONE_ML_BLOCK_THRESHOLD")
		}
		thresholdOverride = &value
	}
	if bundleDir == "" {
		if required || mode == analysis.MLModeEnforce {
			return analysis.MLModeDisabled, nil, fmt.Errorf("ML bundle is required for mode %s", mode)
		}
		logjson.Warn("ML bundle not configured; requested ML mode is unavailable", map[string]any{"service": "risk", "mode": mode})
		return mode, nil, nil
	}

	classifier, err := analysis.NewBundleClassifierWithThreshold(bundleDir, thresholdOverride)
	if err != nil {
		if required || mode == analysis.MLModeEnforce {
			return analysis.MLModeDisabled, nil, fmt.Errorf("ML bundle load failed: %w", err)
		}
		logjson.Warn("ML bundle load failed; requested ML mode is unavailable", map[string]any{
			"service":     "risk",
			"mode":        mode,
			"error_class": "bundle_load",
		})
		return mode, nil, nil
	}
	logjson.Info("ML classifier loaded", map[string]any{
		"service":          "risk",
		"ml_mode":          mode,
		"ml_model_version": classifier.ModelVersion(),
		"ml_revision":      classifier.Revision(),
	})
	return mode, classifier, nil
}
