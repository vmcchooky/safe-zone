package risk

import (
	"time"

	"safe-zone/internal/ai"
	"safe-zone/internal/cache"
	"safe-zone/internal/config"
	"safe-zone/internal/logjson"
	"safe-zone/internal/osint"
	"safe-zone/internal/store"
)

func NewServiceFromEnv() *Service {
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

	return NewService(Options{
		Redis:           redisCache,
		RedisTimeout:    config.DurationMillis("SAFE_ZONE_REDIS_TIMEOUT_MS", 250*time.Millisecond),
		TTLAllowed:      config.DurationSeconds("SAFE_ZONE_CACHE_TTL_ALLOWED_SECONDS", 3*time.Hour),
		TTLSuspicious:   config.DurationSeconds("SAFE_ZONE_CACHE_TTL_SUSPICIOUS_SECONDS", time.Hour),
		TTLBlocked:      config.DurationSeconds("SAFE_ZONE_CACHE_TTL_BLOCKED_SECONDS", 6*time.Hour),
		RecentLimit:     int64(config.Int("SAFE_ZONE_DASHBOARD_RECENT_LIMIT", 25)),
		RecentTTL:       config.DurationSeconds("SAFE_ZONE_RECENT_ANALYSIS_TTL_SECONDS", 24*time.Hour),
		ThreatFeedKey:   config.String("SAFE_ZONE_THREAT_FEED_KEY", defaultThreatFeedKey),
		AIClient:        aiClient,
		AIProvider:      config.String("SAFE_ZONE_AI_PROVIDER", "gemini"),
		GeminiBaseURL:   config.String("SAFE_ZONE_GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta"),
		GeminiAPIKey:    readSecret("SAFE_ZONE_GEMINI_API_KEY"),
		GeminiModel:     config.String("SAFE_ZONE_GEMINI_MODEL", "gemini-2.5-flash-lite"),
		GeminiTimeout:   config.DurationMillis("SAFE_ZONE_GEMINI_TIMEOUT_MS", 3*time.Second),
		OllamaBaseURL:   config.String("SAFE_ZONE_OLLAMA_BASE_URL", "http://localhost:11434"),
		OllamaModel:     config.String("SAFE_ZONE_OLLAMA_MODEL", "gemma2:2b"),
		OllamaTimeout:   config.DurationMillis("SAFE_ZONE_OLLAMA_TIMEOUT_MS", 5000*time.Millisecond),
		WhitelistPath:   config.String("SAFE_ZONE_WHITELIST_PATH", "./data/whitelist.txt"),
		AnalysisConfig:  config.LoadAnalysisConfig(config.String("SAFE_ZONE_ANALYSIS_CONFIG_PATH", "")),
		Store:           storeDB,
		BrandCacheTTL:   config.DurationSeconds("SAFE_ZONE_BRAND_CACHE_TTL_SECONDS", 5*time.Minute),
		EnrichEnabled:   config.Bool("SAFE_ZONE_ENRICH_ENABLED", true),
		EnrichTimeout:   config.DurationMillis("SAFE_ZONE_ENRICH_TIMEOUT_MS", 3*time.Second),
		EnrichQueueSize: config.Int("SAFE_ZONE_ENRICH_QUEUE_SIZE", 256),
		EnrichWorkers:   config.Int("SAFE_ZONE_ENRICH_WORKERS", 2),
		OSINT:           osintService,
	})
}
