package main

import (
	"net/http"
	"os"
	"time"

	"safe-zone/internal/agent"
	apiapp "safe-zone/internal/api/app"
	apiassets "safe-zone/internal/api/assets"
	"safe-zone/internal/api/handlers"
	"safe-zone/internal/api/httputil"
	"safe-zone/internal/api/server"
	"safe-zone/internal/config"
	"safe-zone/internal/feed"
	"safe-zone/internal/logjson"
	"safe-zone/internal/observability"
	"safe-zone/internal/ratelimit"
	"safe-zone/internal/risk"
	"safe-zone/internal/serve"
)

func main() {
	addr := config.String("SAFE_ZONE_CORE_API_ADDR", ":8080")
	shutdownTimeout := config.DurationMillis("SAFE_ZONE_SHUTDOWN_TIMEOUT_MS", 10*time.Second)

	security, err := loadRuntimeSecurity()
	if err != nil {
		logjson.Error("core-api security bootstrap failed", map[string]any{
			"service": "core-api",
			"error":   err.Error(),
		})
		os.Exit(1)
	}

	feedPreset := config.String("SAFE_ZONE_AGENT_FEED_PRESET", "")
	feedSources, err := feed.ResolveSources(config.String("SAFE_ZONE_AGENT_FEED_SOURCES", ""), feedPreset)
	if err != nil {
		logjson.Error("core-api invalid threat feed configuration", map[string]any{
			"service": "core-api",
			"error":   err.Error(),
		})
		os.Exit(1)
	}
	feedKey := config.String("SAFE_ZONE_THREAT_FEED_KEY", feed.DefaultThreatFeedKey)
	feedStaleAfter := config.DurationSeconds("SAFE_ZONE_AGENT_FEED_STALE_AFTER_SECONDS", 36*time.Hour)

	riskService := risk.NewServiceFromEnvForRole("core-api")
	metrics := observability.NewRegistry()
	cfg := handlers.Config{

		DeploymentTier:      config.String("SAFE_ZONE_DEPLOYMENT_TIER", "budget-vps"),
		RateLimitingEnabled: config.Bool("SAFE_ZONE_RATELIMIT_ENABLED", true),
		SessionSecret:       security.sessionSecret,
		AdminPassword:       security.adminPassword,
		AdminAPIKey:         security.adminAPIKey,
		PublicHost:          config.String("SAFE_ZONE_PUBLIC_HOST", ""),
		FeedKey:             feedKey,
		FeedPreset:          feedPreset,
		FeedSources:         feedSources,
		FeedStaleAfter:      feedStaleAfter,
	}
	defer func() {
		if err := riskService.Close(); err != nil {
			logjson.Warn("risk service close failed", map[string]any{
				"service": "core-api",
				"error":   err.Error(),
			})
		}
	}()
	/* logCacheStatus removed */
	/* logAnalysisConfigReloadStatus removed */

	// --- Rate limiting ---
	rlEnabled := config.Bool("SAFE_ZONE_RATELIMIT_ENABLED", true)
	var tiered *ratelimit.TieredMiddleware
	if rlEnabled {
		authLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_AUTH_RPM", 8), config.Int("SAFE_ZONE_RATELIMIT_AUTH_BURST", 3))
		analyzeLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_ANALYZE_RPM", 10), config.Int("SAFE_ZONE_RATELIMIT_ANALYZE_BURST", 5))
		dashboardLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_DASHBOARD_RPM", 240), config.Int("SAFE_ZONE_RATELIMIT_DASHBOARD_BURST", 60))
		overrideLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_OVERRIDE_RPM", 20), config.Int("SAFE_ZONE_RATELIMIT_OVERRIDE_BURST", 5))
		telemetryLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_TELEMETRY_RPM", 30), config.Int("SAFE_ZONE_RATELIMIT_TELEMETRY_BURST", 10))
		defaultLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_DEFAULT_RPM", 60), config.Int("SAFE_ZONE_RATELIMIT_DEFAULT_BURST", 15))
		defer authLimiter.Close()
		defer analyzeLimiter.Close()
		defer dashboardLimiter.Close()
		defer overrideLimiter.Close()
		defer telemetryLimiter.Close()
		defer defaultLimiter.Close()
		tiered = ratelimit.NewTieredMiddleware(
			defaultLimiter,
			ratelimit.Tier{PathPrefix: "/v1/auth/login", Limiter: authLimiter},
			ratelimit.Tier{PathPrefix: "/v1/analyze", Limiter: analyzeLimiter},
			ratelimit.Tier{PathPrefix: "/assets/", Limiter: dashboardLimiter},
			ratelimit.Tier{PathPrefix: "/app", Limiter: dashboardLimiter},
			ratelimit.Tier{PathPrefix: "/dashboard", Limiter: dashboardLimiter},
			ratelimit.Tier{PathPrefix: "/v1/status", Limiter: dashboardLimiter},
			ratelimit.Tier{PathPrefix: "/v1/version", Limiter: dashboardLimiter},
			ratelimit.Tier{PathPrefix: "/v1/auth/session", Limiter: dashboardLimiter},
			ratelimit.Tier{PathPrefix: "/v1/settings/bundle", Limiter: dashboardLimiter},
			ratelimit.Tier{PathPrefix: "/v1/overrides", Limiter: overrideLimiter},
			ratelimit.Tier{PathPrefix: "/v1/brands", Limiter: overrideLimiter},
			ratelimit.Tier{PathPrefix: "/v1/telemetry", Limiter: telemetryLimiter},
		)
		logjson.Info("rate limiting enabled", map[string]any{
			"service":     "core-api",
			"analyze_rpm": config.Float64("SAFE_ZONE_RATELIMIT_ANALYZE_RPM", 10),
			"default_rpm": config.Float64("SAFE_ZONE_RATELIMIT_DEFAULT_RPM", 60),
		})
	}

	// --- Agent Engine ---
	var agentEngine *agent.Engine
	if config.Bool("SAFE_ZONE_AGENT_ENABLED", false) {
		agentEngine = agent.NewEngine()

		// Audit Task
		auditTask := agent.NewAuditTask(
			riskService.StoreDB(),
			riskService.AIClient(),
			riskService.RedisCache(),
			agent.AuditConfig{
				MinOccurrences:      config.Int("SAFE_ZONE_AGENT_AUDIT_MIN_OCCURRENCES", 3),
				MaxPerCycle:         config.Int("SAFE_ZONE_AGENT_AUDIT_MAX_PER_CYCLE", 50),
				ConfidenceThreshold: config.Float64("SAFE_ZONE_AGENT_AUDIT_CONFIDENCE_THRESHOLD", 0.7),
				EnrichTimeout:       config.DurationSeconds("SAFE_ZONE_AGENT_ENRICH_TIMEOUT_SECONDS", 5*time.Second),
			},
		)
		agentEngine.Register(
			auditTask,
			config.DurationSeconds("SAFE_ZONE_AGENT_AUDIT_INTERVAL_SECONDS", 1*time.Hour),
			config.DurationSeconds("SAFE_ZONE_AGENT_AUDIT_TIMEOUT_SECONDS", 5*time.Minute),
			true,
		)

		// Feed Sync Task
		feedSyncTask := agent.NewFeedSyncTask(
			riskService.StoreDB(),
			agent.FeedSyncConfig{
				Sources:                    feedSources,
				FileRoot:                   config.FeedFileRoot(),
				MaxBytes:                   int64(config.Int("SAFE_ZONE_FEED_MAX_BYTES", int(feed.DefaultMaxFeedBytes))),
				RedisAddr:                  config.String("SAFE_ZONE_REDIS_ADDR", ""),
				RedisPassword:              config.SecretString("SAFE_ZONE_REDIS_PASSWORD", ""),
				RedisDB:                    config.Int("SAFE_ZONE_REDIS_DB", 0),
				FeedKey:                    feedKey,
				Timeout:                    config.DurationSeconds("SAFE_ZONE_AGENT_FEED_TIMEOUT_SECONDS", 2*time.Minute),
				ParserDriftInvalidRatio:    config.Float64("SAFE_ZONE_AGENT_FEED_DRIFT_INVALID_RATIO", 0.20),
				ParserDriftMinInvalid:      config.Int("SAFE_ZONE_AGENT_FEED_DRIFT_MIN_INVALID", 25),
				CacheInvalidationMinWrites: int64(config.Int("SAFE_ZONE_AGENT_FEED_CACHE_INVALIDATION_MIN_WRITES", 1)),
			},
		)
		agentEngine.Register(
			feedSyncTask,
			config.DurationSeconds("SAFE_ZONE_AGENT_FEED_INTERVAL_SECONDS", 24*time.Hour),
			config.DurationSeconds("SAFE_ZONE_AGENT_FEED_TIMEOUT_SECONDS", 2*time.Minute),
			len(feedSources) > 0,
		)

		osintTask := agent.NewOSINTTask(
			riskService.StoreDB(),
			riskService.OSINT(),
			riskService.RedisCache(),
			agent.OSINTConfig{
				MaxPerCycle: config.Int("SAFE_ZONE_AGENT_OSINT_MAX_PER_CYCLE", 50),
				Lookback:    config.DurationSeconds("SAFE_ZONE_AGENT_OSINT_LOOKBACK_SECONDS", 24*time.Hour),
				ThreatKey:   feedKey,
			},
		)
		agentEngine.Register(
			osintTask,
			config.DurationSeconds("SAFE_ZONE_AGENT_OSINT_INTERVAL_SECONDS", 1*time.Hour),
			config.DurationSeconds("SAFE_ZONE_AGENT_OSINT_TIMEOUT_SECONDS", 2*time.Minute),
			config.Bool("SAFE_ZONE_OSINT_ENABLED", false),
		)

		// Alert Task
		alertTask := agent.NewAlertTask(
			riskService.StoreDB(),
			agent.AlertConfig{
				WebhookURL:        config.SecretString("SAFE_ZONE_AGENT_WEBHOOK_URL", ""),
				MinEvents:         config.Int("SAFE_ZONE_AGENT_ALERT_MIN_EVENTS", 1),
				Timeout:           config.DurationSeconds("SAFE_ZONE_AGENT_ALERT_TIMEOUT_SECONDS", 30*time.Second),
				TelegramEnabled:   config.Bool("SAFE_ZONE_ALERT_TELEGRAM_ENABLED", false),
				TelegramToken:     config.SecretString("SAFE_ZONE_ALERT_TELEGRAM_TOKEN", ""),
				TelegramChatID:    config.String("SAFE_ZONE_ALERT_TELEGRAM_CHAT_ID", ""),
				SlackEnabled:      config.Bool("SAFE_ZONE_ALERT_SLACK_ENABLED", false),
				SlackWebhookURL:   config.SecretString("SAFE_ZONE_ALERT_SLACK_WEBHOOK_URL", ""),
				EmailEnabled:      config.Bool("SAFE_ZONE_ALERT_EMAIL_ENABLED", false),
				EmailSMTPHost:     config.String("SAFE_ZONE_ALERT_EMAIL_SMTP_HOST", ""),
				EmailSMTPPort:     config.Int("SAFE_ZONE_ALERT_EMAIL_SMTP_PORT", 0),
				EmailSMTPUsername: config.String("SAFE_ZONE_ALERT_EMAIL_USERNAME", ""),
				EmailFrom:         config.String("SAFE_ZONE_ALERT_EMAIL_FROM", ""),
				EmailPassword:     config.SecretString("SAFE_ZONE_ALERT_EMAIL_PASSWORD", ""),
				EmailTo:           config.String("SAFE_ZONE_ALERT_EMAIL_TO", ""),
			},
		)
		webhookURL := config.SecretString("SAFE_ZONE_AGENT_WEBHOOK_URL", "")
		alertEnabled := webhookURL != "" ||
			config.Bool("SAFE_ZONE_ALERT_TELEGRAM_ENABLED", false) ||
			config.Bool("SAFE_ZONE_ALERT_SLACK_ENABLED", false) ||
			config.Bool("SAFE_ZONE_ALERT_EMAIL_ENABLED", false)

		agentEngine.Register(
			alertTask,
			config.DurationSeconds("SAFE_ZONE_AGENT_ALERT_INTERVAL_SECONDS", 15*time.Minute),
			config.DurationSeconds("SAFE_ZONE_AGENT_ALERT_TIMEOUT_SECONDS", 30*time.Second),
			alertEnabled,
		)

		// Whitelist Update Task
		whitelistUpdateTask := agent.NewWhitelistUpdateTask(
			riskService.StoreDB(),
			riskService.Whitelist(),
			agent.WhitelistUpdateConfig{
				SourceURL: config.String("SAFE_ZONE_AGENT_WHITELIST_SOURCE_URL", "https://tranco-list.eu/download/L/1000000"),
				Timeout:   config.DurationSeconds("SAFE_ZONE_AGENT_WHITELIST_TIMEOUT_SECONDS", 10*time.Minute),
				Enabled:   config.Bool("SAFE_ZONE_AGENT_WHITELIST_ENABLED", true),
			},
		)
		agentEngine.Register(
			whitelistUpdateTask,
			config.DurationSeconds("SAFE_ZONE_AGENT_WHITELIST_INTERVAL_SECONDS", 7*24*time.Hour),
			config.DurationSeconds("SAFE_ZONE_AGENT_WHITELIST_TIMEOUT_SECONDS", 10*time.Minute),
			config.Bool("SAFE_ZONE_AGENT_WHITELIST_ENABLED", true),
		)

		agentEngine.Start()
		defer agentEngine.Stop()
		logjson.Info("agent engine enabled", map[string]any{"service": "core-api"})
	}

	h := handlers.New(riskService, metrics, cfg)
	mux := server.NewRouter(h, agentEngine, apiassets.FS, apiapp.StaticFS)

	var handler http.Handler = mux
	if tiered != nil {
		handler = tiered.Wrap(mux)
	}

	recoveryHandler := serve.Recovery(handler, metrics)
	securityHeadersHandler := serve.SecurityHeaders(recoveryHandler)
	requestIDHandler := serve.WithRequestID(httputil.LogRequests("core-api", metrics)(securityHeadersHandler))

	srv := &http.Server{
		Addr:              addr,
		Handler:           requestIDHandler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	logjson.Info("service listening", map[string]any{
		"service": "core-api",
		"addr":    addr,
	})
	if err := serve.RunHTTPServer(srv, shutdownTimeout); err != nil {
		logjson.Error("core-api server stopped with error", map[string]any{
			"service": "core-api",
			"error":   err.Error(),
		})
		os.Exit(1)
	}
}
