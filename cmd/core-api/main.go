package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"safe-zone/internal/agent"
	"safe-zone/internal/analysis"
	"safe-zone/internal/auth"
	"safe-zone/internal/buildinfo"
	"safe-zone/internal/config"
	"safe-zone/internal/feed"
	"safe-zone/internal/logjson"
	"safe-zone/internal/observability"
	"safe-zone/internal/ratelimit"
	"safe-zone/internal/risk"
	"safe-zone/internal/serve"
	"safe-zone/internal/store"
)

type analyzeRequest struct {
	Domain string `json:"domain"`
}

type RateLimitingStatus struct {
	Enabled bool `json:"enabled"`
}

type statusResponse struct {
	Service        string              `json:"service"`
	Status         string              `json:"status"`
	Mode           string              `json:"mode,omitempty"`
	DeploymentTier string              `json:"deployment_tier,omitempty"`
	Redis          *risk.CacheStatus   `json:"redis,omitempty"`
	FeedSync       *feed.StatusSummary `json:"feed_sync,omitempty"`
	Endpoints      []string            `json:"endpoints,omitempty"`
	RateLimiting   *RateLimitingStatus `json:"rate_limiting,omitempty"`
	Time           string              `json:"time"`
}

type app struct {
	risk           *risk.Service
	metrics        *observability.Registry
	deploymentTier string
	sessionSecret  []byte
	adminPassword  string
	adminAPIKey    string
	publicHost     string
	feedKey        string
	feedPreset     string
	feedSources    []string
	feedStaleAfter time.Duration
	rateLimiter    *ratelimit.TieredMiddleware
}

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

	api := &app{
		risk:           risk.NewServiceFromEnv(),
		metrics:        observability.NewRegistry(),
		deploymentTier: config.String("SAFE_ZONE_DEPLOYMENT_TIER", "budget-vps"),
		sessionSecret:  security.sessionSecret,
		adminPassword:  security.adminPassword,
		adminAPIKey:    security.adminAPIKey,
		publicHost:     config.String("SAFE_ZONE_PUBLIC_HOST", ""),
		feedKey:        feedKey,
		feedPreset:     feedPreset,
		feedSources:    feedSources,
		feedStaleAfter: feedStaleAfter,
	}
	defer func() {
		if err := api.risk.Close(); err != nil {
			logjson.Warn("risk service close failed", map[string]any{
				"service": "core-api",
				"error":   err.Error(),
			})
		}
	}()
	logCacheStatus("core-api", api.risk)

	// --- Rate limiting ---
	rlEnabled := config.Bool("SAFE_ZONE_RATELIMIT_ENABLED", true)
	var tiered *ratelimit.TieredMiddleware
	if rlEnabled {
		analyzeLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_ANALYZE_RPM", 10), config.Int("SAFE_ZONE_RATELIMIT_ANALYZE_BURST", 5))
		overrideLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_OVERRIDE_RPM", 20), config.Int("SAFE_ZONE_RATELIMIT_OVERRIDE_BURST", 5))
		telemetryLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_TELEMETRY_RPM", 30), config.Int("SAFE_ZONE_RATELIMIT_TELEMETRY_BURST", 10))
		defaultLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_DEFAULT_RPM", 60), config.Int("SAFE_ZONE_RATELIMIT_DEFAULT_BURST", 15))
		defer analyzeLimiter.Close()
		defer overrideLimiter.Close()
		defer telemetryLimiter.Close()
		defer defaultLimiter.Close()
		tiered = ratelimit.NewTieredMiddleware(
			defaultLimiter,
			ratelimit.Tier{PathPrefix: "/v1/analyze", Limiter: analyzeLimiter},
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
	api.rateLimiter = tiered

	// --- Agent Engine ---
	var agentEngine *agent.Engine
	if config.Bool("SAFE_ZONE_AGENT_ENABLED", false) {
		agentEngine = agent.NewEngine()

		// Audit Task
		auditTask := agent.NewAuditTask(
			api.risk.StoreDB(),
			api.risk.AIClient(),
			api.risk.RedisCache(),
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
			api.risk.StoreDB(),
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
			api.risk.StoreDB(),
			api.risk.OSINT(),
			api.risk.RedisCache(),
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
			api.risk.StoreDB(),
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
			api.risk.StoreDB(),
			api.risk.Whitelist(),
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

	mux := http.NewServeMux()
	mux.HandleFunc("/", api.statusHandler)
	mux.HandleFunc("/healthz", healthHandler("core-api"))
	mux.HandleFunc("/readyz", healthHandler("core-api"))
	mux.HandleFunc("/block", api.blockPageHandler)
	mux.HandleFunc("/block/report", api.blockReportHandler)
	mux.HandleFunc("/v1/version", api.versionHandler)
	mux.HandleFunc("/metrics", api.metricsHandler)
	mux.HandleFunc("/v1/analyze", api.analyzeHandler)
	mux.HandleFunc("/v1/osint/evidence", api.requireAuthFunc(api.osintEvidenceHandler))
	mux.HandleFunc("/v1/analysis/recent", api.recentAnalysisHandler)
	mux.HandleFunc("/v1/auth/login", api.authLoginHandler)
	mux.HandleFunc("/v1/auth/logout", api.authLogoutHandler)
	mux.HandleFunc("/v1/overrides", api.requireAuthFunc(api.overridesHandler))
	mux.HandleFunc("/v1/overrides/review-false-positive", api.requireAuthFunc(api.reviewFalsePositiveHandler))
	mux.HandleFunc("/v1/reports", api.requireAuthFunc(api.listReportsHandler))
	mux.HandleFunc("/v1/reports/status", api.requireAuthFunc(api.updateReportStatusHandler))
	mux.HandleFunc("/v1/brands", api.requireAuthFunc(serve.BrandHandler(api.risk)))
	mux.HandleFunc("/v1/telemetry/recent", api.requireAuthFunc(api.telemetryRecentHandler))
	mux.HandleFunc("/v1/telemetry/stats", api.requireAuthFunc(api.telemetryStatsHandler))
	mux.HandleFunc("/v1/agent/status", api.requireAuthFunc(api.agentStatusHandler(agentEngine)))
	mux.HandleFunc("/v1/agent/trigger", api.requireAuthFunc(agentTriggerHandler(agentEngine)))
	mux.HandleFunc("/v1/groups", api.requireAuthFunc(api.groupsHandler))
	mux.HandleFunc("/v1/mappings", api.requireAuthFunc(api.mappingsHandler))
	mux.HandleFunc("/v1/group-overrides", api.requireAuthFunc(api.groupOverridesHandler))
	mux.HandleFunc("/v1/settings", api.requireAuthFunc(api.settingsHandler))
	mux.HandleFunc("/v1/settings/test-ai", api.requireAuthFunc(api.testAIHandler))
	mux.HandleFunc("/v1/settings/test-alert", api.requireAuthFunc(api.testAlertHandler))
	mux.HandleFunc("/v1/config/analysis", api.requireAuthFunc(api.analysisConfigHandler))
	mux.HandleFunc("/v1/config/analysis/reset", api.requireAuthFunc(api.analysisConfigResetHandler))
	mux.Handle("/assets/", http.FileServer(http.FS(assetsFS)))
	mux.HandleFunc("/dashboard", api.dashboardHandler)
	mux.HandleFunc("/dashboard/", api.dashboardHandler)

	var handler http.Handler = mux
	if tiered != nil {
		handler = tiered.Wrap(mux)
	}

	recoveryHandler := serve.Recovery(handler, api.metrics)
	requestIDHandler := serve.WithRequestID(logRequests("core-api", recoveryHandler, api.metrics))

	server := &http.Server{
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
	if err := serve.RunHTTPServer(server, shutdownTimeout); err != nil {
		logjson.Error("core-api server stopped with error", map[string]any{
			"service": "core-api",
			"error":   err.Error(),
		})
		os.Exit(1)
	}
}

func healthHandler(service string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, statusResponse{
			Service: service,
			Status:  "ok",
			Time:    time.Now().UTC().Format(time.RFC3339Nano),
		})
	}
}

func (a *app) statusHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	cacheStatus := a.risk.CacheStatus(r.Context())
	feedStatus := a.feedStatus(r.Context())
	writeJSON(w, http.StatusOK, statusResponse{
		Service:        "core-api",
		Status:         "ok",
		Mode:           "api",
		DeploymentTier: a.deploymentTier,
		Redis:          &cacheStatus,
		FeedSync:       &feedStatus,
		Endpoints: []string{
			"/",
			"/healthz",
			"/readyz",
			"/block",
			"/v1/version",
			"/v1/analyze?domain=example.com",
			"/v1/osint/evidence?domain=example.com",
			"/v1/analysis/recent",
			"/v1/overrides",
			"/v1/overrides/review-false-positive",
			"/v1/brands",
			"/v1/telemetry/recent",
			"/v1/telemetry/stats",
			"/v1/agent/status",
			"/v1/agent/trigger?task=<name>",
			"/dashboard",
		},
		RateLimiting: &RateLimitingStatus{
			Enabled: a.rateLimiter != nil,
		},
		Time: time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (a *app) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"service":   "core-api",
		"status":    "ok",
		"metrics":   a.metrics.Snapshot(),
		"feed_sync": a.feedStatus(r.Context()),
		"time":      time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (a *app) versionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	writeJSON(w, http.StatusOK, buildinfo.Snapshot("core-api", a.deploymentTier))
}

func (a *app) analyzeHandler(w http.ResponseWriter, r *http.Request) {
	var domain string

	switch r.Method {
	case http.MethodGet:
		domain = r.URL.Query().Get("domain")
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		defer r.Body.Close()
		var req analyzeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		domain = req.Domain
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	clientInfo := extractClientInfo(r)
	response := a.risk.AnalyzeWithOptions(r.Context(), domain, clientInfo, risk.AnalyzeOptions{
		IncludeEvidence: r.URL.Query().Get("include_evidence") == "1",
		ForceOSINT:      r.URL.Query().Get("force_osint") == "1",
	})
	a.risk.RecordRecent(r.Context(), response)
	writeJSON(w, http.StatusOK, response)
}

func (a *app) osintEvidenceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain query parameter is required")
		return
	}
	force := r.URL.Query().Get("refresh") == "1" || r.URL.Query().Get("force") == "1"
	report, err := a.risk.OSINTEvidence(r.Context(), domain, force)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (a *app) recentAnalysisHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items": a.risk.Recent(r.Context()),
	})
}

func logCacheStatus(service string, riskService *risk.Service) {
	status := riskService.CacheStatus(context.Background())
	if !status.Configured {
		return
	}
	if status.Status == "ok" {
		logjson.Info("redis cache connected", map[string]any{"service": service})
		return
	}
	logjson.Warn("redis cache unavailable at startup", map[string]any{
		"service": service,
		"error":   status.Error,
	})
}

func (a *app) feedStatus(ctx context.Context) feed.StatusSummary {
	return feed.ReadStatusSummary(ctx, a.risk.RedisCache(), a.feedKey, a.feedPreset, a.feedSources, a.feedStaleAfter)
}

func logRequests(service string, next http.Handler, metrics *observability.Registry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panicObserved := false
		ctx := context.WithValue(r.Context(), serve.ObservedPanicKey, &panicObserved)
		r = r.WithContext(ctx)
		started := time.Now()
		recorder := &statusLoggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(recorder, r)
		if metrics != nil {
			if p, ok := r.Context().Value(serve.ObservedPanicKey).(*bool); !ok || !*p {
				metrics.Observe(r.Method, r.URL.Path, recorder.statusCode, recorder.bytesWritten, time.Since(started))
			}
		}
		clientInfo := extractClientInfo(r)
		logjson.Info("http request", map[string]any{
			"service":     service,
			"request_id":  serve.RequestID(r.Context()),
			"method":      sanitizeLog(r.Method),
			"path":        sanitizeLog(r.URL.Path),
			"status":      recorder.statusCode,
			"bytes":       recorder.bytesWritten,
			"duration_ms": time.Since(started).Milliseconds(),
			"client_ip":   clientInfo.IP,
			"client_id":   clientInfo.ClientID,
		})
	})
}

type statusLoggingResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (w *statusLoggingResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *statusLoggingResponseWriter) Write(p []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytesWritten += n
	return n, err
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		logjson.Error("write response failed", map[string]any{
			"service": "core-api",
			"error":   err.Error(),
		})
	}
}

func writeError(w http.ResponseWriter, statusCode int, message string) {
	writeJSON(w, statusCode, map[string]string{"error": message})
}

func sanitizeLog(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// --- Overrides API ---

type overrideRequest struct {
	Domain string `json:"domain"`
	Action string `json:"action"`
	Reason string `json:"reason"`
}

type falsePositiveReviewRequest struct {
	Domain         string `json:"domain"`
	Reason         string `json:"reason"`
	Source         string `json:"source,omitempty"`
	PreviousAction string `json:"previous_action,omitempty"`
}

type updateReportStatusRequest struct {
	ID     int64  `json:"id"`
	Status string `json:"status"`
}

func (a *app) overridesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		action := r.URL.Query().Get("action")
		overrides, err := a.risk.ListOverrides(action)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if overrides == nil {
			overrides = []store.Override{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": overrides})

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 10240)
		defer r.Body.Close()
		var req overrideRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.Domain == "" || req.Action == "" {
			writeError(w, http.StatusBadRequest, "domain and action are required")
			return
		}
		if err := a.risk.UpsertOverride(req.Domain, req.Action, req.Reason); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "domain": req.Domain, "action": req.Action})

	case http.MethodDelete:
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			writeError(w, http.StatusBadRequest, "domain query parameter is required")
			return
		}
		if err := a.risk.DeleteOverride(domain); err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "domain": domain})

	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *app) reviewFalsePositiveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 12288)
	defer r.Body.Close()

	var req falsePositiveReviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	req.Domain = strings.TrimSpace(req.Domain)
	req.Reason = strings.TrimSpace(req.Reason)
	req.Source = strings.TrimSpace(req.Source)
	req.PreviousAction = strings.TrimSpace(req.PreviousAction)

	if req.Domain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	if req.Reason == "" {
		writeError(w, http.StatusBadRequest, "review reason is required")
		return
	}
	normalized, err := analysis.NormalizeDomain(req.Domain)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain: "+err.Error())
		return
	}

	reviewReason := "false-positive review: " + req.Reason
	if req.Source != "" {
		reviewReason = fmt.Sprintf("false-positive review (%s): %s", req.Source, req.Reason)
	}

	if err := a.risk.UpsertOverride(normalized, "allow", reviewReason); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if db := a.risk.StoreDB(); db != nil {
		details := map[string]string{
			"source":          req.Source,
			"review_reason":   req.Reason,
			"previous_action": req.PreviousAction,
			"resolved_action": "allow",
		}
		if data, err := json.Marshal(details); err == nil {
			_ = db.RecordAgentEvent("operator_review", "operator_false_positive_review", normalized, string(data))
		}
		if db.Enabled() {
			_ = db.ResolveBlockReportsForDomain(normalized)
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"domain": normalized,
		"action": "allow",
		"reason": reviewReason,
	})
}

// --- Telemetry API ---

func (a *app) telemetryRecentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	limit := 50
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 100 {
		limit = 100
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	filter := store.TelemetryFilter{
		Verdict: strings.TrimSpace(r.URL.Query().Get("verdict")),
		Source:  strings.TrimSpace(r.URL.Query().Get("source")),
		Domain:  strings.TrimSpace(r.URL.Query().Get("domain")),
	}
	if period := strings.TrimSpace(r.URL.Query().Get("period")); period != "" {
		filter.Since = telemetryPeriodSince(period)
	}

	entries, err := a.risk.TelemetryRecentFiltered(filter, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []store.TelemetryEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":  entries,
		"filter": filter,
	})
}

func (a *app) listReportsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	limit := 50
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 100 {
		limit = 100
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	status := r.URL.Query().Get("status")
	query := r.URL.Query().Get("q")

	db := a.risk.StoreDB()
	if db == nil || !db.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	reports, err := db.ListBlockReportsFiltered(store.BlockReportFilter{
		Status: status,
		Query:  query,
	}, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list reports: "+err.Error())
		return
	}
	if reports == nil {
		reports = []store.BlockReport{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"reports": reports,
		"filter": map[string]string{
			"status": status,
			"q":      query,
		},
	})
}

func (a *app) updateReportStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	defer r.Body.Close()

	var req updateReportStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	req.Status = strings.TrimSpace(req.Status)
	if req.ID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid ID")
		return
	}
	if req.Status == "" {
		writeError(w, http.StatusBadRequest, "status is required")
		return
	}

	db := a.risk.StoreDB()
	if db == nil || !db.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	if err := db.UpdateBlockReportStatus(req.ID, req.Status); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update report status: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func (a *app) telemetryStatsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	period := r.URL.Query().Get("period")
	since := time.Now().Add(-24 * time.Hour) // default 24h
	switch period {
	case "7d":
		since = time.Now().Add(-7 * 24 * time.Hour)
	case "30d":
		since = time.Now().Add(-30 * 24 * time.Hour)
	case "24h", "":
		period = "24h"
	}

	stats, err := a.risk.TelemetryStats(since)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	stats.Period = period
	writeJSON(w, http.StatusOK, stats)
}

func telemetryPeriodSince(period string) time.Time {
	switch period {
	case "7d":
		return time.Now().Add(-7 * 24 * time.Hour)
	case "30d":
		return time.Now().Add(-30 * 24 * time.Hour)
	case "24h", "":
		return time.Now().Add(-24 * time.Hour)
	default:
		return time.Time{}
	}
}

// --- Agent API ---

func (a *app) agentStatusHandler(engine *agent.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var engineStatus any
		if engine == nil {
			engineStatus = map[string]any{"enabled": false}
		} else {
			engineStatus = engine.Status()
		}

		db := a.risk.StoreDB()
		var dbStats store.DatabaseStats
		var retentionDays int
		if db != nil && db.Enabled() {
			dbStats = db.Stats()
			retentionDays = db.GetRetentionDays()
		}

		var wlMetrics risk.WhitelistMetrics
		if a.risk != nil && a.risk.Whitelist() != nil {
			wlMetrics = a.risk.Whitelist().Metrics()
		}

		response := map[string]any{
			"status":                   engineStatus,
			"whitelist_stats":          wlMetrics,
			"database_stats":           dbStats,
			"telemetry_retention_days": retentionDays,
		}

		writeJSON(w, http.StatusOK, response)
	}
}

func agentTriggerHandler(engine *agent.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if engine == nil {
			writeError(w, http.StatusServiceUnavailable, "agent engine not enabled")
			return
		}
		taskName := r.URL.Query().Get("task")
		if taskName == "" {
			writeError(w, http.StatusBadRequest, "task query parameter is required")
			return
		}
		if !engine.Trigger(taskName) {
			writeError(w, http.StatusNotFound, "task not found: "+taskName)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "triggered", "task": taskName})
	}
}

func extractClientInfo(r *http.Request) risk.ClientInfo {
	ip := ""
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		ip = strings.TrimSpace(parts[0])
	}
	if ip == "" {
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			ip = strings.TrimSpace(xri)
		}
	}
	if ip == "" {
		remoteAddr := r.RemoteAddr
		if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
			ip = remoteAddr[:idx]
		} else {
			ip = remoteAddr
		}
		ip = strings.Trim(ip, "[]")
	}

	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		path := r.URL.Path
		path = strings.Trim(path, "/")
		parts := strings.Split(path, "/")
		if len(parts) >= 2 && parts[0] == "dns-query" {
			clientID = parts[1]
		} else if len(parts) == 1 && parts[0] != "" && parts[0] != "dns-query" {
			clientID = parts[0]
		}
	}

	return risk.ClientInfo{
		IP:       ip,
		ClientID: clientID,
	}
}

// --- Groups API ---

type groupRequest struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	BlockCategories []string `json:"block_categories"`
	StrictPhishing  bool     `json:"strict_phishing"`
	StrictMalware   bool     `json:"strict_malware"`
}

func (a *app) groupsHandler(w http.ResponseWriter, r *http.Request) {
	db := a.risk.StoreDB()
	if db == nil {
		writeError(w, http.StatusServiceUnavailable, "store not configured")
		return
	}

	switch r.Method {
	case http.MethodGet:
		id := r.URL.Query().Get("id")
		if id != "" {
			var gid int64
			if _, err := fmt.Sscanf(id, "%d", &gid); err != nil {
				writeError(w, http.StatusBadRequest, "invalid group id")
				return
			}
			g, err := db.GetGroup(gid)
			if err != nil {
				writeError(w, http.StatusNotFound, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, g)
			return
		}
		groups, err := db.ListGroups()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if groups == nil {
			groups = []store.ClientGroup{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": groups})

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
		defer r.Body.Close()
		var req groupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.Name == "" {
			writeError(w, http.StatusBadRequest, "name is required")
			return
		}
		id, err := db.CreateGroup(req.Name, req.Description, req.BlockCategories, req.StrictPhishing, req.StrictMalware)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": id, "status": "created"})

	case http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
		defer r.Body.Close()
		id := r.URL.Query().Get("id")
		if id == "" {
			writeError(w, http.StatusBadRequest, "id is required")
			return
		}
		var gid int64
		if _, err := fmt.Sscanf(id, "%d", &gid); err != nil {
			writeError(w, http.StatusBadRequest, "invalid group id")
			return
		}
		var req groupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if err := db.UpdateGroup(gid, req.Name, req.Description, req.BlockCategories, req.StrictPhishing, req.StrictMalware); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			writeError(w, http.StatusBadRequest, "id is required")
			return
		}
		var gid int64
		if _, err := fmt.Sscanf(id, "%d", &gid); err != nil {
			writeError(w, http.StatusBadRequest, "invalid group id")
			return
		}
		if err := db.DeleteGroup(gid); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// --- Mappings API ---

type mappingRequest struct {
	MappingType string `json:"mapping_type"`
	Value       string `json:"value"`
	GroupID     int64  `json:"group_id"`
}

func (a *app) mappingsHandler(w http.ResponseWriter, r *http.Request) {
	db := a.risk.StoreDB()
	if db == nil {
		writeError(w, http.StatusServiceUnavailable, "store not configured")
		return
	}

	switch r.Method {
	case http.MethodGet:
		mappings, err := db.ListMappings()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if mappings == nil {
			mappings = []store.ClientMapping{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": mappings})

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 10240)
		defer r.Body.Close()
		var req mappingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.MappingType == "" || req.Value == "" || req.GroupID == 0 {
			writeError(w, http.StatusBadRequest, "mapping_type, value, and group_id are required")
			return
		}
		id, err := db.AddMappingInt(req.MappingType, req.Value, req.GroupID)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": id, "status": "created"})

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			writeError(w, http.StatusBadRequest, "id is required")
			return
		}
		var mid int64
		if _, err := fmt.Sscanf(id, "%d", &mid); err != nil {
			writeError(w, http.StatusBadRequest, "invalid mapping id")
			return
		}
		if err := db.DeleteMapping(mid); err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// --- Group Overrides API ---

type groupOverrideRequest struct {
	GroupID int64  `json:"group_id"`
	Domain  string `json:"domain"`
	Action  string `json:"action"`
	Reason  string `json:"reason"`
}

func (a *app) groupOverridesHandler(w http.ResponseWriter, r *http.Request) {
	db := a.risk.StoreDB()
	if db == nil {
		writeError(w, http.StatusServiceUnavailable, "store not configured")
		return
	}

	switch r.Method {
	case http.MethodGet:
		groupIDStr := r.URL.Query().Get("group_id")
		if groupIDStr == "" {
			writeError(w, http.StatusBadRequest, "group_id is required")
			return
		}
		var gid int64
		if _, err := fmt.Sscanf(groupIDStr, "%d", &gid); err != nil {
			writeError(w, http.StatusBadRequest, "invalid group_id")
			return
		}
		overrides, err := db.ListGroupOverrides(gid)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if overrides == nil {
			overrides = []store.GroupOverride{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": overrides})

	case http.MethodPost, http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, 10240)
		defer r.Body.Close()
		var req groupOverrideRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.GroupID == 0 || req.Domain == "" || req.Action == "" {
			writeError(w, http.StatusBadRequest, "group_id, domain, and action are required")
			return
		}
		if err := db.UpsertGroupOverride(req.GroupID, req.Domain, req.Action, req.Reason); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	case http.MethodDelete:
		groupIDStr := r.URL.Query().Get("group_id")
		domain := r.URL.Query().Get("domain")
		if groupIDStr == "" || domain == "" {
			writeError(w, http.StatusBadRequest, "group_id and domain are required")
			return
		}
		var gid int64
		if _, err := fmt.Sscanf(groupIDStr, "%d", &gid); err != nil {
			writeError(w, http.StatusBadRequest, "invalid group_id")
			return
		}
		if err := db.DeleteGroupOverride(gid, domain); err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// --- Authentication & Session Handlers ---

func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.ToLower(r.Header.Get("X-Forwarded-Proto")) == "https" {
		return true
	}
	return false
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a *app) authLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Limit request body size to 4KB to prevent JSON memory exhaustion DoS attacks
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	defer r.Body.Close()

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Use ConstantTimeCompare with SHA-256 hashing to secure comparisons against timing attacks
	userHash := sha256.Sum256([]byte(req.Username))
	expectedUserHash := sha256.Sum256([]byte("admin"))
	passHash := sha256.Sum256([]byte(req.Password))
	expectedPassHash := sha256.Sum256([]byte(a.adminPassword))

	userMatch := subtle.ConstantTimeCompare(userHash[:], expectedUserHash[:]) == 1
	passMatch := subtle.ConstantTimeCompare(passHash[:], expectedPassHash[:]) == 1

	if !userMatch || !passMatch {
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	token, err := auth.GenerateSessionCookieValue("admin", 12*time.Hour, a.sessionSecret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate session")
		return
	}

	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure is dynamically set via isHTTPS(r)
		Name:     "admin_session",
		Value:    token,
		Path:     "/",
		MaxAge:   int(12 * time.Hour / time.Second),
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *app) authLogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure is dynamically set via isHTTPS(r)
		Name:     "admin_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *app) requireAuthFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Check Authorization Header for static API Key
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")

			// Use ConstantTimeCompare with SHA-256 hashing to secure token comparisons against timing attacks
			tokenHash := sha256.Sum256([]byte(token))
			expectedHash := sha256.Sum256([]byte(a.adminAPIKey))

			if subtle.ConstantTimeCompare(tokenHash[:], expectedHash[:]) == 1 {
				next(w, r)
				return
			}
		}

		// 2. Check Session Cookie
		cookie, err := r.Cookie("admin_session")
		if err == nil && cookie.Value != "" {
			_, err = auth.VerifySessionCookieValue(cookie.Value, a.sessionSecret)
			if err == nil {
				// Cookie auth is active. Enforce CSRF protection for state-modifying requests.
				if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
					if csrfErr := a.verifyCSRF(r); csrfErr != nil {
						writeError(w, http.StatusForbidden, "CSRF verification failed: "+csrfErr.Error())
						return
					}
				}
				next(w, r)
				return
			}
		}

		writeError(w, http.StatusUnauthorized, "unauthorized")
	}
}

func isStateChangingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func (a *app) validCSRFSources(r *http.Request) bool {
	source := strings.TrimSpace(r.Header.Get("Origin"))
	if source == "" {
		source = strings.TrimSpace(r.Header.Get("Referer"))
	}
	if source == "" {
		return false
	}

	parsed, err := url.Parse(source)
	if err != nil || parsed.Host == "" {
		return false
	}

	sourceHost := canonicalRequestHost(parsed.Host)
	for _, allowed := range []string{r.Host, a.publicHost, config.String("SAFE_ZONE_PUBLIC_HOST", "")} {
		if sourceHost == canonicalRequestHost(allowed) {
			return true
		}
	}
	return false
}

func (a *app) verifyCSRF(r *http.Request) error {
	if !a.validCSRFSources(r) {
		return fmt.Errorf("invalid csrf origin or referer")
	}
	return nil
}

func canonicalRequestHost(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil {
			value = parsed.Host
		}
	}
	value = strings.TrimSuffix(value, "/")
	if host, port, err := net.SplitHostPort(value); err == nil {
		if port == "80" || port == "443" {
			return host
		}
		return net.JoinHostPort(host, port)
	}
	return value
}

// Settings API Handlers

type settingsResponse struct {
	GeminiAPIKey           string `json:"gemini_api_key"`
	AgentWebhookURL        string `json:"agent_webhook_url"`
	TelemetryRetentionDays int    `json:"telemetry_retention_days"`
}

type settingsRequest struct {
	GeminiAPIKey           string `json:"gemini_api_key"`
	AgentWebhookURL        string `json:"agent_webhook_url"`
	TelemetryRetentionDays int    `json:"telemetry_retention_days"`
}

type testAlertEvent struct {
	Type      string `json:"type"`
	Domain    string `json:"domain,omitempty"`
	Details   string `json:"details,omitempty"`
	CreatedAt string `json:"created_at"`
}

type testAlertPayload struct {
	Timestamp string           `json:"timestamp"`
	EventType string           `json:"event_type"`
	Summary   string           `json:"summary"`
	Events    []testAlertEvent `json:"events"`
}

func maskConfigValue(val string) string {
	if val == "" {
		return ""
	}
	if len(val) <= 4 {
		return strings.Repeat("*", len(val))
	}
	return val[:4] + strings.Repeat("*", len(val)-4)
}

func (a *app) settingsHandler(w http.ResponseWriter, r *http.Request) {
	db := a.risk.StoreDB()
	if db == nil || !db.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	switch r.Method {
	case http.MethodGet:
		apiKey, err := db.GetSystemConfig("gemini_api_key")
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get gemini_api_key: "+err.Error())
			return
		}
		webhookURL, err := db.GetSystemConfig("agent_webhook_url")
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get agent_webhook_url: "+err.Error())
			return
		}

		writeJSON(w, http.StatusOK, settingsResponse{
			GeminiAPIKey:           maskConfigValue(apiKey),
			AgentWebhookURL:        maskConfigValue(webhookURL),
			TelemetryRetentionDays: db.GetRetentionDays(),
		})

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var req settingsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		// Save Gemini API Key if not masked
		if req.GeminiAPIKey != "" {
			if !strings.Contains(req.GeminiAPIKey, "*") {
				if err := db.SetSystemConfig("gemini_api_key", strings.TrimSpace(req.GeminiAPIKey)); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to save gemini_api_key: "+err.Error())
					return
				}
				// Hot reload key in client
				if a.risk != nil {
					a.risk.AIClient() // triggers syncAIClient
				}
			}
		} else {
			if err := db.SetSystemConfig("gemini_api_key", ""); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to clear gemini_api_key: "+err.Error())
				return
			}
		}

		// Save Webhook URL if not masked
		if req.AgentWebhookURL != "" {
			if !strings.Contains(req.AgentWebhookURL, "*") {
				if err := db.SetSystemConfig("agent_webhook_url", strings.TrimSpace(req.AgentWebhookURL)); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to save agent_webhook_url: "+err.Error())
					return
				}
			}
		} else {
			if err := db.SetSystemConfig("agent_webhook_url", ""); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to clear agent_webhook_url: "+err.Error())
				return
			}
		}

		// Save Telemetry Retention Days if provided
		if req.TelemetryRetentionDays > 0 {
			db.UpdateRetentionDays(req.TelemetryRetentionDays)
			if err := db.SetSystemConfig("telemetry_retention_days", strconv.Itoa(req.TelemetryRetentionDays)); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to save telemetry_retention_days: "+err.Error())
				return
			}
		}

		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *app) analysisConfigHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.risk.GetAnalysisConfig())
	case http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, 32768)
		defer r.Body.Close()
		cfg := a.risk.GetAnalysisConfig()
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&cfg); err != nil {
			writeError(w, http.StatusBadRequest, "invalid analysis config JSON: "+err.Error())
			return
		}
		if err := a.risk.UpdateAnalysisConfig(r.Context(), cfg); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, a.risk.GetAnalysisConfig())
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *app) analysisConfigResetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cfg, err := a.risk.ResetAnalysisConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (a *app) testAIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	aiClient := a.risk.AIClient()
	if aiClient == nil || !aiClient.Enabled() {
		writeError(w, http.StatusBadRequest, "AI client is not configured or disabled")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	testRes := analysis.Result{
		Domain:     "test-api-key.com",
		Verdict:    analysis.VerdictSuspicious,
		Score:      50,
		Confidence: 0.5,
		Reasons:    []string{"testing API key configuration"},
	}

	res, err := aiClient.Refine(ctx, "test-api-key.com", testRes)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"verdict": res.Verdict,
		"reason":  strings.Join(res.Reasons, "; "),
	})
}

func (a *app) testAlertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	db := a.risk.StoreDB()
	if db == nil || !db.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	webhookURL := ""
	if customURL, err := db.GetSystemConfig("agent_webhook_url"); err == nil && customURL != "" {
		webhookURL = customURL
	}
	if webhookURL == "" {
		webhookURL = config.SecretString("SAFE_ZONE_AGENT_WEBHOOK_URL", "")
	}

	if webhookURL == "" {
		writeError(w, http.StatusBadRequest, "No webhook URL configured")
		return
	}

	payload := testAlertPayload{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		EventType: "safe_zone_test_alert",
		Summary:   "Safe Zone: This is a test notification from the management console",
		Events: []testAlertEvent{
			{
				Type:      "test_alert",
				Domain:    "test-notification.com",
				Details:   "Testing Discord/Slack Alert Channel Configuration",
				CreatedAt: time.Now().Format(time.RFC3339),
			},
		},
	}

	var body []byte
	var err error
	if strings.Contains(webhookURL, "discord.com/api/webhooks") || strings.Contains(webhookURL, "discordapp.com/api/webhooks") {
		discord := map[string]any{
			"embeds": []map[string]any{
				{
					"title":       "🔔 Safe Zone Test Alert",
					"description": "🟢 Your Alert Notification integration is working perfectly!",
					"color":       3066993,
					"footer": map[string]string{
						"text": payload.Summary,
					},
					"timestamp": payload.Timestamp,
				},
			},
		}
		body, err = json.Marshal(discord)
	} else {
		body, err = json.Marshal(payload)
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to marshal payload: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create request: "+err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "error",
			"error":  fmt.Sprintf("Webhook returned status %d", resp.StatusCode),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
	})
}
