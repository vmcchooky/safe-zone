package handlers

import (
	"context"
	"net/http"
	"time"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/buildinfo"
	"safe-zone/internal/feed"
	"safe-zone/internal/logjson"
	"safe-zone/internal/risk"
)

type RateLimitingStatus struct {
	Enabled bool `json:"enabled"`
}

type statusResponse struct {
	Service        string                           `json:"service"`
	Status         string                           `json:"status"`
	Mode           string                           `json:"mode,omitempty"`
	DeploymentTier string                           `json:"deployment_tier,omitempty"`
	Redis          *risk.CacheStatus                `json:"redis,omitempty"`
	AnalysisConfig *risk.AnalysisConfigReloadStatus `json:"analysis_config_reload,omitempty"`
	FeedSync       *feed.StatusSummary              `json:"feed_sync,omitempty"`
	Adblock        *risk.AdblockStatus              `json:"adblock,omitempty"`
	Endpoints      []string                         `json:"endpoints,omitempty"`
	RateLimiting   *RateLimitingStatus              `json:"rate_limiting,omitempty"`
	Time           string                           `json:"time"`
}

func HealthHandler(service string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		httputil.WriteJSON(w, http.StatusOK, statusResponse{
			Service: service,
			Status:  "ok",
			Time:    time.Now().UTC().Format(time.RFC3339Nano),
		})
	}
}

func (h *Handler) StatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/v1/status" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	cacheStatus := h.Risk.CacheStatus(r.Context())
	analysisConfigStatus := h.Risk.AnalysisConfigReloadStatus()
	feedStatus := h.FeedStatus(r.Context())
	adblockStatus := h.Risk.AdblockStatus()
	httputil.WriteJSON(w, http.StatusOK, statusResponse{
		Service:        "core-api",
		Status:         "ok",
		Mode:           "api",
		DeploymentTier: h.Config.DeploymentTier,
		Redis:          &cacheStatus,
		AnalysisConfig: &analysisConfigStatus,
		FeedSync:       &feedStatus,
		Adblock:        &adblockStatus,
		Endpoints: []string{
			"/",
			"/v1/status",
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
			Enabled: true, /* TODO fix ratelimiter status */
		},
		Time: time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (h *Handler) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"service":                "core-api",
		"status":                 "ok",
		"metrics":                h.Metrics.Snapshot(),
		"feed_sync":              h.FeedStatus(r.Context()),
		"adblock":                h.Risk.AdblockStatus(),
		"analysis_config_reload": h.Risk.AnalysisConfigReloadStatus(),
		"time":                   time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (h *Handler) VersionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, buildinfo.Snapshot("core-api", h.Config.DeploymentTier))
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

func logAnalysisConfigReloadStatus(service string, riskService *risk.Service) {
	status := riskService.AnalysisConfigReloadStatus()
	logjson.Info("analysis config reload status", map[string]any{
		"service":            service,
		"enabled":            status.Enabled,
		"channel":            status.Channel,
		"poll_interval":      status.PollInterval,
		"node_role":          status.NodeRole,
		"revision":           status.Revision,
		"last_reload_source": status.LastReloadSource,
		"last_reload_at":     status.LastReloadAt,
		"redis_configured":   status.RedisConfigured,
		"store_configured":   status.StoreConfigured,
		"subscriber_active":  status.SubscriberActive,
		"reconciler_active":  status.ReconcilerActive,
	})
}

func (h *Handler) FeedStatus(ctx context.Context) feed.StatusSummary {
	return feed.ReadStatusSummary(ctx, h.Risk.RedisCache(), h.Config.FeedKey, h.Config.FeedPreset, h.Config.FeedSources, h.Config.FeedStaleAfter)
}
