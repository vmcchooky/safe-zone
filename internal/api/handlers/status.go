package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/buildinfo"
	"safe-zone/internal/feed"
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


func (h *Handler) FeedStatus(ctx context.Context) feed.StatusSummary {
	return feed.ReadStatusSummary(ctx, h.Risk.RedisCache(), h.Config.FeedKey, h.Config.FeedPreset, h.Config.FeedSources, h.Config.FeedStaleAfter)
}

func (h *Handler) CacheFlushHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if h.Risk != nil && h.Risk.Whitelist() != nil {
		err := h.Risk.Whitelist().LoadFromDB()
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "Failed to flush cache: "+err.Error())
			return
		}
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "Cache flushed"})
}

func (h *Handler) LogsExportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=\"safe-zone-diagnostics.log\"")

	_, _ = w.Write([]byte("Safe-Zone Diagnostic Logs\n=========================\n\n"))
	
	db := h.Risk.StoreDB()
	if db != nil {
		events, err := db.QueryAgentEvents(r.Context(), time.Now().Add(-7*24*time.Hour), []string{}, 1000)
		if err == nil {
			for _, ev := range events {
				_, _ = w.Write([]byte(fmt.Sprintf("[%s] %s: %s - %s (Domain: %s)\n", ev.CreatedAt, ev.TaskName, ev.EventType, ev.Details, ev.Domain)))
			}
		} else {
			_, _ = w.Write([]byte("Error fetching events: " + err.Error() + "\n"))
		}
	} else {
		_, _ = w.Write([]byte("Store DB is disabled or unavailable.\n"))
	}
}
