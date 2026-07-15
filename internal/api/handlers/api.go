package handlers

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
	"strconv"
	"strings"
	"time"

	"safe-zone/internal/agent"
	"safe-zone/internal/analysis"
	"safe-zone/internal/api/httputil"
	"safe-zone/internal/auth"
	"safe-zone/internal/buildinfo"
	"safe-zone/internal/config"
	"safe-zone/internal/feed"
	"safe-zone/internal/logjson"
	"safe-zone/internal/risk"
	"safe-zone/internal/store"
)

// types that were at the top of main.go
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

type analyzeRequest struct {
	Domain string `json:"domain"`
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
			Enabled: h.Config.RateLimitingEnabled,
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

func (h *Handler) AnalyzeHandler(w http.ResponseWriter, r *http.Request) {
	var domain string

	switch r.Method {
	case http.MethodGet:
		domain = r.URL.Query().Get("domain")
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		defer r.Body.Close()
		var req analyzeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		domain = req.Domain
	default:
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	clientInfo := httputil.ExtractClientInfo(r)
	response := h.Risk.AnalyzeWithOptions(r.Context(), domain, clientInfo, risk.AnalyzeOptions{
		IncludeEvidence: r.URL.Query().Get("include_evidence") == "1",
		ForceOSINT:      r.URL.Query().Get("force_osint") == "1",
	})
	h.Risk.RecordRecent(r.Context(), response)
	httputil.WriteJSON(w, http.StatusOK, response)
}

func (h *Handler) OsintEvidenceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		httputil.WriteError(w, http.StatusBadRequest, "domain query parameter is required")
		return
	}
	force := r.URL.Query().Get("refresh") == "1" || r.URL.Query().Get("force") == "1"
	report, err := h.Risk.OSINTEvidence(r.Context(), domain, force)
	if err != nil {
		httputil.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	httputil.WriteJSON(w, http.StatusOK, report)
}

func (h *Handler) RecentAnalysisHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"items": h.Risk.Recent(r.Context()),
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

func (h *Handler) OverridesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		action := r.URL.Query().Get("action")
		overrides, err := h.Risk.ListOverrides(action)
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if overrides == nil {
			overrides = []store.Override{}
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"items": overrides})

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 10240)
		defer r.Body.Close()
		var req overrideRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.Domain == "" || req.Action == "" {
			httputil.WriteError(w, http.StatusBadRequest, "domain and action are required")
			return
		}
		if err := h.Risk.UpsertOverride(req.Domain, req.Action, req.Reason); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "domain": req.Domain, "action": req.Action})

	case http.MethodDelete:
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			httputil.WriteError(w, http.StatusBadRequest, "domain query parameter is required")
			return
		}
		if err := h.Risk.DeleteOverride(domain); err != nil {
			httputil.WriteError(w, http.StatusNotFound, err.Error())
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "domain": domain})

	default:
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) ReviewFalsePositiveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 12288)
	defer r.Body.Close()

	var req falsePositiveReviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	req.Domain = strings.TrimSpace(req.Domain)
	req.Reason = strings.TrimSpace(req.Reason)
	req.Source = strings.TrimSpace(req.Source)
	req.PreviousAction = strings.TrimSpace(req.PreviousAction)

	if req.Domain == "" {
		httputil.WriteError(w, http.StatusBadRequest, "domain is required")
		return
	}
	if req.Reason == "" {
		httputil.WriteError(w, http.StatusBadRequest, "review reason is required")
		return
	}
	normalized, err := analysis.NormalizeDomain(req.Domain)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid domain: "+err.Error())
		return
	}

	reviewReason := "false-positive review: " + req.Reason
	if req.Source != "" {
		reviewReason = fmt.Sprintf("false-positive review (%s): %s", req.Source, req.Reason)
	}

	if err := h.Risk.UpsertOverride(normalized, "allow", reviewReason); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	if db := h.Risk.StoreDB(); db != nil {
		details := map[string]string{
			"source":          req.Source,
			"review_reason":   req.Reason,
			"previous_action": req.PreviousAction,
			"resolved_action": "allow",
		}
		if data, err := json.Marshal(details); err == nil {
			_ = db.RecordAgentEvent(r.Context(), "operator_review", "operator_false_positive_review", normalized, string(data))
		}
		if db.Enabled() {
			_ = db.ResolveBlockReportsForDomain(r.Context(), normalized)
		}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"domain": normalized,
		"action": "allow",
		"reason": reviewReason,
	})
}

// --- Telemetry API ---

func (h *Handler) TelemetryRecentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
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

	entries, err := h.Risk.TelemetryRecentFiltered(filter, limit, offset)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []store.TelemetryEntry{}
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"items":  entries,
		"filter": filter,
	})
}

func (h *Handler) ListReportsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
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

	db := h.Risk.StoreDB()
	if db == nil || !db.Enabled() {
		httputil.WriteError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	reports, err := db.ListBlockReportsFiltered(r.Context(), store.BlockReportFilter{
		Status: status,
		Query:  query,
	}, limit, offset)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to list reports: "+err.Error())
		return
	}
	if reports == nil {
		reports = []store.BlockReport{}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"reports": reports,
		"filter": map[string]string{
			"status": status,
			"q":      query,
		},
	})
}

func (h *Handler) UpdateReportStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	defer r.Body.Close()

	var req updateReportStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	req.Status = strings.TrimSpace(req.Status)
	if req.ID <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid ID")
		return
	}
	if req.Status == "" {
		httputil.WriteError(w, http.StatusBadRequest, "status is required")
		return
	}

	db := h.Risk.StoreDB()
	if db == nil || !db.Enabled() {
		httputil.WriteError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	if err := db.UpdateBlockReportStatus(r.Context(), req.ID, req.Status); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to update report status: "+err.Error())
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func (h *Handler) TelemetryStatsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
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

	stats, err := h.Risk.TelemetryStats(since)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	stats.Period = period
	httputil.WriteJSON(w, http.StatusOK, stats)
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

func (h *Handler) AgentStatusHandler(engine *agent.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var engineStatus any
		if engine == nil {
			engineStatus = map[string]any{"enabled": false}
		} else {
			engineStatus = engine.Status()
		}

		db := h.Risk.StoreDB()
		var dbStats store.DatabaseStats
		var retentionDays int
		if db != nil && db.Enabled() {
			dbStats = db.Stats(context.Background())
			retentionDays = db.GetRetentionDays(context.Background())
		}

		var wlMetrics risk.WhitelistMetrics
		if h.Risk != nil && h.Risk.Whitelist() != nil {
			wlMetrics = h.Risk.Whitelist().Metrics()
		}

		response := map[string]any{
			"status":                   engineStatus,
			"whitelist_stats":          wlMetrics,
			"database_stats":           dbStats,
			"telemetry_retention_days": retentionDays,
		}

		httputil.WriteJSON(w, http.StatusOK, response)
	}
}

func AgentTriggerHandler(engine *agent.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if engine == nil {
			httputil.WriteError(w, http.StatusServiceUnavailable, "agent engine not enabled")
			return
		}
		taskName := r.URL.Query().Get("task")
		if taskName == "" {
			httputil.WriteError(w, http.StatusBadRequest, "task query parameter is required")
			return
		}
		if !engine.Trigger(taskName) {
			httputil.WriteError(w, http.StatusNotFound, "task not found: "+taskName)
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "triggered", "task": taskName})
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

func (h *Handler) GroupsHandler(w http.ResponseWriter, r *http.Request) {
	db := h.Risk.StoreDB()
	if db == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "store not configured")
		return
	}

	switch r.Method {
	case http.MethodGet:
		id := r.URL.Query().Get("id")
		if id != "" {
			var gid int64
			if _, err := fmt.Sscanf(id, "%d", &gid); err != nil {
				httputil.WriteError(w, http.StatusBadRequest, "invalid group id")
				return
			}
			g, err := db.GetGroup(r.Context(), gid)
			if err != nil {
				httputil.WriteError(w, http.StatusNotFound, err.Error())
				return
			}
			httputil.WriteJSON(w, http.StatusOK, g)
			return
		}
		groups, err := db.ListGroups(r.Context())
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if groups == nil {
			groups = []store.ClientGroup{}
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"items": groups})

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
		defer r.Body.Close()
		var req groupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.Name == "" {
			httputil.WriteError(w, http.StatusBadRequest, "name is required")
			return
		}
		id, err := db.CreateGroup(r.Context(), req.Name, req.Description, req.BlockCategories, req.StrictPhishing, req.StrictMalware)
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		httputil.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "status": "created"})

	case http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
		defer r.Body.Close()
		id := r.URL.Query().Get("id")
		if id == "" {
			httputil.WriteError(w, http.StatusBadRequest, "id is required")
			return
		}
		var gid int64
		if _, err := fmt.Sscanf(id, "%d", &gid); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid group id")
			return
		}
		var req groupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if err := db.UpdateGroup(r.Context(), gid, req.Name, req.Description, req.BlockCategories, req.StrictPhishing, req.StrictMalware); err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "updated"})

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			httputil.WriteError(w, http.StatusBadRequest, "id is required")
			return
		}
		var gid int64
		if _, err := fmt.Sscanf(id, "%d", &gid); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid group id")
			return
		}
		if err := db.DeleteGroup(r.Context(), gid); err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// --- Mappings API ---

type mappingRequest struct {
	MappingType string `json:"mapping_type"`
	Value       string `json:"value"`
	GroupID     int64  `json:"group_id"`
}

func (h *Handler) MappingsHandler(w http.ResponseWriter, r *http.Request) {
	db := h.Risk.StoreDB()
	if db == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "store not configured")
		return
	}

	switch r.Method {
	case http.MethodGet:
		mappings, err := db.ListMappings(r.Context())
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if mappings == nil {
			mappings = []store.ClientMapping{}
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"items": mappings})

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 10240)
		defer r.Body.Close()
		var req mappingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.MappingType == "" || req.Value == "" || req.GroupID == 0 {
			httputil.WriteError(w, http.StatusBadRequest, "mapping_type, value, and group_id are required")
			return
		}
		id, err := db.AddMappingInt(r.Context(), req.MappingType, req.Value, req.GroupID)
		if err != nil {
			httputil.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		httputil.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "status": "created"})

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			httputil.WriteError(w, http.StatusBadRequest, "id is required")
			return
		}
		var mid int64
		if _, err := fmt.Sscanf(id, "%d", &mid); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid mapping id")
			return
		}
		if err := db.DeleteMapping(r.Context(), mid); err != nil {
			httputil.WriteError(w, http.StatusNotFound, err.Error())
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// --- Group Overrides API ---

type groupOverrideRequest struct {
	GroupID int64  `json:"group_id"`
	Domain  string `json:"domain"`
	Action  string `json:"action"`
	Reason  string `json:"reason"`
}

func (h *Handler) GroupOverridesHandler(w http.ResponseWriter, r *http.Request) {
	db := h.Risk.StoreDB()
	if db == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "store not configured")
		return
	}

	switch r.Method {
	case http.MethodGet:
		groupIDStr := r.URL.Query().Get("group_id")
		if groupIDStr == "" {
			httputil.WriteError(w, http.StatusBadRequest, "group_id is required")
			return
		}
		var gid int64
		if _, err := fmt.Sscanf(groupIDStr, "%d", &gid); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid group_id")
			return
		}
		overrides, err := db.ListGroupOverrides(r.Context(), gid)
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if overrides == nil {
			overrides = []store.GroupOverride{}
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"items": overrides})

	case http.MethodPost, http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, 10240)
		defer r.Body.Close()
		var req groupOverrideRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.GroupID == 0 || req.Domain == "" || req.Action == "" {
			httputil.WriteError(w, http.StatusBadRequest, "group_id, domain, and action are required")
			return
		}
		if err := db.UpsertGroupOverride(r.Context(), req.GroupID, req.Domain, req.Action, req.Reason); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	case http.MethodDelete:
		groupIDStr := r.URL.Query().Get("group_id")
		domain := r.URL.Query().Get("domain")
		if groupIDStr == "" || domain == "" {
			httputil.WriteError(w, http.StatusBadRequest, "group_id and domain are required")
			return
		}
		var gid int64
		if _, err := fmt.Sscanf(groupIDStr, "%d", &gid); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid group_id")
			return
		}
		if err := db.DeleteGroupOverride(r.Context(), gid, domain); err != nil {
			httputil.WriteError(w, http.StatusNotFound, err.Error())
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
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

func (h *Handler) AuthLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Limit request body size to 4KB to prevent JSON memory exhaustion DoS attacks
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	defer r.Body.Close()

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	username := strings.TrimSpace(strings.ToLower(req.Username))

	// Use ConstantTimeCompare with SHA-256 hashing to secure comparisons against timing attacks
	userHash := sha256.Sum256([]byte(username))
	expectedUserHash := sha256.Sum256([]byte(auth.RoleAdmin))
	passHash := sha256.Sum256([]byte(req.Password))
	expectedPassHash := sha256.Sum256([]byte(h.Config.AdminPassword))

	userMatch := subtle.ConstantTimeCompare(userHash[:], expectedUserHash[:]) == 1
	passMatch := subtle.ConstantTimeCompare(passHash[:], expectedPassHash[:]) == 1

	role := ""
	if userMatch && passMatch {
		role = auth.RoleAdmin
	} else if username == auth.RoleGuest {
		cfg, err := h.loadGuestAccessConfig(r.Context())
		if err != nil {
			httputil.WriteError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		if cfg.Exists() && cfg.Enabled && auth.VerifyPasswordHash(cfg.PasswordHash, req.Password) == nil {
			role = auth.RoleGuest
		}
	}

	if role == "" {
		httputil.WriteError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	token, err := auth.GenerateSessionCookieValueForRole(username, role, 12*time.Hour, h.Config.SessionSecret)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to generate session")
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

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) AuthLogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	clearSessionCookie(w, r)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) RequireAuthFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Check Authorization Header for static API Key
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")

			// Use ConstantTimeCompare with SHA-256 hashing to secure token comparisons against timing attacks
			tokenHash := sha256.Sum256([]byte(token))
			expectedHash := sha256.Sum256([]byte(h.Config.AdminAPIKey))

			if subtle.ConstantTimeCompare(tokenHash[:], expectedHash[:]) == 1 {
				identity := authIdentity{Username: auth.RoleAdmin, Role: auth.RoleAdmin, AuthMethod: "bearer"}
				next(w, r.WithContext(withAuthIdentity(r.Context(), identity)))
				return
			}
		}

		// 2. Check Session Cookie
		cookie, err := r.Cookie("admin_session")
		if err == nil && cookie.Value != "" {
			claims, err := auth.VerifySessionClaims(cookie.Value, h.Config.SessionSecret)
			if err == nil {
				if err := h.ensureGuestSessionActive(r.Context(), claims); err != nil {
					if err == errGuestAccessRevoked {
						clearSessionCookie(w, r)
						httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
						return
					}
					httputil.WriteError(w, http.StatusServiceUnavailable, "guest access validation unavailable")
					return
				}

				// Cookie auth is active. Enforce CSRF protection for state-modifying requests.
				if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
					if csrfErr := h.VerifyCSRF(r); csrfErr != nil {
						httputil.WriteError(w, http.StatusForbidden, "CSRF verification failed: "+csrfErr.Error())
						return
					}
				}
				identity := authIdentity{
					Username:   claims.Username,
					Role:       claims.Role,
					AuthMethod: "cookie",
				}
				next(w, r.WithContext(withAuthIdentity(r.Context(), identity)))
				return
			}
		}

		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
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

func (h *Handler) ValidCSRFSources(r *http.Request) bool {
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
	for _, allowed := range []string{r.Host, h.Config.PublicHost, config.String("SAFE_ZONE_PUBLIC_HOST", "")} {
		if sourceHost == canonicalRequestHost(allowed) {
			return true
		}
	}
	return false
}

func (h *Handler) VerifyCSRF(r *http.Request) error {
	if !h.ValidCSRFSources(r) {
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

type settingsBundleResponse struct {
	Settings       settingsResponse          `json:"settings"`
	AnalysisConfig config.AnalysisConfig     `json:"analysis_config"`
	GuestAccess    guestAccessStatusResponse `json:"guest_access"`
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

func (h *Handler) loadSettingsResponse(ctx context.Context) (settingsResponse, error) {
	db := h.Risk.StoreDB()
	if db == nil || !db.Enabled() {
		return settingsResponse{}, fmt.Errorf("database not configured")
	}

	apiKey, err := db.GetSystemConfig(ctx, "gemini_api_key")
	if err != nil {
		return settingsResponse{}, fmt.Errorf("failed to get gemini_api_key: %w", err)
	}
	webhookURL, err := db.GetSystemConfig(ctx, "agent_webhook_url")
	if err != nil {
		return settingsResponse{}, fmt.Errorf("failed to get agent_webhook_url: %w", err)
	}

	return settingsResponse{
		GeminiAPIKey:           maskConfigValue(apiKey),
		AgentWebhookURL:        maskConfigValue(webhookURL),
		TelemetryRetentionDays: db.GetRetentionDays(ctx),
	}, nil
}

func (h *Handler) SettingsHandler(w http.ResponseWriter, r *http.Request) {
	db := h.Risk.StoreDB()
	if db == nil || !db.Enabled() {
		httputil.WriteError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	switch r.Method {
	case http.MethodGet:
		resp, err := h.loadSettingsResponse(r.Context())
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		httputil.WriteJSON(w, http.StatusOK, resp)

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var req settingsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		// Save Gemini API Key if not masked
		if req.GeminiAPIKey != "" {
			if !strings.Contains(req.GeminiAPIKey, "*") {
				if err := db.SetSystemConfig(r.Context(), "gemini_api_key", strings.TrimSpace(req.GeminiAPIKey)); err != nil {
					httputil.WriteError(w, http.StatusInternalServerError, "failed to save gemini_api_key: "+err.Error())
					return
				}
				// Hot reload key in client
				if h.Risk != nil {
					h.Risk.AIClient() // triggers syncAIClient
				}
			}
		} else {
			if err := db.SetSystemConfig(r.Context(), "gemini_api_key", ""); err != nil {
				httputil.WriteError(w, http.StatusInternalServerError, "failed to clear gemini_api_key: "+err.Error())
				return
			}
		}

		// Save Webhook URL if not masked
		if req.AgentWebhookURL != "" {
			if !strings.Contains(req.AgentWebhookURL, "*") {
				if err := db.SetSystemConfig(r.Context(), "agent_webhook_url", strings.TrimSpace(req.AgentWebhookURL)); err != nil {
					httputil.WriteError(w, http.StatusInternalServerError, "failed to save agent_webhook_url: "+err.Error())
					return
				}
			}
		} else {
			if err := db.SetSystemConfig(r.Context(), "agent_webhook_url", ""); err != nil {
				httputil.WriteError(w, http.StatusInternalServerError, "failed to clear agent_webhook_url: "+err.Error())
				return
			}
		}

		// Save Telemetry Retention Days if provided
		if req.TelemetryRetentionDays > 0 {
			db.UpdateRetentionDays(r.Context(), req.TelemetryRetentionDays)
			if err := db.SetSystemConfig(r.Context(), "telemetry_retention_days", strconv.Itoa(req.TelemetryRetentionDays)); err != nil {
				httputil.WriteError(w, http.StatusInternalServerError, "failed to save telemetry_retention_days: "+err.Error())
				return
			}
		}

		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	default:
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) SettingsBundleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	settings, err := h.loadSettingsResponse(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	guestCfg, err := h.loadGuestAccessConfig(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	httputil.WriteJSON(w, http.StatusOK, settingsBundleResponse{
		Settings:       settings,
		AnalysisConfig: h.Risk.GetAnalysisConfig(),
		GuestAccess:    guestAccessStatus(guestCfg),
	})
}

func (h *Handler) AnalysisConfigHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		httputil.WriteJSON(w, http.StatusOK, h.Risk.GetAnalysisConfig())
	case http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, 32768)
		defer r.Body.Close()
		cfg := h.Risk.GetAnalysisConfig()
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&cfg); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid analysis config JSON: "+err.Error())
			return
		}
		if err := h.Risk.UpdateAnalysisConfig(r.Context(), cfg); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		httputil.WriteJSON(w, http.StatusOK, h.Risk.GetAnalysisConfig())
	default:
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) AnalysisConfigResetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cfg, err := h.Risk.ResetAnalysisConfig(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	httputil.WriteJSON(w, http.StatusOK, cfg)
}

func (h *Handler) TestAIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	aiClient := h.Risk.AIClient()
	if aiClient == nil || !aiClient.Enabled() {
		httputil.WriteError(w, http.StatusBadRequest, "AI client is not configured or disabled")
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
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"verdict": res.Verdict,
		"reason":  strings.Join(res.Reasons, "; "),
	})
}

func (h *Handler) TestAlertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	db := h.Risk.StoreDB()
	if db == nil || !db.Enabled() {
		httputil.WriteError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	webhookURL := ""
	if customURL, err := db.GetSystemConfig(r.Context(), "agent_webhook_url"); err == nil && customURL != "" {
		webhookURL = customURL
	}
	if webhookURL == "" {
		webhookURL = config.SecretString("SAFE_ZONE_AGENT_WEBHOOK_URL", "")
	}

	if webhookURL == "" {
		httputil.WriteError(w, http.StatusBadRequest, "No webhook URL configured")
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
		httputil.WriteError(w, http.StatusInternalServerError, "failed to marshal payload: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to create request: "+err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"status": "error",
			"error":  fmt.Sprintf("Webhook returned status %d", resp.StatusCode),
		})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
	})
}
