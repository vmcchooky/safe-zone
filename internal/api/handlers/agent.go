package handlers

import (
	"context"
	"net/http"

	"safe-zone/internal/agent"
	"safe-zone/internal/api/httputil"
	"safe-zone/internal/risk"
	"safe-zone/internal/store"
)

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
