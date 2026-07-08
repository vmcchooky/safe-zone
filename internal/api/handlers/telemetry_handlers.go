package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/store"
)

type updateReportStatusRequest struct {
	ID     int64  `json:"id"`
	Status string `json:"status"`
}

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
