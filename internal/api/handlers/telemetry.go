package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/store"
)

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

func (h *Handler) TelemetryStatsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	period := r.URL.Query().Get("period")
	switch period {
	case "7d", "30d":
		// valid periods
	case "24h", "":
		fallthrough
	default:
		period = "24h"
	}

	stats, err := h.Risk.TelemetryStats(period)
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
