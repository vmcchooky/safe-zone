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
		httputil.WriteStoreError(w, r, err, "failed to list telemetry")
		return
	}
	if entries == nil {
		entries = []store.TelemetryEntry{}
	}

	// The read-only guest account exists for dashboard visibility, not for
	// enumerating which clients resolved through this server. Every row is
	// written from the fully anonymous /v1/analyze path, so the recent feed
	// carries the IP and client id of every DoH client. Strip both fields
	// for any caller that is not an administrator; the fields are
	// omitempty, so they disappear from the payload entirely.
	//
	// redacted reports the policy applied to this response, not whether any
	// row happened to change. Deriving it from "did we modify something" made
	// it false for an empty page and false for a page whose rows happen to
	// carry no identifier, which is exactly when a client cannot tell whether
	// it was filtered.
	identity, ok := authIdentityFromRequest(r)
	isAdmin := ok && identity.isAdmin()
	if !isAdmin {
		redactTelemetryIdentities(entries)
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"items":    entries,
		"filter":   filter,
		"redacted": !isAdmin,
	})
}

// redactTelemetryIdentities clears the per-client identifier fields in place.
// It is a no-op for administrators and for an empty page.
func redactTelemetryIdentities(entries []store.TelemetryEntry) {
	for i := range entries {
		entries[i].ClientIP = ""
		entries[i].ClientID = ""
	}
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
		httputil.WriteStoreError(w, r, err, "failed to compute telemetry stats")
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
