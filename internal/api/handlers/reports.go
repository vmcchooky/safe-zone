package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/store"
)

type updateReportStatusRequest struct {
	ID     int64  `json:"id"`
	Status string `json:"status"`
	Reason string `json:"reason"`
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
	if status != "" && status != "pending" && status != "resolved" && status != "rejected" {
		httputil.WriteError(w, http.StatusBadRequest, "invalid report status filter")
		return
	}

	db := h.Risk.StoreDB()
	if db == nil || !db.Enabled() {
		httputil.WriteError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	filter := store.BlockReportFilter{
		Status: status,
		Query:  query,
	}
	reports, err := db.ListBlockReportsFiltered(r.Context(), filter, limit, offset)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to list reports: "+err.Error())
		return
	}
	total, err := db.CountBlockReportsFiltered(r.Context(), filter)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to count reports: "+err.Error())
		return
	}
	if reports == nil {
		reports = []store.BlockReport{}
	}
	counts, err := db.CountBlockReportsByStatus(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to count report statuses: "+err.Error())
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"reports": reports,
		"total":   total,
		"counts":  counts,
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
	defer func() { _ = r.Body.Close() }()

	var req updateReportStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	req.Status = strings.TrimSpace(req.Status)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.ID <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid ID")
		return
	}
	if req.Status != "resolved" && req.Status != "rejected" {
		httputil.WriteError(w, http.StatusBadRequest, "status must be resolved or rejected")
		return
	}
	if len(req.Reason) < 8 {
		httputil.WriteError(w, http.StatusBadRequest, "review reason must contain at least 8 characters")
		return
	}

	db := h.Risk.StoreDB()
	if db == nil || !db.Enabled() {
		httputil.WriteError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	reviewer := "admin"
	if identity, ok := authIdentityFromRequest(r); ok && strings.TrimSpace(identity.Username) != "" {
		reviewer = identity.Username
	}
	resolutionAction := "resolve"
	if req.Status == "rejected" {
		resolutionAction = "reject"
	}
	if err := db.ReviewBlockReport(r.Context(), req.ID, req.Status, req.Reason, reviewer, resolutionAction); err != nil {
		if errors.Is(err, store.ErrBlockReportNotFound) {
			httputil.WriteError(w, http.StatusNotFound, "block report not found")
			return
		}
		httputil.WriteError(w, http.StatusInternalServerError, "failed to update report status: "+err.Error())
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{
		"status":            "ok",
		"decision":          req.Status,
		"resolution_action": resolutionAction,
	})
}
