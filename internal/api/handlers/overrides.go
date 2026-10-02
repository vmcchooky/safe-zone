package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"safe-zone/internal/analysis"
	"safe-zone/internal/api/httputil"
	"safe-zone/internal/store"
)

type overrideRequest struct {
	Domain string `json:"domain"`
	Action string `json:"action"`
	Reason string `json:"reason"`
}

type falsePositiveReviewRequest struct {
	ReportID       int64  `json:"report_id,omitempty"`
	Domain         string `json:"domain"`
	Reason         string `json:"reason"`
	Source         string `json:"source,omitempty"`
	PreviousAction string `json:"previous_action,omitempty"`
}

func (h *Handler) OverridesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		action := strings.TrimSpace(r.URL.Query().Get("action"))
		// An unrecognised filter is rejected rather than ignored. Silently
		// dropping it returned the whole table, so a typo read as "no filter
		// matched" instead of "you asked for something that does not exist".
		if action != "" && action != "allow" && action != "block" {
			httputil.WriteError(w, http.StatusBadRequest, `action must be "allow" or "block"`)
			return
		}
		overrides, err := h.Risk.ListOverrides(r.Context(), action)
		if err != nil {
			httputil.WriteStoreError(w, r, err, "failed to list overrides")
			return
		}
		if overrides == nil {
			overrides = []store.Override{}
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"items": overrides})

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 10240)
		defer func() { _ = r.Body.Close() }()
		var req overrideRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		req.Domain = strings.TrimSpace(req.Domain)
		if req.Domain == "" || req.Action == "" {
			httputil.WriteError(w, http.StatusBadRequest, "domain and action are required")
			return
		}
		if err := h.Risk.UpsertOverride(r.Context(), req.Domain, req.Action, req.Reason); err != nil {
			httputil.WriteStoreError(w, r, err, "failed to save override")
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "domain": req.Domain, "action": req.Action})

	case http.MethodDelete:
		domain := strings.TrimSpace(r.URL.Query().Get("domain"))
		if domain == "" {
			httputil.WriteError(w, http.StatusBadRequest, "domain query parameter is required")
			return
		}
		if err := h.Risk.DeleteOverride(r.Context(), domain); err != nil {
			httputil.WriteStoreError(w, r, err, "failed to delete override")
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
	defer func() { _ = r.Body.Close() }()

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
	if len(req.Reason) < 8 {
		httputil.WriteError(w, http.StatusBadRequest, "review reason must contain at least 8 characters")
		return
	}
	if req.ReportID < 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid report ID")
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

	db := h.Risk.StoreDB()
	if db == nil || !db.Enabled() {
		httputil.WriteError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	reviewer := h.adminUsername()
	if identity, ok := authIdentityFromRequest(r); ok && strings.TrimSpace(identity.Username) != "" {
		reviewer = identity.Username
	}
	resolvedReports, err := db.ApproveFalsePositive(
		r.Context(),
		req.ReportID,
		normalized,
		reviewReason,
		req.Reason,
		reviewer,
		req.Source,
		req.PreviousAction,
	)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrBlockReportNotFound):
			httputil.WriteError(w, http.StatusNotFound, "block report not found")
		case errors.Is(err, store.ErrBlockReportDomainMismatch):
			httputil.WriteError(w, http.StatusConflict, "report domain does not match review domain")
		default:
			// The two sentinels above are the operator-actionable outcomes and keep
			// their own status. Everything else here came out of the store and used
			// to be echoed into the body, which could carry a file path or a SQL
			// fragment.
			httputil.WriteStoreError(w, r, err, "failed to apply the false-positive review")
		}
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":           "ok",
		"domain":           normalized,
		"action":           "allow",
		"reason":           reviewReason,
		"reviewed_by":      reviewer,
		"resolved_reports": resolvedReports,
	})
}
