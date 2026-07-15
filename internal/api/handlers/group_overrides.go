package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/store"
)

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
