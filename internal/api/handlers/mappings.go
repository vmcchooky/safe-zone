package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/store"
)

type mappingRequest struct {
	MappingType string `json:"mapping_type"`
	Value       string `json:"value"`
	GroupID     int64  `json:"group_id"`
}

func (h *Handler) MappingsHandler(w http.ResponseWriter, r *http.Request) {
	db := h.Risk.StoreDB()
	if db == nil || !db.Enabled() {
		httputil.WriteError(w, http.StatusServiceUnavailable, "store is unavailable")
		return
	}

	switch r.Method {
	case http.MethodGet:
		mappings, err := db.ListMappings(r.Context())
		if err != nil {
			httputil.WriteStoreError(w, r, err, "failed to list mappings")
			return
		}
		if mappings == nil {
			mappings = []store.ClientMapping{}
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"items": mappings})

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 10240)
		defer func() { _ = r.Body.Close() }()
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
			// A store failure must not be reported as a bad request: that tells
			// the operator their input is wrong when the input was fine.
			if httputil.StoreUnavailable(err) {
				httputil.WriteStoreError(w, r, err, "failed to create mapping")
				return
			}
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
			if errors.Is(err, store.ErrMappingNotFound) {
				httputil.WriteError(w, http.StatusNotFound, "mapping not found")
				return
			}
			httputil.WriteStoreError(w, r, err, "failed to delete mapping")
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
