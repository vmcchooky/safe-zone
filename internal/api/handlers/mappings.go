package handlers

import (
	"encoding/json"
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
