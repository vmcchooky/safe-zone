package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/store"
)

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
