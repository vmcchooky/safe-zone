package handlers

import (
	"encoding/json"
	"net/http"

	"safe-zone/internal/api/httputil"
)

func (h *Handler) AnalysisConfigHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		httputil.WriteJSON(w, http.StatusOK, h.Risk.GetAnalysisConfig())
	case http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, 32768)
		defer r.Body.Close()
		cfg := h.Risk.GetAnalysisConfig()
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&cfg); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid analysis config JSON: "+err.Error())
			return
		}
		if err := h.Risk.UpdateAnalysisConfig(r.Context(), cfg); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		httputil.WriteJSON(w, http.StatusOK, h.Risk.GetAnalysisConfig())
	default:
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) AnalysisConfigResetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cfg, err := h.Risk.ResetAnalysisConfig(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	httputil.WriteJSON(w, http.StatusOK, cfg)
}
