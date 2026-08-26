package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"safe-zone/internal/api/httputil"
)

// urlMLFeedbackRequest carries an opaque caller-generated event ID plus a
// coarse label. No raw URL, query, redirect target or credential is accepted
// or persisted; the server correlates via HMAC fingerprints of the event ID.
type urlMLFeedbackRequest struct {
	EventID string `json:"event_id"`
	Label   string `json:"label"`
}

// URLMLFeedbackHandler records privacy-safe label feedback for earlier URL
// shadow observations. Labels only affect aggregate calibration counters;
// they never change any verdict.
func (h *Handler) URLMLFeedbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	defer func() { _ = r.Body.Close() }()
	var req urlMLFeedbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	eventID := strings.TrimSpace(req.EventID)
	label := strings.ToLower(strings.TrimSpace(req.Label))
	if eventID == "" || len(eventID) > 256 {
		httputil.WriteError(w, http.StatusBadRequest, "event_id is required")
		return
	}
	if label != "benign" && label != "malicious" {
		httputil.WriteError(w, http.StatusBadRequest, "label must be benign or malicious")
		return
	}
	recorded, reason := h.Risk.RecordURLFeedback(eventID, label)
	status := http.StatusOK
	switch reason {
	case "unsupported":
		status = http.StatusNotImplemented
	case "persistence_error":
		// Fail closed for feedback only: the durable store rejected the label,
		// so it is not silently accepted or downgraded to ephemeral state.
		status = http.StatusServiceUnavailable
	}
	httputil.WriteJSON(w, status, map[string]any{
		"recorded": recorded,
		"reason":   reason,
	})
}
