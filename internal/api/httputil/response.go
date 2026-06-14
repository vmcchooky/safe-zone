package httputil

import (
	"encoding/json"
	"net/http"

	"safe-zone/internal/logjson"
)

func WriteJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		logjson.Error("write response failed", map[string]any{
			"error": err.Error(),
		})
	}
}

func WriteError(w http.ResponseWriter, statusCode int, message string) {
	WriteJSON(w, statusCode, map[string]string{"error": message})
}
