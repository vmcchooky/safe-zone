package httputil

import (
	"bytes"
	"encoding/json"
	"net/http"

	"safe-zone/internal/logjson"
)

// encodeFailureBody is served when a payload cannot be marshalled. It is a
// valid JSON document on purpose: a client that only knows how to parse JSON
// must not fall back to guessing at a truncated body.
const encodeFailureBody = `{"error":"failed to encode response"}`

// WriteJSON marshals payload and writes it with the given status.
//
// The body is encoded into a buffer before the status line is written.
// Streaming the encoder straight to the ResponseWriter put the header on the
// wire first, so a payload that fails to marshal was discovered too late: the
// client had already received HTTP 200 followed by a truncated body and had
// no way to tell the response was incomplete. A non-finite float anywhere in
// a payload triggers this — json cannot represent NaN or +Inf — and one such
// value was reachable through the URL-ML drift PSI on /v1/status.
//
// Large streaming responses (the log export) deliberately do not come through
// here; they write text/plain directly.
func WriteJSON(w http.ResponseWriter, statusCode int, payload any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(payload); err != nil {
		logjson.Error("encode response failed", map[string]any{
			"error":         err.Error(),
			"intended_code": statusCode,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(encodeFailureBody))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if _, err := w.Write(buf.Bytes()); err != nil {
		logjson.Error("write response failed", map[string]any{
			"error": err.Error(),
		})
	}
}

func WriteError(w http.ResponseWriter, statusCode int, message string) {
	WriteJSON(w, statusCode, map[string]string{"error": message})
}
