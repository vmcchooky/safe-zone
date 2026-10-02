package httputil

import (
	"net/http"

	"safe-zone/internal/logjson"
	"safe-zone/internal/serve"
)

// WriteInternalError scrubs an internal failure whose status is endpoint-specific
// and cannot be derived from a sentinel.
//
// It exists because WriteStoreError is the right answer for a store failure and the
// wrong answer for the rest. Password hashing, JSON marshalling, and building an
// outbound request fail for reasons unrelated to the database, but they still
// produced a response body containing the raw error: a bcrypt cost misconfiguration,
// a marshalling type error, or a URL parse failure, all of which tell an attacker or
// a confused operator something about the server's internals that the log already
// records and the client does not need.
//
// The status is passed in rather than derived, because these sites genuinely differ.
// An upstream OSINT failure is a 502; a failed marshal is a 500. What they share is
// the disclosure, not the status.
//
// Only errors describing the caller's own request may be echoed verbatim. Those do not
// come through here: a handler that validated the request already knows the difference
// and returns 400 with its own message before reaching an internal failure.
func WriteInternalError(w http.ResponseWriter, r *http.Request, status int, err error, publicMessage string) {
	if err == nil {
		WriteError(w, status, publicMessage)
		return
	}

	logjson.Error("internal error while serving request", map[string]any{
		"service":    "api",
		"path":       r.URL.Path,
		"method":     r.Method,
		"status":     status,
		"public":     publicMessage,
		"error":      err.Error(),
		"request_id": serve.RequestID(r.Context()),
	})
	WriteError(w, status, publicMessage)
}
