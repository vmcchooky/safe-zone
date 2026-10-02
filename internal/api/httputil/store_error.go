package httputil

import (
	"errors"
	"net/http"

	"safe-zone/internal/logjson"
	"safe-zone/internal/serve"
	"safe-zone/internal/store"
)

// WriteStoreError maps a persistence failure to a status code and writes a
// message that does not leak internals.
//
// Two problems it solves, both of which the API had throughout its life:
//
//   - Status. An unusable store is a 503 "not available", not a 500 "server
//     error". The two tell an operator completely different things.
//   - Disclosure. Handlers interpolated err.Error() straight into the response,
//     so internal messages — file paths, SQL fragments, and the store's own
//     "sqlite store disabled" — reached the client.
//
// The detail still goes to the log, correlated with the request, so an operator
// can diagnose it from the service side.
//
// This is the single mapping point on purpose. Fixing it per handler leaves the
// behaviour half-changed depending on which file a future edit lands in, which is
// how the two problems survived being noticed in the first place.
func WriteStoreError(w http.ResponseWriter, r *http.Request, err error, publicMessage string) {
	if err == nil {
		WriteError(w, http.StatusInternalServerError, publicMessage)
		return
	}

	if errors.Is(err, store.ErrDisabled) {
		logjson.Warn("store unavailable while serving request", map[string]any{
			"service":    "api",
			"path":       r.URL.Path,
			"method":     r.Method,
			"public":     publicMessage,
			"error":      err.Error(),
			"request_id": serve.RequestID(r.Context()),
		})
		WriteError(w, http.StatusServiceUnavailable, publicMessage)
		return
	}

	logjson.Error("store operation failed while serving request", map[string]any{
		"service":    "api",
		"path":       r.URL.Path,
		"method":     r.Method,
		"public":     publicMessage,
		"error":      err.Error(),
		"request_id": serve.RequestID(r.Context()),
	})
	WriteError(w, http.StatusInternalServerError, publicMessage)
}

// StoreUnavailable reports whether err means the store exists but cannot be
// used. Handlers that need a bespoke status for a disabled store can branch on
// it without going through WriteStoreError.
func StoreUnavailable(err error) bool {
	return errors.Is(err, store.ErrDisabled)
}
