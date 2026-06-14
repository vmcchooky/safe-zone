package httputil

import (
	"context"
	"net/http"
	"time"

	"safe-zone/internal/logjson"
	"safe-zone/internal/observability"
	"safe-zone/internal/serve"
)

func LogRequests(service string, metrics *observability.Registry) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panicObserved := false
			ctx := context.WithValue(r.Context(), serve.ObservedPanicKey, &panicObserved)
			r = r.WithContext(ctx)
			started := time.Now()
			recorder := &StatusLoggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(recorder, r)
			if metrics != nil {
				if p, ok := r.Context().Value(serve.ObservedPanicKey).(*bool); !ok || !*p {
					metrics.Observe(r.Method, r.URL.Path, recorder.statusCode, recorder.bytesWritten, time.Since(started))
				}
			}
			clientInfo := ExtractClientInfo(r)
			logjson.Info("http request", map[string]any{
				"service":     service,
				"request_id":  serve.RequestID(r.Context()),
				"method":      SanitizeLog(r.Method),
				"path":        SanitizeLog(r.URL.Path),
				"status":      recorder.statusCode,
				"bytes":       recorder.bytesWritten,
				"duration_ms": time.Since(started).Milliseconds(),
				"client_ip":   clientInfo.IP,
				"client_id":   clientInfo.ClientID,
			})
		})
	}
}

type StatusLoggingResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (w *StatusLoggingResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *StatusLoggingResponseWriter) Write(p []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytesWritten += n
	return n, err
}
