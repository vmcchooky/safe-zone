package serve

import (
	"context"
	"net/http"

	"safe-zone/internal/correlation"
)

func WithRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := correlation.SanitizeID(r.Header.Get("X-Request-ID"))
		if requestID == "" {
			requestID = correlation.NewID("req")
		}

		w.Header().Set("X-Request-ID", requestID)
		ctx := correlation.WithRequestID(r.Context(), requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func RequestID(ctx context.Context) string {
	return correlation.RequestID(ctx)
}
