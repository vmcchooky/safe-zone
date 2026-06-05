package serve

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"safe-zone/internal/logjson"
)

// MetricsObserver định nghĩa interface lỏng lẻo (duck typing) để quan sát chỉ số HTTP.
// Điều này giúp tránh hiện tượng vòng lặp import (circular dependency) với package observability.
type MetricsObserver interface {
	Observe(method, path string, statusCode int, bytesWritten int, duration time.Duration)
}

type ContextKey string

const ObservedPanicKey ContextKey = "observed_panic"

//go:embed error500.html
var error500HTML string

func RunHTTPServer(server *http.Server, shutdownTimeout time.Duration) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case sig := <-sigCh:
		logjson.Info("shutdown requested", map[string]any{"signal": sig.String()})
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return server.Shutdown(ctx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}

		return err
	}
}

// Recovery là middleware phục hồi lỗi Runtime (panic) cho các HTTP handler,
// ngăn chặn sập server và trả về phản hồi lỗi JSON hoặc HTML Glassmorphism đẹp mắt.
func Recovery(next http.Handler, obs MetricsObserver) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		defer func() {
			if rec := recover(); rec != nil {
				// 1. Ghi nhận lỗi và ngăn xếp cuộc gọi (stack trace) chi tiết để điều tra lỗi
				stack := make([]byte, 4096)
				length := runtime.Stack(stack, false)
				logjson.Error("panic recovered", map[string]any{
					"request_id": RequestID(r.Context()),
					"path":       r.URL.Path,
					"panic":      fmt.Sprintf("%v", rec),
					"stack":      string(stack[:length]),
				})

				// 2. Đánh dấu panic đã được ghi nhận để tránh metrics trùng lặp ở logRequests.
				if p, ok := r.Context().Value(ObservedPanicKey).(*bool); ok {
					*p = true
				}

				// 3. Tự động phát hiện định dạng trả về dựa trên header Accept hoặc URL Path
				accept := r.Header.Get("Accept")
				isHTML := strings.Contains(accept, "text/html") || strings.HasPrefix(r.URL.Path, "/dashboard")

				reqID := RequestID(r.Context())
				var bytesWritten int
				if isHTML {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.WriteHeader(http.StatusInternalServerError)
					htmlContent := getGlassmorphicErrorHTML(reqID)
					n, _ := w.Write([]byte(htmlContent))
					bytesWritten = n
				} else {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					jsonResponse := `{"error":"internal server error"}`
					n, _ := w.Write([]byte(jsonResponse))
					bytesWritten = n
				}

				// 4. Ghi nhận metrics sự cố vào hệ thống Telemetry/Metrics Registry
				if obs != nil {
					obs.Observe(r.Method, r.URL.Path, http.StatusInternalServerError, bytesWritten, time.Since(started))
				}
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// getGlassmorphicErrorHTML renders the static panic recovery page with a request reference.
func getGlassmorphicErrorHTML(requestID string) string {
	return strings.ReplaceAll(error500HTML, "{{REQUEST_ID}}", htmlEscape(requestID))
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}
