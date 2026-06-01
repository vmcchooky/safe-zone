package serve

import (
	"context"
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

// getGlassmorphicErrorHTML sinh ra giao diện lỗi HTML phong cách Glassmorphic cực kỳ hiện đại
func getGlassmorphicErrorHTML(requestID string) string {
	return `<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>500 - Lỗi Hệ Thống | Safe Zone</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-gradient: linear-gradient(135deg, #090d16 0%, #111827 50%, #1e1b4b 100%);
            --glass-bg: rgba(17, 24, 39, 0.55);
            --glass-border: rgba(255, 255, 255, 0.08);
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --accent-color: #ef4444;
            --accent-glow: rgba(239, 68, 68, 0.25);
            --btn-bg: linear-gradient(90deg, #ef4444 0%, #dc2626 100%);
            --btn-hover-glow: rgba(239, 68, 68, 0.4);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Outfit', sans-serif;
        }

        body {
            background: var(--bg-gradient);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--text-primary);
            overflow: hidden;
            position: relative;
        }

        /* Ambient background glow elements */
        body::before, body::after {
            content: "";
            position: absolute;
            width: 350px;
            height: 350px;
            border-radius: 50%;
            filter: blur(120px);
            z-index: 0;
            opacity: 0.4;
        }

        body::before {
            background: #ef4444;
            top: 15%;
            left: 20%;
            animation: float-slow 15s infinite alternate;
        }

        body::after {
            background: #4f46e5;
            bottom: 15%;
            right: 20%;
            animation: float-slow 12s infinite alternate-reverse;
        }

        @keyframes float-slow {
            0% { transform: translate(0, 0) scale(1); }
            100% { transform: translate(40px, 30px) scale(1.15); }
        }

        .container {
            position: relative;
            z-index: 10;
            width: 100%;
            max-width: 580px;
            padding: 20px;
        }

        .card {
            background: var(--glass-bg);
            backdrop-filter: blur(20px) saturate(180%);
            -webkit-backdrop-filter: blur(20px) saturate(180%);
            border: 1px solid var(--glass-border);
            border-radius: 24px;
            padding: 48px 40px;
            text-align: center;
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.3);
            animation: fade-in-up 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }

        @keyframes fade-in-up {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .icon-container {
            width: 80px;
            height: 80px;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 28px;
            box-shadow: 0 0 25px var(--accent-glow);
            animation: pulse-glow 2s infinite;
        }

        @keyframes pulse-glow {
            0%, 100% {
                box-shadow: 0 0 20px var(--accent-glow);
                border-color: rgba(239, 68, 68, 0.3);
            }
            50% {
                box-shadow: 0 0 35px rgba(239, 68, 68, 0.45);
                border-color: rgba(239, 68, 68, 0.6);
            }
        }

        .icon-container svg {
            width: 38px;
            height: 38px;
            color: var(--accent-color);
        }

        h1 {
            font-size: 2.25rem;
            font-weight: 800;
            margin-bottom: 12px;
            background: linear-gradient(135deg, #fff 0%, #d1d5db 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -0.025em;
        }

        .status-badge {
            display: inline-block;
            padding: 6px 14px;
            background: rgba(239, 68, 68, 0.15);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.25);
            border-radius: 9999px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 24px;
        }

        p {
            font-size: 1.05rem;
            line-height: 1.6;
            color: var(--text-secondary);
            margin-bottom: 32px;
        }

        .error-details {
            background: rgba(0, 0, 0, 0.25);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 16px;
            font-family: monospace;
            font-size: 0.85rem;
            color: #fda4af;
            text-align: left;
            overflow-x: auto;
            margin-bottom: 32px;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 120px;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 14px 28px;
            background: var(--btn-bg);
            color: #fff;
            border: none;
            border-radius: 12px;
            font-size: 1rem;
            font-weight: 600;
            text-decoration: none;
            cursor: pointer;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px var(--btn-hover-glow);
            filter: brightness(1.1);
        }

        .btn:active {
            transform: translateY(0);
        }

        .btn svg {
            margin-right: 8px;
            width: 18px;
            height: 18px;
        }

        .footer {
            margin-top: 32px;
            font-size: 0.8rem;
            color: rgba(156, 163, 175, 0.5);
            letter-spacing: 0.025em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="icon-container">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
            </div>
            <h1>Hệ Thống Gặp Sự Cố</h1>
            <div class="status-badge">HTTP 500 Internal Error</div>
            <p>Đã xảy ra lỗi runtime không mong muốn trong quá trình xử lý yêu cầu của bạn. Sự cố đã được tự động ghi nhận và chuyển tới đội ngũ kỹ thuật để khắc phục.</p>
            
            			<div class="error-details">Mã sự cố: ` + htmlEscape(requestID) + `
Vui lòng cung cấp mã này khi liên hệ hỗ trợ kỹ thuật.</div>

            <a href="/dashboard" class="btn">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M10 19l-7-7m0 0l7-7m-7 7h18" />
                </svg>
                Quay Lại Dashboard
            </a>

            <div class="footer">SAFE ROAD SECURITY SYSTEM &copy; 2026</div>
        </div>
    </div>
</body>
</html>`
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}
