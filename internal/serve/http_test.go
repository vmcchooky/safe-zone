package serve_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"safe-zone/internal/serve"
)

type mockMetricsObserver struct {
	mu       sync.Mutex
	method   string
	path     string
	status   int
	observed bool
}

func (m *mockMetricsObserver) Observe(method, path string, statusCode int, bytesWritten int, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.method = method
	m.path = path
	m.status = statusCode
	m.observed = true
}

func (m *mockMetricsObserver) GetResult() (string, string, int, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.method, m.path, m.status, m.observed
}

func TestRecoveryMiddleware_JSON(t *testing.T) {
	// Handler giả lập xảy ra panic nghiêm trọng
	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("something went critically wrong")
	})

	mockObs := &mockMetricsObserver{}
	recovery := serve.Recovery(panicHandler, mockObs)

	// Tạo request giả lập dạng API
	req := httptest.NewRequest("GET", "/v1/analyze", nil)
	w := httptest.NewRecorder()

	recovery.ServeHTTP(w, req)

	// Kiểm tra Status Code phải là 500 Internal Server Error
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}

	// Kiểm tra Content-Type phải là application/json
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got '%s'", contentType)
	}

	// Giải nén body JSON và xác thực cấu trúc
	var respBody map[string]string
	if err := json.NewDecoder(w.Body).Decode(&respBody); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if respBody["error"] != "internal server error" {
		t.Errorf("expected error message 'internal server error', got '%s'", respBody["error"])
	}

	// Kiểm tra metrics đã ghi nhận lỗi 500 thành công
	method, path, status, observed := mockObs.GetResult()
	if !observed {
		t.Error("metrics observer was not called")
	}
	if method != "GET" || path != "/v1/analyze" || status != 500 {
		t.Errorf("invalid metrics observed: method=%s, path=%s, status=%d", method, path, status)
	}
}

func TestRecoveryMiddleware_HTML(t *testing.T) {
	// Handler giả lập xảy ra panic trong Dashboard
	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("database connection failure")
	})

	mockObs := &mockMetricsObserver{}
	recovery := serve.Recovery(panicHandler, mockObs)

	// Tạo request yêu cầu HTML
	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9")
	w := httptest.NewRecorder()

	recovery.ServeHTTP(w, req)

	// Kiểm tra Status Code phải là 500
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}

	// Kiểm tra Content-Type phải chứa text/html
	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("expected Content-Type to contain 'text/html', got '%s'", contentType)
	}

	// Kiểm tra xem body KHÔNG chứa thông tin lỗi nội bộ (bảo mật)
	bodyStr := w.Body.String()
	if strings.Contains(bodyStr, "database connection failure") {
		t.Error("HTML response must NOT leak internal error details")
	}
	if !strings.Contains(bodyStr, "Hệ Thống Gặp Sự Cố") {
		t.Error("HTML response does not contain error title")
	}
	if !strings.Contains(bodyStr, "Mã sự cố") {
		t.Error("HTML response should contain request ID reference")
	}
	if !strings.Contains(bodyStr, "Quay Lại Dashboard") {
		t.Error("HTML response does not contain back to dashboard button")
	}

	// Kiểm tra metrics đã đồng bộ thành công
	_, _, status, observed := mockObs.GetResult()
	if !observed {
		t.Error("metrics observer was not called")
	}
	if status != 500 {
		t.Errorf("expected status 500 in metrics, got %d", status)
	}
}
