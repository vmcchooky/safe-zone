# Kế hoạch tích hợp AI cục bộ & AI đám mây lai (Hybrid/Fallback Local & Cloud AI Integration Plan)

Kế hoạch này thiết lập một cấu trúc AI linh hoạt (Hybrid AI Provider) cho Safe Zone. Cho phép người dùng chuyển đổi tự do giữa **Cloud AI (Gemini API - Miễn phí, 0MB RAM phát sinh)** và **Local AI (Ollama - Bảo mật tối đa, chạy offline hoàn toàn trên RAM server)** hoặc cấu hình chạy **Hybrid (Ollama trước, nếu lỗi tự động fallback sang Gemini)**.

Điều này giải quyết hoàn hảo bài toán tối ưu hóa chi phí VPS của bạn, cho phép vận hành trơn tru trên VPS RAM thấp (1GB - 2GB RAM) bằng Gemini API trước, và sẵn sàng kích hoạt AI offline (Ollama) khi có ngân sách nâng cấp cấu hình sau này.

---

## User Review Required

> [!IMPORTANT]
> **Các chế độ hoạt động mới cấu hình linh hoạt qua file `.env`:**
> 1. **`none`:** Tắt hoàn toàn bộ lọc AI (chỉ chạy bằng bộ phân tích heuristics lexical, threat feed, whitelist, admin overrides và TLS/WHOIS).
> 2. **`gemini` (Mặc định):** Sử dụng Gemini API (yêu cầu `SAFE_ZONE_GEMINI_API_KEY`). **Hoàn hảo cho VPS giá rẻ** vì chỉ gọi HTTP API từ xa, không tiêu tốn thêm RAM máy chủ.
> 3. **`ollama`:** Sử dụng mô hình cục bộ chạy qua Ollama trên máy chủ (ví dụ: `gemma2:2b`, `llama3.2:1b`). **Bảo mật tuyệt đối, không cần internet**.
> 4. **`hybrid`:** Ưu tiên gọi Ollama cục bộ. Nếu Ollama chưa khởi động, quá tải hoặc phản hồi chậm (Timeout), hệ thống sẽ tự động fallback sang Gemini API để đảm bảo dịch vụ thông suốt.

---

## Proposed Changes

### 1. AI Package (`internal/ai`)

#### [NEW] [ollama.go](file:///D:/Quorix/services/safe-zone/internal/ai/ollama.go)
-   Triển khai struct `OllamaClient` tương thích hoàn toàn để gọi API của Ollama cục bộ qua endpoint `POST /api/generate`.
-   Sử dụng tính năng xuất JSON định dạng cấu trúc (`"format": "json"`) có sẵn của Ollama để lấy về phản hồi JSON chuẩn có cấu trúc:
    ```json
    {"verdict": "SAFE|SUSPICIOUS|MALICIOUS", "confidence": 0.0-1.0, "category": "...", "reason": "..."}
    ```
-   Tích hợp Timeout cục bộ riêng cho Ollama để đảm bảo phản hồi nhanh chóng (mặc định 5 giây).

#### [NEW] [provider.go](file:///D:/Quorix/services/safe-zone/internal/ai/provider.go)
-   Định nghĩa interface `Provider` để chuẩn hóa các client AI:
    ```go
    type Provider interface {
        Refine(ctx context.Context, domain string, current analysis.Result) (analysis.Result, error)
        Enabled() bool
    }
    ```

#### [MODIFY] [client.go](file:///D:/Quorix/services/safe-zone/internal/ai/client.go)
-   Tách logic hiện tại của Gemini sang struct `GeminiClient` implementing `Provider`.
-   Cập nhật struct `Client` trở thành một **AI Manager** quản lý động các Sub-client (`GeminiClient`, `OllamaClient`) dựa trên chế độ `ProviderType` cấu hình.
-   Thêm struct `Config` và hàm tạo `NewClient(cfg Config) *Client`.
-   Giữ nguyên hàm tạo cũ `New(baseURL, apiKey, model, timeout)` để đảm bảo khả năng tương thích ngược 100% với các test suite hiện tại mà không phải sửa mã nguồn test cũ.

---

### 2. Risk Package (`internal/risk`)

#### [MODIFY] [service.go](file:///D:/Quorix/services/safe-zone/internal/risk/service.go)
-   Mở rộng struct `Options` để nhận thêm các cấu hình cho Ollama và Provider Type (`AIProvider`, `OllamaBaseURL`, `OllamaModel`, `OllamaTimeout`).
-   Cập nhật `NewService` sử dụng hàm khởi tạo AI thông minh mới `ai.NewClient(...)` và có fallback tự động nếu cấu hình rỗng (ví dụ: nếu `AIProvider` trống nhưng có `GeminiAPIKey`, tự động gán là `"gemini"`).

#### [MODIFY] [env.go](file:///D:/Quorix/services/safe-zone/internal/risk/env.go)
-   Ánh xạ các biến môi trường mới từ `.env` vào cấu trúc khởi tạo `NewServiceFromEnv()`:
    -   `SAFE_ZONE_AI_PROVIDER` (mặc định: `gemini`)
    -   `SAFE_ZONE_OLLAMA_BASE_URL` (mặc định: `http://localhost:11434`)
    -   `SAFE_ZONE_OLLAMA_MODEL` (mặc định: `gemma2:2b`)
    -   `SAFE_ZONE_OLLAMA_TIMEOUT_MS` (mặc định: `5000`)

---

### 3. Configuration Template

#### [MODIFY] [.env.example](file:///D:/Quorix/services/safe-zone/.env.example)
-   Thêm các tham số cấu hình mẫu của Ollama để hướng dẫn người dùng sử dụng và ghi chú rõ ràng về mức tiêu hao tài nguyên bộ nhớ cho từng chế độ.

---

## Verification Plan

### Automated Tests
-   Bổ dung suite kiểm thử `internal/ai/ollama_test.go` giả lập API của Ollama để kiểm chứng khả năng phân tích tên miền.
-   Bổ sung suite kiểm thử trong `internal/ai/hybrid_test.go` để xác thực cơ chế fallback và cơ chế ưu tiên:
    1.  Test `hybrid` mode gọi Ollama thành công.
    2.  Test `hybrid` mode tự động fallback sang Gemini khi Ollama bị lỗi/tắt.
-   Chạy test suite an toàn đa luồng:
    ```bash
    go test -race -v -count=1 ./internal/ai/...
    go test -race -v -count=1 ./internal/risk/...
    ```

### Manual Verification
-   Kiểm tra việc biên dịch ứng dụng:
    ```bash
    go build ./cmd/dns-resolver
    go build ./cmd/core-api
    ```
