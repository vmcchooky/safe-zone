# Danh sách đầu việc (Task Checklist) - Tích hợp AI Cục bộ & AI Đám mây Lai (Hybrid/Fallback AI Integration)

Mục tiêu: Xây dựng interface AI đa nhà cung cấp hỗ trợ cả Gemini API và Ollama cục bộ với cơ chế chuyển đổi chế độ và tự động fallback.

- [x] **Giai đoạn 1: Chuẩn hóa Interface AI (`internal/ai`)**
  - [x] 1.1 Định nghĩa interface `Provider` trong file mới `internal/ai/provider.go`.
  - [x] 1.2 Tách logic Gemini API hiện tại sang struct `GeminiClient` implementing `Provider` trong `internal/ai/client.go`.
  - [x] 1.3 Triển khai struct `OllamaClient` tương thích hoàn toàn qua HTTP API cục bộ `/api/generate` trong file mới `internal/ai/ollama.go`.
  - [x] 1.4 Refactor struct `Client` đóng vai trò là một **AI Manager** quản lý và điều phối động các Sub-client dựa trên chế độ cấu hình (`AIProvider`).
  - [x] 1.5 Cung cấp hàm tạo mới `NewClient(cfg Config) *Client` và duy trì khả năng tương thích ngược của hàm cũ `New(...)`.

- [x] **Giai đoạn 2: Cập nhật Cấu hình & Tích hợp Risk Service (`internal/risk`)**
  - [x] 2.1 Cập nhật struct `Options` trong `internal/risk/service.go` để nhận thêm các cấu hình cho Ollama và AI Provider.
  - [x] 2.2 Cập nhật `NewService` trong `internal/risk/service.go` gọi `ai.NewClient(...)` và xử lý fallback cấu hình tương thích ngược.
  - [x] 2.3 Ánh xạ các biến môi trường mới (`SAFE_ZONE_AI_PROVIDER`, `SAFE_ZONE_OLLAMA_*`) từ `.env` vào hàm khởi tạo `NewServiceFromEnv()` trong `internal/risk/env.go`.
  - [x] 2.4 Thêm các cấu hình mẫu của Ollama vào file mẫu `.env.example`.

- [x] **Giai đoạn 3: Viết và Chạy Kiểm thử (Tests)**
  - [x] 3.1 Bổ sung suite kiểm thử `internal/ai/ollama_test.go` giả lập Ollama HTTP Server để kiểm chứng khả năng phân tích tên miền.
  - [x] 3.2 Bổ sung suite kiểm thử `internal/ai/hybrid_test.go` xác thực cơ chế fallback tự động sang Gemini khi Ollama bị lỗi/treo.
  - [x] 3.3 Đảm bảo toàn bộ test suite `go test -race -v -count=1 ./internal/ai/...` and `./internal/risk/...` vượt qua thành công.
  - [x] 3.4 Đảm bảo biên dịch dự án không có bất kỳ lỗi nào.

- [x] **Giai đoạn 4: Tài liệu Hướng dẫn & Lưu vết**
  - [/] 4.1 Cập nhật file báo cáo kết quả `walkthrough.md` trong thư mục tài liệu `docs/specs/local-ai-module/`.
