# Danh sách đầu việc (Task Checklist) - Advanced Brand Spoofing & Lexical Heuristics

Tiến độ triển khai Hướng 6 về các giải thuật phát hiện giả mạo thương hiệu và Lexical Heuristics nâng cao:

- `[x]` 1. Tích hợp bản đồ Homoglyph và hàm chuẩn hóa `ToSkeleton` trong `internal/analysis/brand.go`
- `[x]` 2. Triển khai thuật toán khoảng cách bàn phím `WeightedLevenshteinDistance` trong `internal/analysis/brand.go`
- `[x]` 3. Nâng cấp logic `CheckBrandSpoofing` hỗ trợ phân tích skeleton, Weighted Levenshtein, và Suspicious TLD Penalty
- `[x]` 4. Bổ sung các test cases nâng cao (Homoglyph, Keyboard typosquatting, TLD Penalty) vào `internal/analysis/brand_test.go`
- `[x]` 5. Chạy toàn bộ unit tests và kiểm tra race condition (`go test -race ./...`)
- `[x]` 6. Cập nhật và lưu trữ hồ sơ tài liệu phát triển chuyên nghiệp (`task.md` và `walkthrough.md`) vào thư mục `docs/specs/advanced-lexical-heuristics/`
