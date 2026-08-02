---
name: writing-docs
description: >
  Hướng dẫn AI agent viết tài liệu nghiên cứu & phát triển (R&D) cho dự án Safe-Zone.
  Kích hoạt khi tạo mới hoặc cập nhật bất kỳ file nào trong docs/research/.
  Đảm bảo văn phong kỹ sư chuyên nghiệp, cấu trúc học thuật, và tuân thủ AGENTS.md Section 5.
---

# Kỹ năng Viết Tài liệu Nghiên cứu & Phát triển — Safe-Zone

> **Phạm vi:** Áp dụng khi AI agent tạo mới hoặc chỉnh sửa bất kỳ file Markdown nào trong `docs/research/`. Đọc kỹ toàn bộ hướng dẫn trước khi viết.

---

## 1. Nguyên tắc Cốt lõi

### 1.1. Giọng văn & Phong cách

- **Vai trò:** Kỹ sư nghiên cứu & phát triển — khách quan, chính xác, có tư duy phản biện.
- **Ngôi:** Ngôi thứ ba (viết "hệ thống sử dụng..." thay vì "chúng tôi sử dụng..." hoặc "tôi dùng...").
- **Ngôn ngữ:** Tiếng Việt. Thuật ngữ kỹ thuật giữ nguyên tiếng Anh khi chưa có dịch chuẩn (ví dụ: "Bloom filter", "TF-IDF", "Platt calibration").

### 1.2. Cân bằng Perplexity & Burstiness

Đan xen tự nhiên giữa câu ngắn (nhấn mạnh kết luận) và câu dài (giải thích logic, chuỗi suy luận). Không băm nhỏ mọi câu thành bullet points — một đoạn văn chặt chẽ 3-5 câu thường truyền đạt ý tốt hơn 10 gạch đầu dòng rời rạc.

**Ví dụ minh họa 3 chiều:**

| Loại | Câu mẫu |
|---|---|
| ❌ AI Cliche | "Có thể nói rằng, LightGBM đóng vai trò quan trọng trong việc phân loại tên miền." |
| ❌ Kịch tính hóa | "LightGBM chính là lá chắn sinh tồn bảo vệ người dùng khỏi nanh vuốt phishing." |
| ✅ Chuẩn kỹ sư | "LightGBM được chọn vì hỗ trợ sparse input native và cho phép inference thuần Go qua thư viện `leaves` mà không cần CGO — giảm phức tạp triển khai trên production." |

---

## 2. Danh sách Cấm (Anti-Patterns)

### 2.1. AI Cliches — Cấm hoàn toàn

| Cụm từ cấm | Thay bằng |
|---|---|
| "Có thể nói rằng" | *(Bỏ, vào thẳng nội dung)* |
| "Nhìn chung" / "Tóm lại" | *(Bỏ, hoặc dùng "Kết quả cho thấy...")* |
| "Đóng vai trò quan trọng" | Mô tả cụ thể vai trò: "xử lý X", "chịu trách nhiệm Y" |
| "Đi sâu vào" (Delve into) | "Phân tích", "Khảo sát" |
| "Điều mấu chốt là" (It is pivotal) | "Yếu tố quyết định là..." hoặc bỏ, viết trực tiếp |
| "Được thiết kế để" | "Thực hiện chức năng..." |
| "Một cách toàn diện" | *(Bỏ — nếu toàn diện thật thì nội dung tự chứng minh)* |

### 2.2. Từ ngữ Tuyệt đối hóa — Cấm

| Cụm từ cấm | Thay bằng |
|---|---|
| "Bảo mật tuyệt đối" | "Giảm thiểu tối đa bề mặt tấn công" |
| "An toàn 100%" | "Đạt tỷ lệ FPR = 0.000000 trên tập kiểm thử N = 44,840" |
| "Parity tuyệt đối" | "Parity trong giới hạn floating-point precision" |
| "Hoàn toàn chính xác" | "Sai số nằm trong ngưỡng dung sai $< 10^{-17}$" |

### 2.3. Từ ngữ Kịch tính hóa — Cấm

| Cụm từ cấm | Thay bằng |
|---|---|
| "Quyền sinh sát" / "Nanh vuốt" | "Quyền kiểm soát", "Mối đe dọa" |
| "Rào chắn sinh tồn" | "Cơ chế bảo vệ", "Lớp phòng thủ" |
| "Đập tan" / "Bóc trần" | "Ngăn chặn", "Phát hiện" |
| "Bòn rút" / "Trục lợi" | "Thu thập trái phép", "Khai thác" |

---

## 3. Cấu trúc Tài liệu Bắt buộc

Mỗi tài liệu trong `docs/research/` phải tuân theo cấu trúc sau. Có thể bỏ section không liên quan nhưng **không được bỏ** các section đánh dấu ★.

```markdown
# [Tiêu đề Tài liệu]

> **Tài liệu Living Document** — Cập nhật đồng bộ mỗi khi có thay đổi.
> Tuân thủ quy tắc tại `.agents/AGENTS.md` Section 5.

## ★ Tóm tắt (Abstract)
<!-- 5-7 câu: bài toán, phương pháp, kết quả chính, trạng thái -->

## Sơ đồ Tổng quan
<!-- Mermaid diagram nếu phù hợp -->

## ★ [Tên Phase/Công việc]

### ★ Mục tiêu (Objectives)
<!-- Mô tả rõ mục tiêu cần đạt -->

### ★ Phương pháp & Lý do (Methodology & Rationale)
<!-- PHẢI có bảng so sánh với alternatives -->
| Quyết định | Phương pháp chọn | Các phương pháp thay thế | Lý do |
|---|---|---|---|

### ★ Cách thức Thực hiện (Implementation Details)
<!-- Ghi rõ: công cụ, scripts, AI agent usage -->
<!-- Nếu dùng AI agent: model, strategy, subagent, voting -->

### ★ Số liệu (Metrics & Results)
<!-- Số liệu cụ thể, có đơn vị, có thể tái kiểm chứng -->

### Liên kết Artifacts
<!-- Đường dẫn tương đối tới files liên quan -->

---

## Lịch sử Thay đổi (Version History)
| Ngày | Thay đổi | Tác giả |
|---|---|---|
```

---

## 4. Phương pháp luận Viết Học thuật

### 4.1. Mô hình P-E-E (Point — Evidence — Explain)

Mỗi đoạn văn tuân theo:
1. **Point (Luận điểm):** Câu đầu tiên — topic sentence rõ ràng.
2. **Evidence (Dẫn chứng):** Số liệu, kết quả thí nghiệm, trích dẫn tiêu chuẩn.
3. **Explain (Giải thích):** Phân tích ý nghĩa, liên hệ bối cảnh, so sánh.

**Ví dụ:**

> Group-disjoint splitting ngăn chặn data leakage giữa các subdomain cùng registrable domain **(P)**. Khi áp dụng hash-based partitioning trên eTLD+1 với seed=42, kết quả cho thấy 0 group overlap giữa tất cả 4 tập (train/val/cal/test) **(E)**. Phương pháp này vượt trội hơn random split hay stratified split vì đảm bảo `login.evil.com` và `pay.evil.com` không xuất hiện ở cả train và test set — một vấn đề phổ biến trong bài toán phân loại tên miền **(Ex)**.

### 4.2. Trích dẫn Tiêu chuẩn

Khi đề cập tiêu chuẩn kỹ thuật, ghi rõ số hiệu:
- DNS-over-HTTPS: RFC 8484
- DNS-over-TLS: RFC 8310
- Public Suffix List: Theo đặc tả Mozilla PSL
- IDNA: UTS #46, RFC 5891

### 4.3. Ghi nhận Phương pháp AI Agent

Khi AI agent tham gia phát triển, ghi rõ trong section "Cách thức Thực hiện":
- **Mô hình sử dụng:** Ví dụ "Gemini 2.5 Flash", "Claude Opus 4"
- **Chiến lược prompt:** Mô tả ngắn cách ra chỉ dẫn
- **Số lượng subagent:** Nếu dùng cơ chế đa agent
- **Cơ chế kiểm soát chất lượng:** Bỏ phiếu đồng thuận, code review, test suite
- **Vai trò con người:** Human-in-the-loop hay fully automated

---

## 5. Bảng Thuật ngữ Chuẩn Safe-Zone

Sử dụng nhất quán các thuật ngữ sau trong toàn bộ tài liệu:

| Thuật ngữ | Định nghĩa ngắn | Ghi chú |
|---|---|---|
| Phishing | Tấn công giả mạo tên miền để lừa đảo | Giữ nguyên tiếng Anh |
| DNS sinkhole | Chuyển hướng tên miền độc hại về IP an toàn | Giữ nguyên |
| Lexical scoring | Chấm điểm rủi ro dựa trên cấu trúc ký tự tên miền | |
| Domain risk scoring | Chấm điểm tổng hợp rủi ro tên miền (thang 0-100) | |
| DGA (Domain Generation Algorithm) | Thuật toán sinh tên miền tự động của malware | |
| Bloom filter | Cấu trúc xác suất kiểm tra tập hợp | Dùng cho whitelist |
| Fail-open | Cơ chế cho phép traffic khi hệ thống gặp lỗi | Đảm bảo availability |
| Reverse proxy | Proxy trung gian (Caddy) | |
| Platt calibration | Hiệu chỉnh xác suất bằng Sigmoid scaling | |
| Group-disjoint split | Phân chia dữ liệu đảm bảo không rò rỉ nhóm | Hash trên eTLD+1 |
| Feature contract | Đặc tả bất biến cho bộ đặc trưng ML | Phiên bản v1: 534 features |
| `leaves` | Thư viện Go inference cho LightGBM, không cần CGO | `github.com/dmitryikh/leaves` |
| `core-api` | Dịch vụ HTTP API chính | Port 8080 |
| `dns-resolver` | Dịch vụ phân giải DNS (DoH/DoT) | Port 8081/853 |
| `feed-syncd` | Daemon đồng bộ threat feed | Background service |
| Candidate cohort | Tập hợp tên miền cần ML scoring (qua heuristic filter) | |

---

## 6. Quy tắc Định dạng

### 6.1. Bảng (Tables)
- Dùng bảng Markdown cho so sánh phương pháp, số liệu, danh sách artifacts.
- Header row bằng tiếng Việt hoặc song ngữ nếu thuật ngữ kỹ thuật.

### 6.2. Công thức Toán học
- Inline: `$P(\text{malicious} \mid z) = \frac{1}{1 + e^{Az+B}}$`
- Display: dùng `$$...$$` cho công thức quan trọng.
- Ghi rõ giá trị tham số ngay sau công thức.

### 6.3. Code Blocks
- Dùng cho lệnh shell, đường dẫn file, tên hàm.
- Chỉ định ngôn ngữ: ` ```bash `, ` ```python `, ` ```go `.

### 6.4. Liên kết File
- Dùng đường dẫn tương đối từ gốc dự án: `ml/models/v1/`, `ml/src/train_lightgbm.py`.
- Không dùng đường dẫn tuyệt đối (D:\...) trong tài liệu.

---

## 7. Pre-flight Checklist

Trước khi xuất nội dung tài liệu, AI agent **PHẢI** tự kiểm tra trong quá trình suy nghĩ (thought/thinking):

```
□ Có Abstract/Tóm tắt ở đầu không?
□ Mỗi section có đủ 4 mục: Mục tiêu, Phương pháp, Thực hiện, Số liệu?
□ Bảng so sánh phương pháp thay thế có đủ không?
□ Có ghi rõ AI agent usage (model, strategy, voting) không?
□ Số liệu có đơn vị không? (%, ms, MB, bản ghi)
□ Có dùng từ cấm nào trong Section 2 không?
□ Đường dẫn file dùng relative path chưa?
□ Có Version History ở cuối không?
□ Giọng văn có khách quan, ngôi thứ ba không?
□ Có câu nào tuyệt đối hóa không có dẫn chứng không?
```
