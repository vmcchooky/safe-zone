# Kế hoạch triển khai: Phát hiện giả mạo thương hiệu nâng cao & Lexical Heuristics (Hướng 6)

Bản kế hoạch này mô tả chi tiết giải pháp thiết kế và triển khai ba cơ chế phân tích lexical nâng cao nhằm nâng tầm khả năng phát hiện các trang web giả mạo thương hiệu (Brand Spoofing) và lỗi gõ sai (Typosquatting) lên mức tối tân:
1.  **Phát hiện tấn công chữ đồng hình (Homoglyph & IDN Visual Spoofing Detection)**.
2.  **Khoảng cách Levenshtein có trọng số bàn phím (Keyboard Adjacency Weighted Levenshtein)**.
3.  **Điểm phạt TLD rủi ro cao kết hợp thương hiệu (Suspicious TLD Penalty for Brands)**.

---

## 📌 1. Homoglyph & IDN Visual Spoofing Detection

### Vấn đề
Kẻ tấn công sử dụng các ký tự quốc tế trông cực kỳ giống với ký tự Latinh (ví dụ chữ `о` của Cyrillic trông giống hệt chữ `o` của Latinh). Một tên miền như `gооgle.com` (chữ `о` thứ 2 là Cyrillic) khi được hiển thị có thể đánh lừa mắt thường 100%, và nếu đo khoảng cách Levenshtein byte thô thì khoảng cách sẽ lớn do sai khác bảng mã.

### Giải pháp
*   Xây dựng một bản đồ map ký tự đồng hình (Homoglyph Map) chứa các ký tự unicode thay thế phổ biến nhất của bảng chữ cái Cyrillic, Greek, Latin mở rộng về ký tự Latin gốc ("skeleton").
*   Khi phân tích một nhãn tên miền, hệ thống sẽ chuẩn hóa chuỗi unicode thành chuỗi "skeleton" thuần Latin.
*   Chạy so sánh typosquatting trên chuỗi skeleton này. Nếu skeleton của tên miền trùng hoặc rất gần với thương hiệu, hệ thống lập tức phát hiện tấn công Homoglyph.

### Bản đồ Homoglyph cốt lõi:
```go
var homoglyphMap = map[rune]rune{
	// Cyrillic lookalikes
	'а': 'a', 'б': 'b', 'с': 'c', 'ԁ': 'd', 'е': 'e', 'f': 'f', 'g': 'g', 'һ': 'h', 
	'і': 'i', 'ј': 'j', 'k': 'k', 'l': 'l', 'm': 'm', 'п': 'n', 'о': 'o', 'р': 'p', 
	'q': 'q', 'г': 'r', 'ѕ': 's', 'т': 't', 'υ': 'u', 'ѵ': 'v', 'ԝ': 'w', 'х': 'x', 
	'у': 'y', 'z': 'z',
	// Uppercase & extensions
	'А': 'a', 'В': 'b', 'С': 'c', 'Е': 'e', 'Н': 'h', 'І': 'i', 'Ј': 'j', 'К': 'k', 
	'М': 'm', 'О': 'o', 'Р': 'p', 'Ѕ': 's', 'Т': 't', 'Х': 'x', 'Ү': 'y',
	// Greek lookalikes
	'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ο': 'o', 'ρ': 'p', 'τ': 't', 
	'υ': 'u', 'χ': 'x',
}
```

---

## 📌 2. Keyboard Adjacency Weighted Levenshtein

### Vấn đề
Lỗi gõ sai thực tế thường do ngón tay gõ lệch sang phím bên cạnh trên bàn phím (ví dụ gõ nhầm `vietcobmank` thay vì `vietcombank` do `b` và `m` sát nhau). Khoảng cách Levenshtein tiêu chuẩn coi mọi sự thay thế ký tự đều có chi phí là `1`. Điều này bỏ qua đặc tính phân bổ lỗi gõ sai tự nhiên.

### Giải pháp
*   Xây dựng một thuật toán **Weighted Levenshtein Distance** (Khoảng cách Levenshtein có trọng số).
*   Nếu thao tác thay thế ký tự $a$ bằng ký tự $b$ mà $b$ nằm kề sát $a$ trên bàn phím QWERTY, chi phí (weight) của thao tác thay thế đó chỉ tính là **`0.5`** thay vì `1.0`.
*   Nếu Weighted Levenshtein Distance $\le 1.5$, hệ thống sẽ xác định đây là typosquatting lỗi gõ kề phím cực kỳ nguy hiểm.

### Bản đồ phím liền kề (QWERTY Adjacency Map):
```go
var keyboardAdjacency = map[rune]string{
	'a': "qwsz",      'b': "vghn",      'c': "xdfv",      'd': "ersfxc",
	'e': "wsdr34",    'f': "rtgvcd",    'g': "tyhbvf",    'h': "yujnbg",
	'i': "ujko89",    'j': "uikmnh",    'k': "ijlm09",    'l': "okp",
	'm': "njk",       'n': "bhjm",      'o': "iklp90",    'p': "ol0",
	'q': "w12a",      'r': "edft45",    's': "wedxza",    't': "rfgy56",
	'u': "yhji78",    'v': "cfgb",      'w': "qase23",    'x': "zsdc",
	'y': "tghu67",    'z': "asx",
}
```

---

## 📌 3. Suspicious TLD Penalty for Brands

### Vấn đề
Các trang lừa đảo thường đăng ký tên miền kết hợp từ khóa thương hiệu đi kèm với các đuôi tên miền (TLDs) rẻ tiền hoặc miễn phí (ví dụ `vietcombank.xyz`, `techcombank.top`, `chinhphu.cc`).

### Giải pháp
*   Thiết lập danh sách các TLD rủi ro cao thường xuyên bị lạm dụng trong chiến dịch phishing/scam:
    `.xyz`, `.top`, `.cc`, `.info`, `.work`, `.club`, `.fit`, `.vip`, `.cf`, `.gq`, `.ga`, `.ml`, `.tk`, `.icu`, `.asia`, `.buzz`, `.bid`.
*   Nếu phát hiện tên miền có chứa tên thương hiệu chính thống hoặc typosquatting của thương hiệu (nhưng không phải tên miền chính thức) **VÀ** tên miền đó sử dụng một TLD trong danh sách rủi ro cao trên, hệ thống sẽ **cộng thêm điểm phạt rủi ro `+20` điểm**.
*   Điều này giúp đẩy nhanh tổng điểm vượt ngưỡng 70 (`MALICIOUS`) để hệ thống kích hoạt cơ chế chặn ngay lập tức.

---

## 🛠️ Đề xuất Thay đổi Mã Nguồn

### 1. Nâng cấp logic phân tích Lexical & Brand Spoofing
#### [MODIFY] [brand.go](file:///D:/Quorix/services/safe-zone/internal/analysis/brand.go)
*   Thêm hàm `ToSkeleton(s string) string` để dịch chuyển các ký tự homoglyph về skeleton Latin gốc.
*   Thêm hàm `WeightedLevenshteinDistance(s1, s2 string) float64` để tính khoảng cách Levenshtein có trọng số bàn phím.
*   Cập nhật `CheckBrandSpoofing`:
    *   Tự động phân tích cả chuỗi domain gốc và chuỗi skeleton của nó để phát hiện Homoglyph visual spoofing.
    *   Áp dụng `WeightedLevenshteinDistance` cho tất cả các nhãn để phát hiện lỗi gõ sai phím liền kề với trọng số $\le 1.5$.
    *   Kiểm tra đuôi TLD của root domain. Nếu thuộc danh sách rủi ro cao và không phải tên miền chính thức nhưng chứa thương hiệu, cộng thêm `20` điểm vào điểm phạt rủi ro.

### 2. Cập nhật cấu hình
#### [MODIFY] [analysis.go](file:///D:/Quorix/services/safe-zone/internal/config/analysis.go) & [analysis.go](file:///D:/Quorix/services/safe-zone/internal/analysis/analysis.go)
*   Tích hợp điểm phạt TLD rủi ro cao vào cấu hình `AnalysisConfig` (nếu cần tùy biến) hoặc giữ nguyên hệ số phạt tĩnh `20` điểm để bảo đảm tối ưu.

---

## 📊 Kế hoạch Kiểm Thử & Xác Minh (Verification Plan)

### Kiểm thử Tự Động (Automated Tests)
*   Cập nhật [brand_test.go](file:///D:/Quorix/services/safe-zone/internal/analysis/brand_test.go) bổ sung các ca kiểm thử:
    *   **Homoglyph Spoofing:** `gооgle.com` (sử dụng chữ `о` Cyrillic), `vіеtсоmbаnk.com` (sử dụng chữ đồng hình Cyrillic). Kỳ vọng: Nhận diện thành công `typosquatting of vietcombank` hoặc `homoglyph visual spoofing`.
    *   **Keyboard Typosquatting:** `goofle.com` (`f` thay cho `g`), `vietcobmank.com` (`b` thay cho `m`). Kỳ vọng: Phát hiện Weighted Levenshtein $\le 1.5$.
    *   **Suspicious TLD Penalty:** `vietcombank.xyz`, `chinhphu.top`. Kỳ vọng: Bị phạt nặng và nâng verdict lên `MALICIOUS`.
*   Chạy kiểm thử đa luồng an toàn bộ nhớ: `go test -race ./...`

---

## 📢 Yêu cầu phê duyệt từ Người dùng

> [!IMPORTANT]
> Vui lòng phản hồi để duyệt kế hoạch thiết kế Hướng 6 này trước khi tôi tiến hành lập trình chi tiết. Kế hoạch này sẽ giúp củng cố tối đa lá chắn bảo vệ người dân Việt Nam trước các thủ đoạn giả mạo tinh vi nhất!
