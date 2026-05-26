# Kế hoạch triển khai: Phát hiện giả mạo cơ quan chính phủ và ngân hàng Việt Nam phòng chống lừa đảo

Bản kế hoạch này mô tả giải pháp bổ sung các heuristics chuyên sâu để bảo vệ người dân Việt Nam trước các chiến dịch lừa đảo công nghệ cao, đặc biệt là các hành vi giả mạo website của cơ quan Nhà nước, tổ chức Chính phủ và các Ngân hàng lớn tại Việt Nam.

Đồng thời, kế hoạch này đáp ứng yêu cầu lưu trữ tài liệu thiết kế bản quyền bài bản ngay trong thư mục tài liệu `docs/specs` của dự án để đảm bảo tính minh bạch và chuyên nghiệp.

---

## 📌 Các Thương Hiệu & Cơ Quan Việt Nam Cần Bảo Vệ

### 1. Cơ quan Nhà nước & Tổ chức Chính phủ
*   **Chính phủ Việt Nam:** `chinhphu` (Tên miền chính thức: `chinhphu.vn`, `chinhphu.gov.vn`)
*   **Bộ Công an:** `bocongan` (Tên miền chính thức: `bocongan.gov.vn`, `mps.gov.vn`)
*   **Bảo hiểm xã hội Việt Nam:** `baohiemxahoi` (Tên miền chính thức: `baohiemxahoi.gov.vn`, `bhxh.gov.vn`)
*   **Đài Truyền hình Việt Nam:** `vtv` (Tên miền chính thức: `vtv.vn`)

### 2. Các Ngân hàng Thương mại lớn tại Việt Nam
*   **Vietcombank:** `vietcombank` (Chính thức: `vietcombank.com.vn`, `vietcombank.com`)
*   **Techcombank:** `techcombank` (Chính thức: `techcombank.com.vn`, `techcombank.com`)
*   **BIDV:** `bidv` (Chính thức: `bidv.com.vn`, `bidv.com`)
*   **Vietinbank:** `vietinbank` (Chính thức: `vietinbank.vn`, `vietinbank.co.vn`)
*   **MB Bank:** `mbbank` (Chính thức: `mbbank.com.vn`, `mbbank.com`)
*   **Agribank:** `agribank` (Chính thức: `agribank.com.vn`, `agribank.com`)
*   **VPBank:** `vpbank` (Chính thức: `vpbank.com.vn`, `vpbank.com`)
*   **ACB:** `acb` (Chính thức: `acb.com.vn`, `acb.com`)
*   **Sacombank:** `sacombank` (Chính thức: `sacombank.com.vn`, `sacombank.com`)
*   **TPBank:** `tpbank` (Chính thức: `tpb.vn`, `tpbank.com.vn`)
*   **VIB:** `vib` (Chính thức: `vib.com.vn`)
*   **HDBank:** `hdbank` (Chính thức: `hdbank.com.vn`)
*   **SHB:** `shb` (Chính thức: `shb.com.vn`)
*   **SCB:** `scb` (Chính thức: `scb.com.vn`)

---

## ⚙️ Bổ Sung Các Từ Khóa Phổ Biến Của Các Chiến Dịch Lừa Đảo Tại Việt Nam
Cập nhật danh sách từ khóa nhạy cảm mặc định để phát hiện các cụm từ tiếng Việt không dấu thường xuyên xuất hiện trong các vụ giả mạo:
*   `dichvucong` (Cổng dịch vụ công quốc gia giả mạo)
*   `congan` / `phatnguoi` / `xulyphat` (Giả mạo trang thông báo vi phạm luật giao thông, đe dọa)
*   `vneid` (Giả mạo ứng dụng định danh định cư quốc gia để đánh cắp thông tin tài khoản)
*   `nganhang` / `xacthuc` / `cungcap` (Các trang đăng nhập ngân hàng giả mạo, dụ dỗ cung cấp OTP)

---

## 🛠️ Đề xuất Thay đổi Mã Nguồn

### 1. Cập nhật Danh mục Thương hiệu & Ngân hàng Việt Nam
#### [MODIFY] [brand.go](file:///D:/Quorix/services/safe-zone/internal/analysis/brand.go)
*   Bổ sung 18 thực thể thương hiệu lớn và cơ quan bộ ngành Việt Nam vào biến `TrustedBrands`.
*   Đảm bảo cấu hình đúng các tên miền phụ và tên miền thay thế (`AltDomains`) để tránh việc chặn nhầm tên miền chính thống (False Positives).

### 2. Bổ sung từ khóa lừa đảo Tiếng Việt vào Cấu hình mặc định
#### [MODIFY] [analysis.go](file:///D:/Quorix/services/safe-zone/internal/config/analysis.go)
*   Mở rộng mảng `Keywords` mặc định trong `DefaultAnalysisConfig()` bao gồm các từ khóa đặc trưng lừa đảo tại Việt Nam: `"dichvucong"`, `"congan"`, `"vneid"`, `"phatnguoi"`, `"xulyphat"`, `"nganhang"`, `"xacthuc"`, `"cungcap"`.

---

## 📊 Kế hoạch Kiểm Thử & Xác Minh (Verification Plan)

### Kiểm thử Tự Động (Automated Tests)
*   **Cập nhật Unit Tests (`internal/analysis/brand_test.go`)**:
    *   Bổ sung các ca thử nghiệm lừa đảo thực tế:
        *   `vietconbank.com.vn` -> Nhận diện typosquatting của `vietcombank`.
        *   `bocongan-verify.xyz` -> Nhận diện chèn tên cơ quan Bộ công an vào root domain.
        *   `chinhphuvn-gov.cc` -> Nhận diện chèn từ khóa Chính phủ Việt Nam.
        *   `vietcombank.secure-login-verify.com` -> Nhận diện lạm dụng subdomain ngân hàng.
        *   `support.vietcombank.com.vn` -> Bỏ qua, nhận diện an toàn (official alt).
        *   `bocongan.gov.vn` -> Bỏ qua, nhận diện an toàn (official domain).
    *   Chạy kiểm thử: `go test -v ./internal/analysis/...` và kiểm thử đa luồng an toàn bộ nhớ `go test -race ./...`.

### Xác Minh Thủ Công (Manual Verification)
*   Truy vấn API `/v1/analyze?domain=vietconbank.com.vn` qua cURL để bảo đảm verdict trả về là `MALICIOUS` hoặc `SUSPICIOUS` với lý do chính xác.
