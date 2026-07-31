# AI Engine Methodology (Phương pháp luận Xây dựng AI Engine)

## 1. Quá trình Chuẩn bị và Xử lý Dữ liệu Tiền huấn luyện (Data Preflight & Processing Methodology)

Quá trình tiền xử lý dữ liệu (Data Preflight) đóng vai trò tiên quyết trong việc đảm bảo chất lượng, tính đại diện và độ tinh sạch của bộ dữ liệu trước khi đưa vào huấn luyện các mô hình học máy (Machine Learning Models). Phương pháp xử lý được thiết kế tuân thủ nghiêm ngặt các tiêu chuẩn khoa học dữ liệu, bao gồm các công đoạn cụ thể như sau:

### 1.1. Tập hợp và Khai thác Nguồn Dữ liệu (Data Sourcing & Acquisition)
Tập dữ liệu nghiên cứu được tổng hợp và đối soát chéo từ nhiều nguồn định tuyến mạng (network routing) và danh sách đen an toàn thông tin (threat intelligence feeds) uy tín trên toàn cầu cũng như nội địa. Dữ liệu được phân loại thành hai nhóm nhãn (labels) nhị phân:
- **Nhóm Tên miền An toàn (Safe Domains - Label 0):** Bao gồm danh sách hạng Tranco, Top-1m toàn cầu, và danh sách trắng các tên miền hợp pháp nội địa Việt Nam.
- **Nhóm Tên miền Độc hại (Malicious Domains - Label 1):** Bao gồm các nguồn cung cấp chỉ số thỏa hiệp (Indicators of Compromise - IoCs) đã được xác minh như URLHaus, PhishTank, danh sách đen lừa đảo quốc gia (NCSC Việt Nam), và các danh sách chuyên biệt (Hagezi, StevenBlack).

### 1.2. Cách ly Xung đột Nhãn (Cross-label Conflict Isolation)
Trong quá trình hợp nhất dữ liệu từ nhiều nguồn độc lập, hiện tượng giao thoa nhãn (cross-label overlap) — nơi một tên miền đồng thời xuất hiện ở cả danh sách trắng và danh sách đen — là không thể tránh khỏi. Để ngăn ngừa hiện tượng nhiễu loạn phân loại (classification noise) cho mô hình học máy, phương pháp **Cách ly Xung đột (Conflict Quarantine)** đã được áp dụng:
- Bất kỳ tên miền nào tồn tại song song ở cả hai tập hợp đều bị loại trừ hoàn toàn khỏi bộ dữ liệu huấn luyện cuối cùng.
- Nhóm tên miền xung đột này được xuất khẩu riêng biệt vào tệp tin lưu trữ (quarantine log) phục vụ cho công tác phân tích chuyên sâu (heuristic review) ở các pha sau của dự án.

### 1.3. Lấy mẫu Giảm Cân bằng và Bảo tồn Ưu tiên (Balanced Downsampling with Priority Retention)
Sự mất cân bằng cấu trúc lớp (Class Imbalance) là một thách thức phổ biến trong các bộ dữ liệu phát hiện mã độc. Để giải quyết vấn đề này, thuật toán cân bằng dữ liệu với tỷ lệ lý tưởng 1:1 đã được áp dụng dựa trên hai nguyên tắc cốt lõi:
- **Bảo tồn Tuyệt đối (Priority Retention):** Giữ lại 100% các bản ghi thuộc các nguồn danh sách đen lừa đảo nhắm mục tiêu (targeted phishing) và danh sách đen nội địa (Vietnam blacklists). Đây là các đặc trưng trọng yếu (high-value features) phản ánh sát nhất các phương thức tấn công hiện hành tại khu vực nghiên cứu.
- **Lấy mẫu Giảm Ngẫu nhiên Xác định (Deterministic Downsampling):** Phần thiếu hụt của nhóm Malicious Domains được bù đắp bằng cách lấy mẫu ngẫu nhiên từ quần thể các danh sách đen chung chung (background threats). Quá trình lấy mẫu sử dụng một hạt giống ngẫu nhiên cố định (fixed random seed) nhằm đảm bảo tính tái lập (reproducibility) của thực nghiệm khoa học, đồng thời giới hạn tổng quy mô của nhóm Độc hại chính xác bằng với quy mô của nhóm An toàn.

### 1.4. Đảm bảo Tính Toàn vẹn và Nguồn gốc Dữ liệu (Data Integrity & Provenance Validation)
Toàn bộ quy trình sinh dữ liệu được tự động hóa thông qua xử lý đa tiến trình (multiprocessing pool) nhằm tối ưu hóa hiệu năng tính toán. Song song đó, tính minh bạch và khả năng truy xuất nguồn gốc (traceability) của dữ liệu được đảm bảo tuyệt đối thông qua cơ chế kiểm định độc lập (Preflight Validation):
- Dữ liệu đầu ra được đối chiếu để loại bỏ hoàn toàn các cấu trúc địa chỉ IP trần (bare IPs), tên miền dị dạng (malformed FQDNs) và các bản ghi trùng lặp (duplicates).
- Một bản Tuyên ngôn Dữ liệu (Data Manifest) được tự động khởi tạo, lưu trữ toàn bộ chữ ký băm (SHA-256 hash), mã định danh phiên bản (Git Commit SHA), và thông số kích thước của từng tệp tin nguyên gốc lẫn tệp tin phái sinh.
