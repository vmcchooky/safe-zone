# Chính sách Bảo mật & Tuyên bố Tuân thủ An toàn Thông tin (Privacy Policy)

**Dự án:** Safe Zone — Hệ thống AI Phòng chống Lừa đảo Trực tuyến qua DNS  
**Tổ chức vận hành:** Quorix Việt Nam  
**Phiên bản:** 1.0  
**Ngày hiệu lực:** 28/07/2026  
**Ngày cập nhật gần nhất:** 28/07/2026

---

> **TUYÊN BỐ PHÁP LÝ**: Văn bản này là Chính sách Bảo mật chính thức của dự án Safe Zone, được soạn thảo và công bố nhằm tuân thủ **Luật An ninh mạng 2018** (Luật số 24/2018/QH14), **Luật An toàn thông tin mạng 2015** (Luật số 86/2015/QH13), và **Nghị định 13/2023/NĐ-CP** về Bảo vệ dữ liệu cá nhân của nước Cộng hòa Xã hội Chủ nghĩa Việt Nam. Chính sách này áp dụng cho toàn bộ hoạt động thu thập, xử lý, lưu trữ dữ liệu liên quan đến hệ thống Safe Zone.

---

## 1. Giới thiệu & Phạm vi Áp dụng

### 1.1 Về Safe Zone
Safe Zone là dự án mã nguồn mở, phi lợi nhuận, được phát triển bởi Quorix Việt Nam, nhằm xây dựng hệ thống bảo vệ người dùng Internet tại Việt Nam khỏi các cuộc tấn công lừa đảo trực tuyến (Phishing), giả mạo tên miền (Domain Impersonation) và các mối đe dọa an ninh mạng thông qua cơ chế lọc DNS (DNS-level Filtering).

### 1.2 Phạm vi Áp dụng
Chính sách bảo mật này áp dụng cho:
- Hệ thống phần mềm Safe Zone (bao gồm Core API, DNS Resolver, Feed Sync, và giao diện vận hành)
- Bộ dữ liệu Whitelist tên miền Việt Nam phục vụ huấn luyện AI Anti-Phishing
- Bộ dữ liệu Threat Intelligence (nguồn cấp thông tin đe dọa) từ các nguồn công khai
- Trang dự án chính thức tại [quorix.io.vn/projects/safe-zone](https://www.quorix.io.vn/projects/safe-zone/)
- Fanpage Quorix Việt Nam: [Quorix Việt Nam](https://facebook.com/quorixvietnam) (Facebook)

### 1.3 Đối tượng Áp dụng
- Người vận hành (Operator) triển khai hệ thống Safe Zone
- Người dùng cuối (End User) được bảo vệ bởi DNS Resolver của Safe Zone
- Chủ sở hữu tên miền có tên miền xuất hiện trong cơ sở dữ liệu của hệ thống
- Cộng đồng nghiên cứu an toàn thông tin sử dụng mã nguồn mở của dự án

---

## 2. Mục đích Thu thập & Xử lý Dữ liệu

### 2.1 Mục đích Duy nhất
Toàn bộ dữ liệu được thu thập và xử lý bởi hệ thống Safe Zone **CHỈ** phục vụ các mục đích sau:

| STT | Mục đích | Mô tả Chi tiết |
| :---: | :--- | :--- |
| 1 | **Phòng chống lừa đảo trực tuyến** | Xây dựng, huấn luyện và vận hành AI Engine nhận diện tên miền lừa đảo (Phishing), giả mạo (Impersonation), phát tán mã độc (Malware Distribution) |
| 2 | **Giảm thiểu báo động giả** | Duy trì bộ Whitelist tên miền hợp pháp tại Việt Nam nhằm giảm tỷ lệ False Positive khi phân loại tên miền |
| 3 | **Nghiên cứu an toàn thông tin** | Phân tích xu hướng tấn công, mẫu hình tên miền độc hại, và cải thiện thuật toán phát hiện rủi ro |
| 4 | **Bảo vệ cộng đồng** | Cung cấp dịch vụ DNS an toàn, miễn phí cho người dùng Internet tại Việt Nam |

### 2.2 Cam kết Không Sử dụng Ngoài Mục đích
Quorix Việt Nam cam kết:
- **KHÔNG** sử dụng dữ liệu cho mục đích thương mại, quảng cáo, hoặc tiếp thị
- **KHÔNG** bán, cho thuê, trao đổi, hoặc chia sẻ dữ liệu cho bên thứ ba vì mục đích lợi nhuận
- **KHÔNG** sử dụng dữ liệu để theo dõi, giám sát, hoặc lập hồ sơ người dùng cá nhân
- **KHÔNG** sử dụng dữ liệu để xây dựng hệ thống chấm điểm xã hội hoặc phân biệt đối xử

---

## 3. Nguồn Dữ liệu & Phương pháp Thu thập

### 3.1 Nguyên tắc Thu thập
Hệ thống Safe Zone **CHỈ** thu thập dữ liệu từ các nguồn mở, công khai, hợp pháp (Publicly Available Data). Toàn bộ quá trình thu thập tuân thủ nghiêm ngặt các nguyên tắc:
- Chỉ truy cập các API công khai (Public API) và giao thức chuẩn Internet (DNS, RDAP, HTTP)
- Tuân thủ giới hạn tốc độ truy vấn (Rate Limit) của từng nguồn
- Không sử dụng kỹ thuật vượt qua cơ chế bảo mật hoặc hạn chế truy cập của bên cung cấp
- Không truy cập các hệ thống yêu cầu xác thực trái phép

### 3.2 Danh mục Nguồn Dữ liệu Công khai
Dữ liệu được thu thập từ các nguồn chính sau (chi tiết kỹ thuật đầy đủ tại [resource.md](resource.md)):

| Loại Nguồn | Ví dụ Cụ thể | Tính chất |
| :--- | :--- | :--- |
| **Nhật ký Chứng chỉ SSL/TLS** | Certificate Transparency Logs (crt.sh) theo RFC 6962 | Dữ liệu mở toàn cầu |
| **Danh bạ Tín nhiệm Chính phủ** | Tín Nhiệm Mạng (Bộ TT&TT / NCSC) | Dữ liệu công khai của cơ quan nhà nước |
| **Cấp phép Thông tin Điện tử** | Cục Phát thanh, Truyền hình và TTĐT (ABEI) | Dữ liệu hành chính công khai |
| **Kho mã nguồn mở** | GitHub Public Repositories, Common Crawl | Dữ liệu mở, tuân thủ giấy phép |
| **Danh sách xếp hạng tên miền** | Tranco Top 1M, APNIC Geolocation | Dữ liệu thống kê công khai |
| **Nguồn cấp đe dọa mở** | URLhaus, OpenPhish, PhishDestroy, Phishing.Database | Cơ sở dữ liệu mã độc/lừa đảo cộng đồng |
| **Phân giải DNS công khai** | Google Public DNS (8.8.8.8), Cloudflare DNS (1.1.1.1) | Dịch vụ DNS công cộng |
| **Danh sách Quảng cáo Hợp pháp** | Thư Viện Pháp Luật — White List Quảng cáo | Dữ liệu công khai phục vụ cộng đồng |

### 3.3 Dữ liệu KHÔNG Thu thập
Hệ thống Safe Zone **KHÔNG BAO GIỜ** thu thập, lưu trữ, hoặc xử lý các loại dữ liệu sau:
- Nội dung trang web (HTML, văn bản, hình ảnh, video)
- Thông tin đăng nhập, mật khẩu, hoặc phiên làm việc (Session) của người dùng
- Lịch sử duyệt web hoặc hành vi trực tuyến của người dùng cuối
- Dữ liệu tài chính (số tài khoản ngân hàng, thẻ tín dụng)
- Dữ liệu sinh trắc học (vân tay, khuôn mặt, giọng nói)

---

## 4. Cam kết Bảo vệ Dữ liệu Cá nhân

### 4.1 Không Thu thập Thông tin Định danh Cá nhân (PII)
Theo quy định tại **Điều 2, Nghị định 13/2023/NĐ-CP**, Quorix Việt Nam tuyên bố:

> Bộ dữ liệu của hệ thống Safe Zone **KHÔNG** chứa thông tin định danh cá nhân (Personally Identifiable Information — PII). Hệ thống chỉ thu thập và xử lý tên miền đầy đủ (FQDN — Fully Qualified Domain Name) và các thông tin phân loại kỹ thuật thuần túy. Toàn bộ các trường thông tin cá nhân từ WHOIS (nếu có) đều bị **loại bỏ hoàn toàn** trước khi dữ liệu được đưa vào hệ thống.

### 4.2 Loại bỏ Chủ động Dữ liệu Nhạy cảm
Bộ lọc AI của Safe Zone chủ động thực hiện các bước sau:
- **Tước bỏ (Stripping)**: Loại bỏ tất cả các trường chứa tên cá nhân, email, số điện thoại, địa chỉ vật lý từ dữ liệu WHOIS/RDAP
- **Không lưu trữ IP người dùng cuối**: Hệ thống DNS Resolver không ghi nhận (log) địa chỉ IP của người dùng gửi truy vấn DNS
- **Mã hóa truyền tải**: Hỗ trợ DNS-over-HTTPS (DoH) và DNS-over-TLS (DoT) để bảo vệ tính riêng tư của truy vấn DNS

### 4.3 Xử lý Dữ liệu Đã Công khai
Dù dữ liệu tên miền được thu thập từ nguồn công khai, Quorix Việt Nam vẫn áp dụng nguyên tắc **Thu thập Tối thiểu** (Data Minimization) theo Nghị định 13/2023/NĐ-CP:
- Chỉ thu thập dữ liệu cần thiết cho mục đích phòng chống lừa đảo
- Không thu thập dữ liệu vượt quá phạm vi cần thiết
- Định kỳ rà soát và loại bỏ dữ liệu không còn phục vụ mục đích ban đầu

---

## 5. Cơ sở Pháp lý cho Hoạt động Xử lý Dữ liệu

### 5.1 Căn cứ Pháp luật Việt Nam

| Văn bản Pháp lý | Điều khoản Liên quan | Áp dụng |
| :--- | :--- | :--- |
| **Luật An ninh mạng 2018** (Luật số 24/2018/QH14) | Điều 8 — Hành vi bị cấm; Điều 26 — Bảo đảm ATTT trên không gian mạng | Tuân thủ nghiêm cấm thu thập, sử dụng trái phép thông tin cá nhân |
| **Luật An toàn thông tin mạng 2015** (Luật số 86/2015/QH13) | Điều 16, 17 — Thu thập và sử dụng thông tin cá nhân | Minh bạch hóa mục đích xử lý, thông báo cho chủ thể dữ liệu |
| **Nghị định 13/2023/NĐ-CP** | Điều 9 — Quyền của chủ thể dữ liệu; Điều 11 — Đồng ý xử lý DLCN; Điều 13 — Thông báo xử lý | Công bố chính sách bảo mật, đảm bảo quyền yêu cầu xóa/chỉnh sửa |
| **Luật Sở hữu Trí tuệ** & Công ước Berne | Không áp dụng — Tên miền là dữ liệu định danh hạ tầng mạng | Tên miền không cấu thành đối tượng bảo hộ bản quyền |

### 5.2 Lợi ích Hợp pháp (Legitimate Interest)
Hoạt động xử lý dữ liệu của Safe Zone được thực hiện trên cơ sở lợi ích hợp pháp của cộng đồng:
- Bảo vệ an toàn thông tin, phòng chống tội phạm mạng là lợi ích công cộng
- Dữ liệu xử lý hoàn toàn mang tính kỹ thuật (tên miền, bản ghi DNS), không xâm phạm quyền riêng tư
- Kết quả phân tích phục vụ miễn phí cho cộng đồng người dùng Internet Việt Nam

---

## 6. Quyền của Chủ thể Dữ liệu

Theo **Điều 9, Nghị định 13/2023/NĐ-CP**, các tổ chức và cá nhân liên quan có các quyền sau:

### 6.1 Quyền Được Biết
Bất kỳ tổ chức hoặc cá nhân nào có quyền yêu cầu Quorix Việt Nam xác nhận liệu tên miền thuộc sở hữu của mình có xuất hiện trong cơ sở dữ liệu Safe Zone hay không, và nếu có, dữ liệu đó được phân loại ra sao.

### 6.2 Quyền Yêu cầu Đính chính (False Positive Correction)
Nếu hệ thống AI phân loại nhầm một tên miền hợp pháp là đáng ngờ hoặc nguy hiểm (False Positive), chủ sở hữu tên miền có quyền:
- Gửi yêu cầu đính chính thông qua kênh liên hệ chính thức (Mục 9)
- Được xem xét và phản hồi trong vòng **07 ngày làm việc** kể từ ngày nhận yêu cầu
- Được thông báo kết quả xử lý bằng văn bản (email)

### 6.3 Quyền Yêu cầu Gỡ bỏ (Opt-out / Take-down)
Chủ sở hữu tên miền có quyền yêu cầu gỡ bỏ tên miền khỏi cơ sở dữ liệu Safe Zone nếu:
- Tên miền bị phân loại sai và gây ảnh hưởng đến hoạt động kinh doanh hợp pháp
- Chủ sở hữu không muốn tên miền xuất hiện trong bộ dữ liệu vì bất kỳ lý do chính đáng nào

### 6.4 Quyền Khiếu nại
Trong trường hợp không hài lòng với kết quả xử lý của Quorix Việt Nam, chủ thể dữ liệu có quyền khiếu nại đến cơ quan nhà nước có thẩm quyền theo quy định pháp luật Việt Nam.

---

## 7. Bảo mật Hệ thống & Dữ liệu

### 7.1 Biện pháp Kỹ thuật
- **Mã hóa truyền tải**: Toàn bộ giao tiếp mạng sử dụng TLS 1.2+ (HTTPS, DoH, DoT)
- **Kiểm soát truy cập**: Hệ thống quản trị yêu cầu xác thực Admin Password và API Key mạnh
- **Fail-open Architecture**: Khi AI hoặc các dịch vụ phụ trợ gặp sự cố, hệ thống tiếp tục hoạt động với kết quả phân tích từ thuật toán xác định (Deterministic Lexical Analysis), không gây gián đoạn hoặc rò rỉ dữ liệu
- **Kiểm tra bảo mật**: Mã nguồn được quét bởi `gosec`, `govulncheck`, và kiểm thử E2E tự động trước mỗi bản phát hành

### 7.2 Biện pháp Tổ chức
- Mã nguồn mở cho phép cộng đồng kiểm tra và đánh giá độc lập
- Quy trình kiểm tra bảo mật trước phát hành (Pre-release Security Checklist)
- Giám sát liên tục thông qua hệ thống cảnh báo (Alert Rules) và chỉ số vận hành (Metrics)

### 7.3 Lưu trữ & Bảo quản Dữ liệu
- Dữ liệu Whitelist được lưu trữ dưới dạng file tĩnh (CSV, JSON, TXT) trong thư mục `data/` của dự án
- Dữ liệu Threat Feed được lưu trữ trong Redis với cơ chế đồng bộ định kỳ
- Bộ nhớ đệm phân tích (Cache) WHOIS có thời hạn mặc định 7 ngày và được tự động làm mới
- Sao lưu (Backup) được thực hiện định kỳ với cơ chế tự động hóa

---

## 8. Dữ liệu của Người dùng Cuối (End User)

### 8.1 Khi Sử dụng DNS Resolver
Khi người dùng cuối sử dụng dịch vụ DNS Resolver của Safe Zone:
- Truy vấn DNS được xử lý theo thời gian thực và **KHÔNG** được ghi nhật ký (No DNS Query Logging)
- Hệ thống chỉ kiểm tra tên miền truy vấn với cơ sở dữ liệu nội bộ và trả về kết quả phân loại
- Không có thông tin định danh người dùng nào được thu thập hoặc lưu trữ

### 8.2 Khi Truy cập Giao diện Vận hành
Giao diện vận hành (Operator Dashboard) chỉ dành cho quản trị viên hệ thống:
- Yêu cầu xác thực bằng mật khẩu và khóa API
- Mọi hành động quản trị được ghi nhật ký với Request ID để kiểm toán (Audit Trail)
- Không thu thập Cookie theo dõi hoặc dữ liệu phân tích hành vi người dùng

---

## 9. Thông tin Liên hệ & Quy trình Gỡ bỏ

### 9.1 Kênh Liên hệ Chính thức

| Kênh | Thông tin |
| :--- | :--- |
| **Email** | [contact@quorix.io.vn](mailto:contact@quorix.io.vn) · [vmcchooky@gmail.com](mailto:vmcchooky@gmail.com) |
| **Website Dự án** | [quorix.io.vn/projects/safe-zone](https://www.quorix.io.vn/projects/safe-zone/) |
| **GitHub Issues** | [github.com/vmcchooky/safe-zone/issues](https://github.com/vmcchooky/safe-zone/issues) |
| **Fanpage** | [Quorix Việt Nam](https://facebook.com/quorixvietnam) (Facebook) |

### 9.2 Quy trình Xử lý Yêu cầu Gỡ bỏ / Đính chính

```
Bước 1: Gửi yêu cầu qua Email hoặc GitHub Issues
        → Cung cấp: Tên miền, bằng chứng sở hữu, lý do yêu cầu

Bước 2: Xác nhận tiếp nhận (trong 02 ngày làm việc)
        → Quorix Việt Nam gửi email xác nhận đã nhận yêu cầu

Bước 3: Xem xét & xác minh (trong 05 ngày làm việc)
        → Đội ngũ kỹ thuật xem xét, đối chiếu dữ liệu

Bước 4: Thông báo kết quả (trong 07 ngày làm việc kể từ ngày nhận)
        → Gửi kết quả xử lý cho chủ thể yêu cầu
        → Nếu chấp thuận: Cập nhật cơ sở dữ liệu ngay lập tức
        → Nếu từ chối: Giải trình rõ lý do bằng văn bản
```

---

## 10. Miễn trừ Trách nhiệm

### 10.1 Nguyên tắc "Nguyên trạng" (AS IS)
Bộ dữ liệu và dịch vụ Safe Zone được cung cấp "nguyên trạng" (AS IS) cho mục đích nghiên cứu an toàn thông tin, phòng chống lừa đảo trực tuyến. Quorix Việt Nam không đảm bảo tính chính xác tuyệt đối 100% của mọi kết quả phân loại tên miền.

### 10.2 Không Xác nhận Thương mại
Việc một tên miền xuất hiện trong bộ dữ liệu Whitelist hoàn toàn mang tính chất kỹ thuật — xác nhận tên miền tồn tại và thuộc hạ tầng mạng Việt Nam. Điều này **KHÔNG** cấu thành lời chứng thực, bảo chứng thương mại, hay cam kết tài chính cho bất kỳ tổ chức hoặc cá nhân nào.

### 10.3 Giới hạn Trách nhiệm
Dự án Safe Zone, Quorix Việt Nam, và các nhà phát triển không chịu trách nhiệm pháp lý đối với bất kỳ thiệt hại trực tiếp hoặc gián tiếp nào phát sinh từ:
- Kết quả phân loại sai (False Positive hoặc False Negative)
- Gián đoạn dịch vụ do sự cố kỹ thuật
- Việc sử dụng bộ dữ liệu ngoài mục đích bảo mật và nghiên cứu đã tuyên bố

---

## 11. Cập nhật Chính sách

Chính sách bảo mật này có thể được cập nhật theo thời gian để phản ánh:
- Thay đổi trong quy định pháp luật Việt Nam
- Mở rộng phạm vi dữ liệu hoặc dịch vụ của Safe Zone
- Phản hồi từ cộng đồng và các bên liên quan

Mọi thay đổi quan trọng sẽ được thông báo qua:
- Cập nhật phiên bản trên tài liệu này
- Bài viết trên Fanpage Quorix Việt Nam
- Thông báo trên trang dự án chính thức

---

## 12. Tài liệu Tham chiếu

| Tài liệu | Đường dẫn |
| :--- | :--- |
| Tuyên bố Nguồn dữ liệu & Phương pháp thu thập (Chi tiết kỹ thuật) | [resource.md](resource.md) |
| Chính sách Nguồn Threat Intelligence | [threat-intelligence-sources.md](threat-intelligence-sources.md) |
| Quy trình Kiểm tra Bảo mật Trước Phát hành | [security/pre-release-security-checklist.md](security/pre-release-security-checklist.md) |
| Luật An ninh mạng 2018 | [Luật số 24/2018/QH14](https://thuvienphapluat.vn/van-ban/Cong-nghe-thong-tin/Luat-an-ninh-mang-2018-351416.aspx) |
| Nghị định 13/2023/NĐ-CP về Bảo vệ Dữ liệu Cá nhân | [Nghị định 13/2023/NĐ-CP](https://thuvienphapluat.vn/van-ban/Cong-nghe-thong-tin/Nghi-dinh-13-2023-ND-CP-bao-ve-du-lieu-ca-nhan-465185.aspx) |
| Luật An toàn Thông tin Mạng 2015 | [Luật số 86/2015/QH13](https://thuvienphapluat.vn/van-ban/Cong-nghe-thong-tin/Luat-an-toan-thong-tin-mang-2015-298365.aspx) |

---

*Tài liệu được ban hành chính thức bởi Quorix Việt Nam vào ngày 28/07/2026. Mọi thắc mắc hoặc yêu cầu liên quan đến chính sách bảo mật, xin vui lòng liên hệ qua email: [contact@quorix.io.vn](mailto:contact@quorix.io.vn) hoặc [vmcchooky@gmail.com](mailto:vmcchooky@gmail.com).*
