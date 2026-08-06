# Quorix Safe-Zone — Hướng dẫn cho AI Agent

> **Living Document** — Cập nhật đồng bộ khi có thay đổi trong quy trình phát triển.

---

## 1. UI Framework & Styling

- **Framework hiện đại:** Khuyến khích sử dụng Tailwind CSS, Shadcn UI, Headless UI, Radix, Material UI để đảm bảo component chất lượng cao.
- **Tailwind CSS:** Được phép và khuyến khích cho styling nhanh.
- **Charts:** Ưu tiên thư viện hỗ trợ SVG/DOM animations (Recharts, ApexCharts) thay vì Canvas-only khi cần animation nâng cao.

## 2. Thẩm mỹ & Hệ thống Thiết kế (Premium SOC Vibe)

- **Theme:** Light, Modern Artistic SOC (Security Operations Center) — lấy cảm hứng Windows 11 / Zorin OS.
- **Bảng màu:** Nền sáng sạch (White, Light Gray, Very Light Pink). Màu accent rõ ràng theo trạng thái (Đỏ — Threat, Vàng — Suspicious, Xanh lá — Safe, Xanh dương — Info).
- **Phong cách hiện đại:** Glassmorphism (backdrop-blur, frosted glass nhẹ), typography sạch. Giao diện phải thể hiện tính nghệ thuật, công nghệ cao, gọn gàng và chuyên nghiệp.

## 3. Animations & Tương tác

- **Micro-interactions:** Các phần tử tương tác (buttons, rows, dropdowns) phải có hover states và transitions nhanh.
- **Render dữ liệu:** Sử dụng layout animations (Framer Motion, Tailwind transitions) để dữ liệu xuất hiện mượt mà (fade-in, slide-in), tránh layout shifts (CLS).

## 4. Tổ chức Scripts & Quy ước Đặt tên

- **Cấu trúc thư mục:** Thư mục `scripts` phân loại theo chức năng. Tên thư mục con viết thường, danh từ số nhiều (ví dụ: `scrapers`, `verifiers`, `ops`, `generators`, `data_processing`).
- **Quy ước đặt tên file:**
  - Python: `snake_case` (ví dụ: `scrape_vietnam_blacklist.py`)
  - Shell/PowerShell: `kebab-case` (ví dụ: `safe-zone.sh`, `ui.ps1`)
- **Vị trí:** Đặt scripts vào thư mục con phù hợp. Không đặt trực tiếp trong gốc `scripts/`.

---

## 5. Tài liệu Phát triển Dự án (Development Documentation)

### 5.1. Phạm vi Áp dụng

- **Bắt buộc:** Mọi thao tác phát triển — dù là AI Engine, Backend, Frontend, Infrastructure, Scripts, hay bất kỳ thành phần nào — đều **PHẢI** cập nhật tài liệu nghiên cứu & phát triển tương ứng. Nếu tài liệu chưa tồn tại, **PHẢI tạo mới**.
- **Thư mục gốc:** `docs/research/`
- **Phân loại theo lĩnh vực:**
  - AI Engine / Machine Learning: `docs/research/ml/`
  - Backend / API / Services: `docs/research/backend/`
  - Frontend / UI / Dashboard: `docs/research/frontend/`
  - Infrastructure / DevOps / CI-CD: `docs/research/infra/`
  - Security / Threat Intelligence: `docs/research/security/`
  - Lĩnh vực khác: tạo thư mục con phù hợp trong `docs/research/`

### 5.2. Nội dung Bắt buộc

Mỗi tài liệu nghiên cứu/phát triển **PHẢI** có đầy đủ các mục sau cho mỗi giai đoạn hoặc công việc:

1. **Mục tiêu (Objectives):** Mô tả rõ ràng mục tiêu cần đạt.

2. **Phương pháp & Lý do Chọn lựa (Methodology & Rationale):**
   - Trình bày phương pháp được chọn.
   - **Bắt buộc** so sánh với các phương pháp thay thế (alternatives). Giải thích rõ **tại sao** phương pháp này được chọn.
   - Ví dụ: "Chọn LightGBM thay vì XGBoost vì hỗ trợ sparse input native và tốc độ inference nhanh hơn 3x trên Go runtime qua thư viện `leaves`."

3. **Cách thức Thực hiện (Implementation Details):**
   - Mô tả chi tiết cách công việc được thực hiện, bao gồm khi sử dụng AI agent.
   - Nếu dùng AI agent: ghi rõ mô hình sử dụng, chiến lược prompt, số lượng subagent, cơ chế kiểm soát chất lượng (ví dụ: bỏ phiếu đồng thuận ≥ 2/3).
   - Ví dụ: "Sử dụng Gemini 2.5 Flash điều phối 3 subagent độc lập (Code Reviewer, Output Auditor, Test Verifier) với cơ chế bỏ phiếu đồng thuận ≥ 2/3."

4. **Số liệu Cụ thể (Metrics & Results):**
   - Ghi nhận đầy đủ các số liệu đo lường: ROC-AUC, PR-AUC, ECE, FPR, thời gian xử lý, dung lượng, số lượng bản ghi, test cases passed, v.v.
   - Số liệu phải cụ thể, có đơn vị, và có thể tái kiểm chứng.

### 5.3. Tiêu chuẩn Chất lượng

- **Rõ ràng, minh bạch, không dài dòng.** Mọi thông tin thêm vào đều phải có giá trị thực tiễn.
- **Có thể tái lập (Reproducible):** Ghi nhận đủ thông tin để một người khác (hoặc AI agent khác) có thể tái lập kết quả.
- **Cập nhật liên tục (Living Document):** Tài liệu phải được cập nhật đồng bộ mỗi khi có thay đổi, không để lạc hậu so với mã nguồn.

---

## 6. Kỹ năng AI Agent (Agent Skills)

### 6.1. Danh sách Skills

Các kỹ năng chuyên biệt cho AI agent được lưu trong `.agents/`, mỗi skill là một thư mục chứa file `SKILL.md`:

| Skill | Thư mục | Kích hoạt khi |
|---|---|---|
| **writing-docs** | `.agents/writing-docs/` | Tạo mới hoặc cập nhật file trong `docs/research/` |
| **draw-diagram** | `.agents/draw-diagram/` | Cần vẽ sơ đồ kiến trúc, flowchart, pipeline, sequence diagram |

### 6.2. Quy tắc Sử dụng

- **PHẢI** đọc `SKILL.md` tương ứng trước khi thực hiện tác vụ liên quan.
- Skill `writing-docs` định nghĩa giọng văn, cấu trúc, danh sách từ cấm, và pre-flight checklist cho tài liệu R&D.
- Skill `draw-diagram` định nghĩa bảng màu, ký hiệu, template Mermaid, và khung kiến trúc C4 cho sơ đồ.
- Khi viết tài liệu có sơ đồ: kích hoạt **cả hai** skills đồng thời.

---

## 7. Quản lý Dữ liệu & Tính Tái lập (Data Management & Reproducibility)

### 7.1. Chính sách Git

Dữ liệu được phân thành 3 loại với chính sách Git khác nhau:

| Loại dữ liệu | Ví dụ | Chính sách Git |
|---|---|---|
| **Code & Config** | `*.go`, `*.tsx`, `*.json` (config) | ✅ Commit bình thường |
| **Metadata & Manifest** | `data_manifest.json`, `SHA256SUMS`, `split_manifest.json` | ✅ Commit — phục vụ tái lập |
| **Dữ liệu thô & xử lý** | `*.csv`, `*.parquet`, `*.npz`, model weights | ❌ KHÔNG commit — quá lớn, thuộc `.gitignore` |

### 7.2. Đảm bảo Tái lập (Reproducibility)

Dù dữ liệu thô không nằm trong Git, tính tái lập được đảm bảo qua:

1. **SHA-256 Checksums:** Mọi dataset và model artifact đều có checksum trong manifest files (đã tracked bởi Git).
2. **Fixed Random Seed:** Seed cố định (42) cho mọi thao tác ngẫu nhiên (splits, sampling).
3. **Deterministic Scripts:** Pipeline scripts (`ml/src/`) cho phép tái tạo dữ liệu từ nguồn thô.
4. **Frozen Dependencies:** `pyproject.toml` khóa chính xác phiên bản (==) cho mọi thư viện Python.
5. **Frozen Snapshots:** Hằng số Go runtime đóng băng tại `ml/contracts/snapshots/`.

### 7.3. Quy trình cho AI Agent

Khi AI agent cần làm việc với dữ liệu:

```
1. Kiểm tra data tồn tại local → nếu có, verify SHA-256 checksums
2. Nếu data chưa có → chạy pipeline scripts để tái tạo từ nguồn
3. SAU KHI hoàn thành → cập nhật manifest files và checksums
4. KHÔNG BAO GIỜ commit files trong .gitignore
```

### 7.4. Hướng phát triển

Khi dự án cần chia sẻ dữ liệu giữa nhiều máy hoặc cộng tác viên, sẽ tích hợp **DVC (Data Version Control)** để:
- Track dữ liệu bằng pointer files (`.dvc`) trong Git
- Lưu dữ liệu thực tế ở private remote storage (Cloudflare R2 / MinIO)
- Đồng bộ `git checkout <sha>` + `dvc checkout` = exact data snapshot

---

## 8. Git Workflow & Quy ước Commit

### 8.1. Commit Message Format

Sử dụng Conventional Commits:

```
<type>(<scope>): <mô tả ngắn>

[thân commit tùy chọn — giải thích lý do, bối cảnh]
```

### 8.2. Danh sách Type

| Type | Ý nghĩa | Ví dụ |
|---|---|---|
| `feat` | Tính năng mới | `feat(api): thêm endpoint /v1/analyze/batch` |
| `fix` | Sửa lỗi | `fix(dns): xử lý timeout khi upstream không phản hồi` |
| `docs` | Cập nhật tài liệu | `docs(ml): cập nhật method.md Phase 2 metrics` |
| `data` | Thay đổi liên quan dữ liệu | `data(feeds): cập nhật manifest sau sync PhishTank` |
| `ml` | Thay đổi ML pipeline | `ml(phase2): train LightGBM full model v1` |
| `refactor` | Tái cấu trúc không đổi chức năng | `refactor(analysis): tách risk scoring thành module riêng` |
| `test` | Thêm/sửa tests | `test(ml): thêm golden parity test cho Phase 3` |
| `ops` | Infrastructure, deployment | `ops(docker): cập nhật docker-compose production` |
| `style` | Thay đổi UI/CSS | `style(dashboard): cập nhật glassmorphism cho cards` |
| `chore` | Công việc bảo trì | `chore(deps): cập nhật Go modules` |

### 8.3. Scope thường dùng

`api`, `dns`, `ml`, `ui`, `feeds`, `analysis`, `config`, `cache`, `store`, `ops`, `docs`, `scripts`

### 8.4. Quy tắc Push & Kiểm tra CI

Khi người dùng yêu cầu push code lên GitHub/remote repository, AI agent **PHẢI** luôn kiểm tra tiến trình CI local (`mise run ci` hoặc tương đương) và tự động khắc phục mọi lỗi (nếu có) trước khi hoàn tất công việc.

