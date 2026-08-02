---
name: draw-diagram
description: >
  Hướng dẫn AI agent vẽ sơ đồ kỹ thuật (kiến trúc, pipeline, flowchart, sequence)
  cho dự án Safe-Zone. Ưu tiên Mermaid.js cho Markdown/GitHub.
  Kích hoạt khi cần tạo hoặc cập nhật sơ đồ trong tài liệu.
---

# Kỹ năng Vẽ Sơ đồ Kỹ thuật — Safe-Zone

> **Phạm vi:** Áp dụng khi AI agent cần vẽ sơ đồ kiến trúc, flowchart, sequence diagram, pipeline, hoặc wireframe cho dự án Safe-Zone.

---

## 1. Nguyên tắc Thiết kế

### 1.1. Mỗi sơ đồ — Một mục đích

Trước khi vẽ, xác định rõ sơ đồ trả lời câu hỏi nào:
- **"Hệ thống gồm những gì?"** → Architecture / Container diagram
- **"Dữ liệu đi qua đâu?"** → Flowchart / Sequence diagram
- **"Quy trình gồm mấy bước?"** → Pipeline / Activity diagram
- **"Ai giao tiếp với ai?"** → Sequence / Interaction diagram

### 1.2. Tối giản & Rõ ràng

- Giới hạn **7 ± 2 node** mỗi sơ đồ. Nếu vượt quá → chia thành sub-diagrams.
- Mỗi node có **tên ngắn** (2-4 từ) và **mô tả 1 dòng** nếu cần.
- Loại bỏ node không đóng góp vào câu trả lời chính.

### 1.3. Luồng Một chiều Nhất quán

- **Trên → Dưới** (TB): cho pipeline, quy trình tuần tự.
- **Trái → Phải** (LR): cho kiến trúc hệ thống, data flow.
- Tránh mũi tên ngược chiều trừ khi thể hiện feedback loop rõ ràng.

### 1.4. Ký hiệu Hình khối Chuẩn

| Hình | Ý nghĩa | Mermaid syntax |
|---|---|---|
| Hình chữ nhật bo tròn | Service / Process | `A([Service Name])` |
| Hình chữ nhật vuông | Module / Component | `A[Module Name]` |
| Hình thoi | Quyết định / Điều kiện | `A{Condition?}` |
| Hình trụ | Database / Storage | `A[(Database)]` |
| Hình bình hành | Input / Output | `A[/Data Input/]` |
| Hình tròn | Bắt đầu / Kết thúc | `A((Start))` |

---

## 2. Công cụ & Cú pháp

### 2.1. Ưu tiên: Mermaid.js

Sử dụng Mermaid cho tất cả sơ đồ trong file Markdown, README, và tài liệu GitHub. Lý do: render trực tiếp trên GitHub, không cần toolchain bên ngoài, dễ version control (text-based).

### 2.2. LaTeX TikZ (Khi viết paper)

Chỉ dùng TikZ khi xuất sơ đồ cho báo cáo khoa học PDF/LaTeX. Khi đó:
- Dùng `inner sep=8pt` để tránh chữ bị cắt.
- Dùng `label=above left` thay vì `fit` overlay khi annotate.
- Bo tròn góc: `rounded corners=4pt`.

### 2.3. Quy tắc Cú pháp Mermaid

```
%% Tránh lỗi render:
- Quote nhãn chứa ký tự đặc biệt: id["Label (Extra Info)"]
- Không dùng HTML tags trong labels
- Không dùng emoji trong node labels (một số renderer không hỗ trợ)
- Dùng subgraph cho nhóm logic, đặt tên rõ ràng
```

---

## 3. Bảng Màu Chuẩn

### 3.1. Nguyên tắc Màu sắc

- **Nền chính:** Nhạt, sạch — White, Light Gray (#F7F8FA), Very Light Blue (#F0F4F8).
- **Giới hạn 3-4 màu accent** mỗi sơ đồ.
- **Pastel** cho nền node. Không dùng màu đậm/neon cho background.
- **Viền (stroke)** đậm hơn nền 2-3 shade để tạo độ tương phản.

### 3.2. Bảng Màu Phán định Rủi ro (Risk Verdict Palette)

Áp dụng nhất quán trong mọi sơ đồ liên quan tới threat scoring:

| Trạng thái | Màu nền | Màu viền | Mã hex | Dải điểm |
|---|---|---|---|---|
| **SAFE** | Xanh lá nhạt | Xanh lá đậm | `#D4EDDA` / `#28A745` | Score < 40 |
| **SUSPICIOUS** | Vàng nhạt | Vàng đậm | `#FFF3CD` / `#FFC107` | 40 ≤ Score < 70 |
| **MALICIOUS** | Đỏ nhạt | Đỏ đậm | `#F8D7DA` / `#DC3545` | Score ≥ 70 |
| **3rd Party / External** | Xám nhạt | Xám đậm | `#E9ECEF` / `#6C757D` | N/A |
| **AI / ML** | Tím nhạt | Tím đậm | `#E8DAEF` / `#8E44AD` | N/A |
| **Info / Neutral** | Xanh dương nhạt | Xanh dương đậm | `#D1ECF1` / `#17A2B8` | N/A |

### 3.3. Áp dụng Màu trong Mermaid

```mermaid
flowchart LR
    A[Domain Query] --> B{Whitelist?}
    B -->|Yes| C[SAFE]:::safe
    B -->|No| D{Threat Feed?}
    D -->|Match| E[MALICIOUS]:::malicious
    D -->|No Match| F{Lexical Score?}
    F -->|< 40| G[SAFE]:::safe
    F -->|40-69| H[SUSPICIOUS]:::suspicious
    F -->|≥ 70| I[ML Scoring]:::ai

    classDef safe fill:#D4EDDA,stroke:#28A745,color:#155724
    classDef suspicious fill:#FFF3CD,stroke:#FFC107,color:#856404
    classDef malicious fill:#F8D7DA,stroke:#DC3545,color:#721C24
    classDef ai fill:#E8DAEF,stroke:#8E44AD,color:#4A235A
```

---

## 4. Khung Kiến trúc C4 Model

Áp dụng 3 mức đầu tiên của C4 Model. Bỏ qua Mức 4 (Code) vì mã nguồn tự giải thích.

### Mức 1: System Context (Ngữ cảnh Hệ thống)

Trả lời: "Safe-Zone tương tác với hệ thống nào bên ngoài?"

```mermaid
graph LR
    User([Người dùng / Admin]) --> SZ[Safe-Zone System]
    SZ --> CF[Cloudflare DoH Upstream]
    SZ --> TF[Threat Feeds<br>PhishTank, URLhaus, NCSC]
    SZ --> LLM[LLM API<br>Gemini / Ollama]
    Client([Client DNS]) --> SZ
```

### Mức 2: Container (Thùng chứa)

Trả lời: "Safe-Zone gồm những service/container nào?"

Các container chính cần thể hiện:
- `Caddy` (reverse proxy, TLS termination)
- `core-api` (HTTP API, Go, port 8080)
- `dns-resolver` (DNS server, DoH/DoT, port 8081/853)
- `feed-syncd` (background daemon, threat feed sync)
- `Redis` (cache, pub/sub)
- `SQLite` (persistent storage, WHOIS cache)
- `React SPA` (embedded UI)

### Mức 3: Component (Thành phần)

Trả lời: "Bên trong core-api có những module nào?"

Các component chính trong `internal/`:
- `analysis` — Multi-layer risk scoring engine
- `risk` — Risk aggregation & verdict
- `ai` — LLM integration (Gemini, Ollama)
- `store` — SQLite repository
- `cache` — Redis client
- `config` — Dynamic configuration (hot-reload)
- `api` — HTTP handlers & middleware

---

## 5. Template Sơ đồ Safe-Zone

### 5.1. DNS Resolution Flow (Sequence Diagram)

```mermaid
sequenceDiagram
    participant C as Client
    participant DR as dns-resolver
    participant R as Redis Cache
    participant CA as core-api
    participant WL as Whitelist<br>Bloom Filter
    participant TF as Threat Feed<br>Redis Set
    participant LX as Lexical<br>Heuristics
    participant ML as ML Model<br>LightGBM
    participant UP as Upstream<br>Cloudflare DoH

    C->>DR: DNS Query (example.com)
    DR->>R: Check cache
    alt Cache hit
        R-->>DR: Cached response
        DR-->>C: DNS Response
    else Cache miss
        DR->>CA: /v1/analyze
        CA->>WL: Bloom filter lookup
        alt Whitelisted
            WL-->>CA: SAFE (skip analysis)
        else Not whitelisted
            CA->>TF: Threat feed check
            alt Known threat
                TF-->>CA: MALICIOUS (immediate block)
            else Unknown
                CA->>LX: 8 lexical signals
                CA->>ML: 534-feature scoring
                ML-->>CA: Calibrated probability
                CA-->>CA: Aggregate verdict
            end
        end
        CA-->>DR: Verdict + score
        alt SAFE or SUSPICIOUS
            DR->>UP: Forward to upstream
            UP-->>DR: Real DNS response
        else MALICIOUS (score ≥ 0.85)
            DR-->>DR: Sinkhole (127.0.0.1)
        end
        DR->>R: Cache result
        DR-->>C: DNS Response
    end
```

### 5.2. ML Training Pipeline (Flowchart)

```mermaid
flowchart TB
    subgraph Phase0["Phase 0: Foundations"]
        G0[Gate G0<br>Data Integrity] --> S0A[Phase 0A<br>Freeze Snapshots]
        S0A --> S0B[Phase 0B<br>Canonicalization<br>& 22 Features]
        S0B --> S0C[Phase 0C<br>Ablation Study<br>18 experiments]
        S0C --> S0D[Phase 0D<br>leaves Spike<br>Go Parity]
    end

    subgraph Phase1["Phase 1: Feature Extraction"]
        CC[Build Candidate<br>Cohort] --> SP[Group-Disjoint<br>Splits 70/10/10/10]
        SP --> FE[Extract 534<br>Features CSR/NPZ]
    end

    subgraph Phase2["Phase 2: Training"]
        TR[Train LightGBM<br>1000 trees] --> CAL[Platt Sigmoid<br>Calibration]
        CAL --> EV[Independent Test<br>Evaluation]
        EV --> BN[Export Immutable<br>Bundle v1]
    end

    subgraph Phase3["Phase 3: Verification"]
        GP[Golden Parity<br>29 test cases] --> RG[Rejection Gates<br>Testing]
        RG --> TS[Thread-Safety<br>20 goroutines]
        TS --> VOTE[3/3 Consensus<br>Vote PASS]
    end

    Phase0 --> Phase1
    Phase1 --> Phase2
    Phase2 --> Phase3

    style Phase0 fill:#D1ECF1,stroke:#17A2B8
    style Phase1 fill:#D4EDDA,stroke:#28A745
    style Phase2 fill:#FFF3CD,stroke:#FFC107
    style Phase3 fill:#E8DAEF,stroke:#8E44AD
```

### 5.3. Container Architecture (LR Layout)

```mermaid
flowchart LR
    subgraph Internet["Internet Zone"]
        CL([Client DNS])
        BR([Browser / Admin])
    end

    subgraph Docker["Docker Network"]
        CD[Caddy<br>:443/:80]
        CA[core-api<br>:8080]
        DR[dns-resolver<br>:8081/853]
        FS[feed-syncd<br>background]
        RD[(Redis<br>:6379)]
        SQ[(SQLite<br>safe-zone.db)]
    end

    CL -->|DoH/DoT| CD
    BR -->|HTTPS| CD
    CD -->|reverse proxy| CA
    CD -->|DNS proxy| DR
    CA <-->|cache/pubsub| RD
    DR <-->|cache| RD
    CA -->|persist| SQ
    FS -->|sync feeds| RD
    DR -->|analyze| CA

    style Internet fill:#F7F8FA,stroke:#6C757D
    style Docker fill:#E8F4FD,stroke:#17A2B8
```

---

## 6. Phong cách Sơ đồ UI Dashboard

Khi vẽ wireframe hoặc layout cho SOC Dashboard:

- **Theme:** Modern Light SOC — lấy cảm hứng Windows 11 / Zorin OS.
- **Nền:** Trắng (#FFFFFF) hoặc xám rất nhạt (#F7F8FA).
- **Card:** Glassmorphism — `backdrop-blur`, viền mờ, đổ bóng nhẹ.
- **Bo tròn:** `border-radius: 12px` cho cards, `8px` cho buttons.
- **Typography:** Inter hoặc system font stack.
- **Biểu đồ:** Recharts (SVG) hoặc ApexCharts. Dùng pastel fills, không dùng pattern phức tạp.
- **State colors:** Theo Risk Verdict Palette (Section 3.2).

---

## 7. Pre-flight Checklist

Trước khi xuất sơ đồ, AI agent **PHẢI** kiểm tra:

```
□ Sơ đồ trả lời đúng 1 câu hỏi rõ ràng?
□ Số node ≤ 9? (Nếu > 9 → cần chia nhỏ)
□ Luồng đi theo 1 hướng nhất quán (TB hoặc LR)?
□ Có dùng đúng Risk Verdict Palette cho trạng thái rủi ro?
□ Tên node/service khớp với codebase (core-api, dns-resolver, feed-syncd)?
□ Label trên mũi tên có mô tả hành động (không để trống)?
□ Không có mũi tên chéo ngoằn ngoèo (crossing arrows)?
□ Cú pháp Mermaid render được (không lỗi parse)?
□ Node chứa ký tự đặc biệt đã được quote ["..."]?
□ subgraph có tên mô tả rõ ràng?
```
