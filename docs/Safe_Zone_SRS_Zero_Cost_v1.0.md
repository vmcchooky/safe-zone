# Software Requirements Specification (SRS)
## Safe Zone — Anti-Phishing System | ZERO-COST EDITION

> **DEPRECATED:** This document is kept for historical reference only. The current roadmap is OPEX-first and lives in [docs/Safe_Zone_OPEX_Estimate.md](../Safe_Zone_OPEX_Estimate.md) and [docs/specs/opex-cost-optimization](specs/opex-cost-optimization).

**Version:** 1.0-ZC  
**Date:** 2026-05-18  
**Status:** Draft for Community Deployment (Zero Monthly Cost)  
**Author:** AI-Assisted Engineering  
**Language:** Vietnamese (Technical terms retained in English)

> **⚡ PHILOSOPHY:** Mọi thành phần phải có lựa chọn MIỄN PHÍ vĩnh viễn (always-free) hoặc self-hosted. Không có chi phí vận hành hàng tháng. Không dùng API trả phí. AI chạy local. Infrastructure chạy trên nền tảng free tier.

---

## Mục lục

1. [Giới thiệu](#1-giới-thiệu)
2. [Tổng quan kiến trúc Zero-Cost](#2-tổng-quan-kiến-trúc-zero-cost)
3. [Yêu cầu chức năng (Zero-Cost Optimized)](#3-yêu-cầu-chức-năng)
4. [Yêu cầu phi chức năng](#4-yêu-cầu-phi-chức-năng)
5. [Chiến lược Tối ưu Chi phí](#5-chiến-lược-tối-ưu-chi-phí)
6. [Phụ lục](#6-phụ-lục)

---

## 1. Giới thiệu

### 1.1 Mục đích
Tài liệu này là phiên bản **Zero-Cost** của SRS Safe Zone, được thiết kế đặc biệt cho cộng đồng, cá nhân và tổ chức phi lợi nhuận **không có ngân sách vận hành**. Mọi quyết định kỹ thuật đều ưu tiên "free-as-in-beer" và "self-hosted".

### 1.2 Phạm vi
- **Included:** Toàn bộ hệ thống chống phishing hoạt động ổn định với **$0 chi phí vận hành/tháng**.
- **Excluded:** Các tính năng đòi hỏi dịch vụ trả phí (VirusTotal Premium, Cloudflare Pro, managed Redis, v.v.).

### 1.3 Định nghĩa
| Thuật ngữ | Định nghĩa |
|-----------|------------|
| **Zero-Cost** | Không phát sinh hóa đơn định kỳ hàng tháng. Có thể cần thẻ tín dụng để verify account nhưng không bị charge nếu ở trong free tier limits. |
| **Always-Free** | Dịch vụ không giới hạn thời gian sử dụng (không phải trial 30 ngày). |
| **Local AI** | Mô hình AI chạy trực tiếp trên server thông qua Ollama, không gọi API bên ngoài. |
| **Free Threat Feed** | Nguồn dữ liệu threat intelligence công khai, không yêu cầu API key trả phí. |
| **Oracle ZC** | Oracle Cloud Always Free Tier — 4 ARM vCPU + 24GB RAM + 200GB storage + 10TB egress. |
| **DuckDNS** | Dịch vụ dynamic DNS miễn phí, cung cấp subdomain `.duckdns.org`. |

---

## 2. Tổng quan kiến trúc Zero-Cost

### 2.1 Stack Zero-Cost

| Thành phần | Lựa chọn Zero-Cost | Chi phí | Ghi chú |
|------------|-------------------|---------|---------|
| **Compute** | Oracle Cloud Always Free ARM (4 vCPU / 24GB RAM) | **$0** | Hoặc Google Cloud e2-micro (2 vCPU/1GB) nếu Oracle khó đăng ký. Go chạy tốt trên ARM64. |
| **OS** | Ubuntu 22.04 LTS ARM64 | **$0** | Oracle cung cấp image sẵn. |
| **DNS Resolver** | Custom Go DNS (DoH/DoT) tự host | **$0** | Chạy trên chính Oracle VM. |
| **Core API** | Go Microservice + Goroutines | **$0** | Chạy trên cùng VM. |
| **Cache/Store** | Redis 7 (self-hosted trên cùng VM) | **$0** | Không dùng Redis Cloud / Upstash. |
| **AI Engine** | Ollama + Local LLM (Gemma 2B / Phi-2 / Llama 2 7B Q4) | **$0** | Chạy local, không API key, không rate limit. |
| **Threat Intel** | PhishTank + AbuseIPDB + URLhaus + AlienVault OTX | **$0** | All free APIs / downloadable feeds. |
| **Domain** | DuckDNS (`safezone.duckdns.org`) hoặc No-IP | **$0** | Không mua domain trả phí. |
| **SSL/TLS** | Let's Encrypt (Certbot) | **$0** | Auto-renew. |
| **Reverse Proxy** | Caddy (tích hợp auto HTTPS) hoặc Nginx | **$0** | Caddy dễ hơn cho Let's Encrypt. |
| **Monitoring** | Oracle Cloud Monitoring (included) + UptimeRobot + Grafana Cloud Free | **$0** | |
| **Backup** | rclone → Google Drive 15GB free hoặc Oracle Object Storage 20GB free | **$0** | |
| **Block Page** | Static HTML served by Go embedded hoặc Caddy | **$0** | |
| **Dashboard** | TypeScript SPA served by Caddy/Nginx | **$0** | |

### 2.2 Sơ đồ triển khai Zero-Cost (Single VM)

```
┌─────────────────────────────────────────────────────────────┐
│           ORACLE CLOUD FREE TIER (Always Free)              │
│              4 ARM vCPU + 24GB RAM + 200GB SSD              │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │              Ubuntu 22.04 LTS (ARM64)                 │  │
│  │                                                     │  │
│  │  ┌──────────┐  ┌──────────┐  ┌─────────────────┐  │  │
│  │  │  DoH/DoT │  │ Core API │  │  Redis (local)  │  │  │
│  │  │  :443    │  │  :8080   │  │    :6379        │  │  │
│  │  └──────────┘  └──────────┘  └─────────────────┘  │  │
│  │                                                     │  │
│  │  ┌──────────┐  ┌──────────┐  ┌─────────────────┐  │  │
│  │  │  Ollama  │  │  Caddy   │  │  Dashboard SPA  │  │  │
│  │  │  :11434  │  │  :80/443 │  │  (static files) │  │  │
│  │  └──────────┘  └──────────┘  └─────────────────┘  │  │
│  │                                                     │  │
│  │  ┌─────────────────────────────────────────────┐    │  │
│  │  │        Free Threat Intel Feeds              │    │  │
│  │  │  (PhishTank, AbuseIPDB, URLhaus, OTX)     │    │  │
│  │  └─────────────────────────────────────────────┘    │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                             │
│  Public IP (Free) ──► DuckDNS ──► safezone.duckdns.org     │
│  SSL: Let's Encrypt (via Caddy)                             │
│  Backup: rclone → Google Drive 15GB                         │
└─────────────────────────────────────────────────────────────┘
```

### 2.3 Giả định & Rủi ro Zero-Cost

**Giả định:**
- Người dùng có thể đăng ký Oracle Cloud Free Tier (cần credit card thật để verify, không charge).
- Nếu Oracle không khả thi, fallback sang **Google Cloud e2-micro** (2 vCPU/1GB RAM) — đủ chạy DNS + Core cho <100 users, hoặc **home server PC cũ**.
- Chấp nhận trade-off: không có HA (High Availability), single point of failure là VM duy nhất.

**Rủi ro & Giải pháp:**
| Rủi ro | Giải pháp |
|--------|-----------|
| Oracle reclaim idle instance | Cron job chạy mỗi 5 phút (lightweight CPU spike) để giữ instance active. |
| Oracle "Out of capacity" | Đăng ký region ít phổ biến hơn (Frankfurt, Singapore, Tokyo). Thử nhiều lần. |
| ARM64 compatibility | Go compile natively cho `GOARCH=arm64`. Ollama hỗ trợ ARM. Docker ARM images sẵn có. |
| 200GB storage hết | Log rotate (giữ 7 ngày), Redis maxmemory 2GB + allkeys-lru, không lưu video/media. |
| 10TB bandwidth | DNS queries rất nhỏ. 10TB = ~20 tỷ queries/tháng. Không lo. |

---

## 3. Yêu cầu chức năng (Zero-Cost Optimized)

### 3.1 Phân hệ DNS Resolver (ZC-DNS)

**ZC-DNS-001 — DoH/DoT trên Single VM:**  
Resolver lắng nghe trên port 443 (DoH) và 853 (DoT) của Oracle VM. Sử dụng IP public miễn phí của Oracle (không cần Elastic IP trả phí). Không hỗ trợ plain UDP/53 để giảm attack surface và đơn giản firewall.

**ZC-DNS-002 — DuckDNS Integration:**  
Nếu IP public là dynamic (Oracle thường giữ IP ổn định nhưng có thể đổi khi stop/start), hệ thống phải có script cron chạy mỗi 5 phút để cập nhật DuckDNS record qua HTTP API.

**ZC-DNS-003 — Cache-First Architecture:**  
Redis local trên cùng VM (port 6379, không auth hoặc auth qua env var đơn giản). TTL mặc định: BLOCKED 6 giờ, ALLOWED 3 giờ. Cache hit phải < 10ms (cùng localhost).

**ZC-DNS-004 — Fail-Open Graceful:**  
Nếu Redis down hoặc Core API timeout > 3 giây, Resolver **bắt buộc** fail-open (trả về IP thật). Không được gián đoạn Internet của người dùng vì một dịch vụ cộng đồng miễn phí.

### 3.2 Phân hệ Core Analysis (ZC-CORE)

**ZC-CORE-001 — Worker Pool trên 4 ARM vCPU:**  
Worker Pool size mặc định = 8 (4 vCPU × 2). Go scheduler trên ARM64 hoạt động hiệu quả tương đương x86.

**ZC-CORE-002 — Module Lexical (Local Only):**
- Punycode decode + Homograph detection (Unicode confusables).
- Levenshtein distance so với whitelist local (Redis Set).
- Entropy analysis cho DGA detection.
- **Không gọi API bên ngoài.**

**ZC-CORE-003 — Module x.509 (Local TLS Handshake):**
- Thực hiện TLS handshake trực tiếp đến target domain từ Oracle VM.
- Parse certificate bằng thư viện Go `crypto/x509`.
- Phân loại DV/OV/EV, check expiry, self-signed.
- **Không dùng dịch vụ certificate inspection bên thứ 3.**

**ZC-CORE-004 — Module Infrastructure (Local WHOIS + DNS):**
- WHOIS query qua command line / thư viện Go (không dùng WHOIS API trả phí).
- DNS query SPF/DKIM/DMARC trực tiếp qua thư viện Go `net`.
- **Không dùng dịch vụ DNS intelligence trả phí.**

**ZC-CORE-005 — Module Threat Intelligence (Free Feeds Only):**

| Feed | URL/API | Cách dùng | Rate Limit |
|------|---------|-----------|------------|
| **PhishTank** | `https://data.phishtank.com/data/online-valid.csv.gz` | Download CSV 1 lần/giờ, giải nén, load vào Redis Set `feed:phishtank`. | Free, không cần key |
| **URLhaus** | `https://urlhaus.abuse.ch/downloads/csv_recent/` | Download CSV recent, parse domain. | Free |
| **AbuseIPDB** | `https://api.abuseipdb.com/api/v2/check` | Check IP reputation nếu cần. Free tier: 1,000 checks/ngày. | 1,000/day free |
| **AlienVault OTX** | `https://otx.alienvault.com/api/v1/` | Pulses về phishing domains. | Generous free tier |
| **REScure** | `https://rescure.me/rescure_feed.json` | JSON feed cập nhật mỗi 6 giờ. | Free |

- **Update Schedule:** Cron job chạy mỗi 30 phút để fetch các feed trên, merge vào Redis Set `threat:feed:combined`. TTL của feed data: 24 giờ.
- **Offline Mode:** Nếu fetch thất bại (network down), sử dụng feed data cũ trong Redis (không fail vì thiếu feed mới).

**ZC-CORE-006 — Local AI Module (Ollama):**
- **Cài đặt:** Ollama chạy trên cùng VM (port 11434), chỉ bind localhost (`127.0.0.1:11434`) để tránh expose ra ngoài.
- **Model:** Sử dụng model nhẹ phù hợp ARM64 + 24GB RAM:
  - **Gemma 2B** (~1.5GB RAM) — đủ cho classification đơn giản.
  - **Phi-2** (~2.5GB RAM) — reasoning tốt hơn.
  - **Llama 2 7B Q4_K_M** (~5GB RAM) — nếu cần chất lượng cao hơn, vẫn còn ~19GB RAM cho hệ thống.
- **Prompt Template:**
```
Bạn là chuyên gia bảo mật. Phân tích domain sau: {domain}
Thông tin: Tuổi domain {age} ngày, SSL {ssl_type}, Levenshtein match {match}

Trả lời CHÍNH XÁC theo JSON:
{"verdict": "SAFE|SUSPICIOUS|MALICIOUS", "confidence": 0.0-1.0, "reason": "giải thích ngắn"}
```
- **Timeout:** 3 giây. Nếu Ollama chưa load model (cold start), timeout 10 giây cho lần đầu.
- **No API Key:** Không cần API key, không có rate limit, không có chi phí per-token.

**ZC-CORE-007 — Risk Score Engine (Simplified):**
- Trọng số mặc định (không cần admin điều chỉnh liên tục):
  - Lexical: 30%
  - x.509: 20%
  - Infrastructure: 25%
  - Threat Feed: 15%
  - Local AI: 10%
- Override: Nếu domain trong PhishTank/URLhaus → min score 90. Nếu trong whitelist → score 0.

### 3.3 Phân hệ UI/UX (ZC-UI)

**ZC-UI-001 — Block Page (Static HTML):**  
Không cần React/Vue build phức tạp. Dùng static HTML + CSS thuần (dark mode, geometric typography) được serve bởi Caddy hoặc embedded Go HTTP server. File size < 100KB.

**ZC-UI-002 — Admin Dashboard (Lightweight SPA):**  
Có thể dùng **Vanilla TypeScript** (không framework) hoặc Alpine.js (~15KB) thay vì React/Vue để giảm bundle size và build complexity. Dashboard chỉ cần:
- Hiển thị log (fetch từ Redis Stream qua API).
- Bảng whitelist/blacklist (CRUD đơn giản).
- Biểu đồ cơ bản dùng Chart.js từ CDN (không build step phức tạp).

**ZC-UI-003 — No Real-time WebSocket:**  
Thay vì WebSocket/SSE (tốn kết nối duy trì), Dashboard poll API mỗi 5 giây. Đơn giản, đủ dùng cho admin cá nhân.

### 3.4 Phân hệ System & DevOps (ZC-SYS)

**ZC-SYS-001 — Single Binary Deployment:**  
Ưu tiên compile Go thành single static binary (`CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build`) thay vì Docker nếu muốn tiết kiệm resource. Tuy nhiên Docker vẫn được hỗ trợ cho dễ quản lý.

**ZC-SYS-002 — Docker Compose (Free Edition):**  
Nếu dùng Docker, tất cả services chạy trên cùng VM trong một `docker-compose.yml`:
- `dns-resolver`: Go binary, port 443/853.
- `core-api`: Go binary, port 8080.
- `redis`: `redis:7-alpine` image (ARM64 sẵn có).
- `ollama`: `ollama/ollama` image (ARM64 sẵn có).
- `caddy`: `caddy:2-alpine` reverse proxy + static file server.
- `dashboard`: Static files volume-mounted vào Caddy.

**ZC-SYS-003 — Log Rotation:**  
Dùng `logrotate` của Ubuntu (có sẵn) để giữ log file dưới 5GB tổng cộng. Cấu hình giữ 7 ngày log. Không cần ELK/Loki.

**ZC-SYS-004 — Backup Script:**  
Script bash chạy cron hàng ngày:
- `redis-cli SAVE` để tạo RDB dump.
- `rclone copy` RDB dump + config files lên Google Drive 15GB free (hoặc Oracle Object Storage 20GB free).

---

## 4. Yêu cầu phi chức năng

### 4.1 Hiệu năng trên Free Tier

**ZC-NFR-PERF-001:**  
Với 4 ARM vCPU + 24GB RAM, hệ thống phải xử lý **tối thiểu 500 queries/giây** (Cache Hit) và **50 queries/giây** (Cache Miss với full analysis + local AI).

**ZC-NFR-PERF-002:**  
Ollama model Gemma 2B phải trả lời trong < 2 giây (warm). Llama 2 7B Q4 trong < 5 giây (warm).

**ZC-NFR-PERF-003:**  
Memory footprint toàn hệ thống (Go services + Redis + Ollama 2B) không vượt quá **8GB RAM**, để còn dư phòng cho burst và OS.

### 4.2 Bảo mật

**ZC-NFR-SEC-001:**  
Ollama chỉ bind `127.0.0.1:11434`. Không expose ra public internet. Core API gọi Ollama qua localhost.

**ZC-NFR-SEC-002:**  
Redis không expose port 6379 ra ngoài (bind localhost hoặc Docker internal network). Không cần Redis ACL phức tạp vì single-tenant.

**ZC-NFR-SEC-003:**  
Caddy tự động HTTPS (Let's Encrypt). Không cần cert management thủ công.

**ZC-NFR-SEC-004:**  
Oracle Cloud Security List chỉ mở port 22 (SSH), 443 (DoH/Dashboard), 853 (DoT). Các port khác (8080, 6379, 11434) chỉ internal.

### 4.3 Độ tin cậy

**ZC-NFR-REL-001:**  
Chấp nhận **không có SLA**. Hệ thống là best-effort. Tuy nhiên phải có:
- Cron job giữ instance alive (tránh Oracle reclaim).
- Auto-restart Docker containers (`restart: unless-stopped`).
- Redis RDB snapshot mỗi 15 phút.

**ZC-NFR-REL-002:**  
Nếu toàn bộ VM crash/reboot, hệ thống phải tự khởi động lại trong < 2 phút nhờ systemd service hoặc Docker restart policy.

---

## 5. Chiến lược Tối ưu Chi phí

### 5.1 So sánh Nền tảng Free Tier

| Nền tảng | Compute | RAM | Storage | Bandwidth | Rủi ro | Khuyến nghị |
|----------|---------|-----|---------|-----------|--------|-------------|
| **Oracle Cloud** | 4 ARM vCPU | 24GB | 200GB | 10TB/tháng | Account khó đăng ký, có thể reclaim idle | **⭐ Tốt nhất** |
| **Google Cloud** | 2 vCPU (shared) | 1GB | 30GB | 1GB–200GB | Rất ổn định, dễ đăng ký | **Dùng nếu Oracle fail** |
| **AWS Lambda** | 1M req/tháng free | 512MB | Ephemeral | 1GB | Cold start, không phù hợp DNS resolver liên tục | Không khuyến nghị |
| **Home Server** | Tùy PC cũ | Tùy | Tùy | Tùy upload | IP động, điện mất | **Lab/backup** |

### 5.2 Chi phí thực tế theo kịch bản

| Kịch bản | Chi phí / tháng | / năm | Lưu ý |
|----------|----------------|-------|-------|
| **Oracle Cloud + DuckDNS + Let's Encrypt + Local AI** | **$0** | **$0** | Cần credit card verify. Không bị charge nếu trong limits. |
| **Google Cloud e2-micro + DuckDNS** | **$0** | **$0** | Chỉ 1GB RAM → phải bỏ Ollama, dùng rule-based only. |
| **Home Server PC cũ + DDNS** | **$3–5** (điện) | **$36–60** | Không phụ thuộc cloud provider. |
| **VPS trả phí rẻ nhất (Hetzner)** | **$8.20** | **$98** | Backup nếu Oracle/Google không khả thi. |

### 5.3 Checklist Triển khai Zero-Cost

**Bước 1: Đăng ký Oracle Cloud Free Tier**
- Truy cập signup.cloud.oracle.com
- Dùng credit/debit card thật (không prepaid/virtual card)
- Chọn region: `ap-singapore-1` hoặc `eu-frankfurt-1` (thường có capacity hơn US regions)
- Tạo instance: Ampere A1 Flex, 4 OCPU, 24GB RAM, Ubuntu 22.04 ARM64
- Mở port 22, 80, 443, 853 trong Security List

**Bước 2: Cài đặt Base System**
```bash
# Update & install essentials
sudo apt update && sudo apt install -y docker.io docker-compose git curl

# Enable Docker
sudo systemctl enable docker

# Install Ollama (ARM64 supported)
curl -fsSL https://ollama.com/install.sh | sh

# Pull lightweight model
ollama pull gemma:2b
# Hoặc nếu muốn chất lượng cao hơn và đủ RAM:
# ollama pull llama2:7b
```

**Bước 3: DuckDNS Auto-Update**
```bash
# Script giữ IP cập nhật
curl -k "https://www.duckdns.org/update?domains=safezone&token=YOUR_TOKEN&ip=" | cron
```

**Bước 4: Anti-Idle (Giữ Oracle Alive)**
```bash
# Cron job mỗi 5 phút
*/5 * * * * echo $(date) >> /tmp/keepalive.log && curl -s https://hc-ping.com/YOUR_ENDPOINT
```

**Bước 5: Backup Daily**
```bash
# Cron hàng ngày 2AM
0 2 * * * redis-cli SAVE && rclone copy /var/lib/redis/dump.rdb gdrive:safe-zone-backup/$(date +\%Y\%m\%d)
```

---

## 6. Phụ lục

### Phụ lục A: Free Threat Feed URLs (Cập nhật 2026)

| Feed | URL | Format | Update Freq |
|------|-----|--------|-------------|
| PhishTank | `http://data.phishtank.com/data/online-valid.csv.gz` | CSV gzip | Real-time |
| URLhaus | `https://urlhaus.abuse.ch/downloads/csv_recent/` | CSV | 5 phút |
| URLhaus (full) | `https://urlhaus.abuse.ch/downloads/csv/` | CSV | 5 phút |
| AbuseIPDB | `https://api.abuseipdb.com/api/v2/check` | JSON | On-demand |
| AlienVault OTX | `https://otx.alienvault.com/api/v1/pulses/subscribed` | JSON | On-demand |
| REScure | `https://rescure.me/rescure_feed.json` | JSON | 6 giờ |
| OpenPhish | `https://openphish.com/feed.txt` | Text (URL per line) | Real-time |

### Phụ lục B: Ollama Models cho ARM64

| Model | Size | RAM cần | Use case | Speed (ARM A1) |
|-------|------|---------|----------|----------------|
| `gemma:2b` | ~1.5GB | ~2GB | Phân loại nhanh | ~15-20 tok/s |
| `phi` | ~2GB | ~2.5GB | Reasoning | ~10-15 tok/s |
| `llama2:7b` | ~5GB | ~6GB | Chất lượng cao | ~5-8 tok/s |
| `mistral:7b` | ~5GB | ~6GB | Đa năng | ~5-8 tok/s |

> Lưu ý: Model lần đầu load có thể mất 10-30 giây (cold start). Sau đó giữ resident trong RAM.

### Phụ lục C: Docker Compose Zero-Cost

```yaml
version: '3.8'
services:
  redis:
    image: redis:7-alpine
    restart: unless-stopped
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes --maxmemory 2gb --maxmemory-policy allkeys-lru
    networks:
      - safe-zone

  ollama:
    image: ollama/ollama:latest
    restart: unless-stopped
    volumes:
      - ollama_data:/root/.ollama
    networks:
      - safe-zone
    # Không expose port ra ngoài, chỉ internal

  core-api:
    build: ./core
    restart: unless-stopped
    environment:
      - REDIS_ADDR=redis:6379
      - OLLAMA_HOST=http://ollama:11434
      - OLLAMA_MODEL=gemma:2b
    depends_on:
      - redis
      - ollama
    networks:
      - safe-zone

  dns-resolver:
    build: ./dns
    restart: unless-stopped
    ports:
      - "443:443"
      - "853:853"
    environment:
      - CORE_API_URL=http://core-api:8080
      - REDIS_ADDR=redis:6379
    depends_on:
      - core-api
      - redis
    networks:
      - safe-zone
    cap_add:
      - NET_BIND_SERVICE

  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - ./dashboard/dist:/srv/dashboard
      - caddy_data:/data
      - caddy_config:/config
    networks:
      - safe-zone

networks:
  safe-zone:
    driver: bridge

volumes:
  redis_data:
  ollama_data:
  caddy_data:
  caddy_config:
```

### Phụ lục D: Caddyfile Zero-Cost

```
# Caddyfile
safezone.duckdns.org {
    # Block Page + Dashboard
    handle /block/* {
        root * /srv/dashboard/block
        file_server
    }

    handle /admin/* {
        root * /srv/dashboard/admin
        file_server
    }

    # DoH endpoint
    handle /dns-query {
        reverse_proxy dns-resolver:443
    }

    # Default redirect
    redir / /admin/
}

# DoT (DNS over TLS) — Caddy không hỗ trợ native DoT, 
# nên DoT được handle trực tiếp bởi dns-resolver container trên port 853.
```

### Phụ lục E: Environment Variables (Zero-Cost)

| Variable | Giá trị mặc định | Mô tả |
|----------|-----------------|-------|
| `SAFE_ZONE_ENV` | `production` | |
| `SAFE_ZONE_DNS_DOH_PORT` | `443` | |
| `SAFE_ZONE_DNS_DOT_PORT` | `853` | |
| `SAFE_ZONE_REDIS_ADDR` | `redis:6379` | |
| `SAFE_ZONE_RISK_THRESHOLD` | `70` | |
| `SAFE_ZONE_TTL_BLOCKED` | `21600` | 6 giờ |
| `SAFE_ZONE_TTL_ALLOWED` | `10800` | 3 giờ |
| `SAFE_ZONE_WORKER_POOL_SIZE` | `8` | |
| `SAFE_ZONE_OLLAMA_HOST` | `http://ollama:11434` | |
| `SAFE_ZONE_OLLAMA_MODEL` | `gemma:2b` | |
| `SAFE_ZONE_OLLAMA_TIMEOUT` | `3000` | ms |
| `SAFE_ZONE_FEED_UPDATE_INTERVAL` | `1800` | 30 phút |
| `SAFE_ZONE_LOG_RETENTION_DAYS` | `7` | |
| `SAFE_ZONE_DUCKDNS_DOMAIN` | `safezone` | |
| `SAFE_ZONE_DUCKDNS_TOKEN` | `` | |
| `SAFE_ZONE_BLOCK_PAGE_IP` | `127.0.0.1` | |

---

**End of Zero-Cost SRS**

> **Commitment:** Với tài liệu này, Safe Zone có thể được triển khai và vận hành với **$0 chi phí hàng tháng**, phục vụ cộng đồng bền vững mà không phụ thuộc vào ngân sách.
