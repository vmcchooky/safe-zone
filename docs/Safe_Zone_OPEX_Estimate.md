# Ước tính Chi phí Vận hành (OPEX) — Safe Zone Anti-Phishing System

> **Lưu ý:** Chỉ tính chi phí vận hành (OPEX). Không bao gồm chi phí phát triển (dev cost) vì bạn tự code bằng AI free.
> Tỷ giá tham khảo: **1 USD ≈ 25,000 VND** (2026).
>
> Cost-sensitive roadmap changes should also follow [docs/specs/opex-cost-optimization/policy.md](specs/opex-cost-optimization/policy.md) and the PR checklist at [.github/pull_request_template.md](../.github/pull_request_template.md).

---

## 1. Giả định Lưu lượng & Tải hệ thống

| Chỉ số | Giá trị | Ghi chú |
|--------|---------|---------|
| **DNS Queries trung bình** | 100 – 1,000 queries/giây | Theo SRS NFR-PERF-003 |
| **Kích thước query trung bình** | ~500 bytes (DoH/DoT bao gồm TLS overhead) | DNS payload nhỏ, TLS handshake có cache |
| **Bandwidth thô ước tính** | ~13 GB – 130 GB / ngày | 100 qps → ~4 TB/tháng; 1000 qps → ~40 TB/tháng |
| **Cache Hit Rate (kỳ vọng)** | 80 – 95% | Redis local cache giảm đáng kể gọi Core API |
| **Core API calls (Cache Miss)** | ~2 – 10 triệu lần / tháng | Tùy cache hit rate và query volume |
| **External API calls** | ~500 – 5,000 lần / ngày | Chỉ gọi khi cache miss + domain mới/chưa rõ |

---

## 2. Chi phí Thành phần theo Tháng

### 2.1. Máy chủ / VPS (Infrastructure)

| Nhà cung cấp | Gói | vCPU | RAM | SSD | Transfer | Giá/tháng | Phù hợp |
|-------------|-----|------|-----|-----|----------|-----------|---------|
| **Hetzner** | CPX21 | 2 | 4 GB | 80 GB | 20 TB | **$8.20** (~205kđ) | ⭐ Tốt nhất giá/ hiệu năng |
| **Vultr** | High Freq 4GB | 2 | 4 GB | 100 GB | 5 TB | **$24.00** (~600kđ) | Ổn định, nhiều DC |
| **DigitalOcean** | Basic 4GB | 2 | 4 GB | 80 GB | 4 TB | **$24.00** (~600kđ) | Dev-friendly |
| **Linode (Akamai)** | Shared 4GB | 2 | 4 GB | 80 GB | 4 TB | **$24.00** (~600kđ) | Bandwidth tốt |
| **AWS Lightsail** | 4GB 2cores | 2 | 4 GB | 80 GB | 4 TB | **$24.00** (~600kđ) | Nếu đã dùng AWS |
| **OVH** | VPS Starter | 1 | 2 GB | 40 GB | 10 TB | **~$4.00** (~100kđ) | Rẻ nhưng ít vCPU |

> **Khuyến nghị:** Với Safe Zone v1.0 (single-node), **Hetzner CPX21 ($8.20/tháng)** là lựa chọn tối ưu nhất. Nếu cần hỗ trợ tại Đông Nam Á, chọn **Vultr Singapore** ($24/tháng).

### 2.2. Tên miền & SSL

| Hạng mục | Chi phí | Ghi chú |
|----------|---------|---------|
| **Domain .com / .net** | ~$1/tháng ($10–14/năm) | Namecheap, Cloudflare Registrar |
| **SSL Certificate** | **$0** | Let's Encrypt tự động renew (Certbot) |
| **DDNS (nếu home server)** | **$0** | DuckDNS, No-IP free tier |

### 2.3. External APIs (Threat Intelligence + AI)

| Dịch vụ | Free Tier | Paid nếu vượt | Chi phí thực tế |
|---------|-----------|---------------|-----------------|
| **Google Safe Browsing API v4** | 10,000 req / 100 giây (~8.6M/ngày) | Không cần paid cho quy mô này | **$0** |
| **VirusTotal API v3** | 500 lookups / ngày | Enterprise ~$10,000–50,000/năm (quá đắt) | **$0** *(chiến lược dùng bên dưới)* |
| **WHOIS (command line)** | Không giới hạn rõ ràng, nhưng rate limit thấp | WHOIS API paid ~$3–5/tháng | **$0** *(dùng CLI + cache)* |
| **Google Gemini 1.5 Flash** | 60 req/phút (~86,400/ngày) | Pay-as-you-go sau quota | **$0** |
| **OpenAI GPT-4o-mini** | Free credits ban đầu (~$5) | ~$0.60 / 1M tokens | **$0–5** |
| **AbuseIPDB** | 1,000 lookups / ngày | $5–150/tháng | **$0** *(dự phòng VT)* |
| **URLhaus** | Unlimited (miễn phí) | Không có paid tier | **$0** |
| **AlienVault OTX** | Generous free tier | Miễn phí cho hầu hết use case | **$0** |

> **Chiến lược tiết kiệm API:**
> - Dùng **Local Cache (Redis)** và **Local Threat Feed** để giảm 90%+ external API calls.
> - VirusTotal chỉ gọi khi domain "ambiguous" (Risk Score 40–75). Các domain rõ ràng độc hại/sạch thì dùng rule local.
> - AI API (Gemini) chỉ gọi khi 4 module truyền thống không đủ quyết định. Với 1,000 qps, nếu chỉ 1% cần AI → ~864 req/ngày → vẫn trong free tier.

### 2.4. Lưu trữ & Backup

| Hạng mục | Chi phí | Ghi chú |
|----------|---------|---------|
| **Redis RDB snapshot** | Local disk (đã có trong VPS SSD) | **$0** |
| **Object Storage (backup log)** | 50–100 GB | Backblaze B2: $0.005/GB = **$0.25–0.50/tháng**; DO Spaces: $5/tháng |
| **Snapshot VPS** | ~$0.05/GB-tháng | Chỉ cần 1 snapshot 20GB = **$1/tháng** |

### 2.5. Giám sát & Cảnh báo

| Công cụ | Chi phí | Ghi chú |
|---------|---------|---------|
| **UptimeRobot** | **$0** | 50 monitors, 5 phút interval |
| **Grafana Cloud** | **$0** | 10,000 metrics, 50GB log (free tier) |
| **Prometheus + Alertmanager** | **$0** | Self-hosted trên chính VPS |

---

## 3. Tổng hợp theo Kịch bản Triển khai

### Kịch bản A: Home Server / Self-Host (Tiết kiệm tối đa)

> Dùng PC cũ / Raspberry Pi 4 / Mini PC tại nhà. Cần IP public (hoặc dùng tunnel như Cloudflare Tunnel/ ngrok không phù hợp production lắm).

| Hạng mục | Chi phí/tháng |
|----------|---------------|
| Điện (PC 50W × 24h × 30 ngày = 36 kWh) | **$3–9** (72k–216kđ) |
| Internet (đã có sẵn, không phát sinh thêm) | **$0** |
| Domain | **$1** |
| API & Services | **$0** |
| **TỔNG** | **~$4–10 / tháng** (~100k–250kđ) |

> ⚠️ **Rủi ro:** IP động (cần DDNS), điện mất là hệ thống down, upload bandwidth hạn chế, không chuyên nghiệp.

---

### Kịch bản B: Single VPS — Budget (Hetzner / OVH)

> Chạy toàn bộ trên 1 VPS duy nhất: DNS Resolver + Core API + Redis + Dashboard.

| Hạng mục | Chi phí/tháng |
|----------|---------------|
| **VPS Hetzner CPX21** (2vCPU/4GB/20TB) | **$8.20** |
| Domain .com | **$1.00** |
| Let's Encrypt SSL | **$0** |
| External APIs (free tier) | **$0** |
| Backup (RDB local + 1 snapshot) | **$1.00** |
| Monitoring (UptimeRobot + Grafana) | **$0** |
| **TỔNG** | **~$10 / tháng** (~250kđ) |
| **TỔNG / năm** | **~$120 / năm** (~3 triệu đồng) |

> ✅ **Phù hợp:** Personal project, thử nghiệm production, < 500 users.

---

### Kịch bản C: Single VPS — Standard (Vultr / DO / Linode)

> VPS 4GB RAM tại datacenter gần người dùng (Singapore/Japan cho VN).

| Hạng mục | Chi phí/tháng |
|----------|---------------|
| **VPS Vultr HF 4GB** (Singapore) | **$24.00** |
| Domain + DNS | **$1.00** |
| Object Storage (log backup 50GB) | **$2.50** |
| Snapshot | **$1.00** |
| External APIs | **$0** |
| Monitoring | **$0** |
| **TỔNG** | **~$28–30 / tháng** (~700k–750kđ) |
| **TỔNG / năm** | **~$340 / năm** (~8.5 triệu đồng) |

> ✅ **Phù hợp:** Production thật sự, 1,000+ users, cần uptime ổn định, support tốt.

---

### Kịch bản D: Multi-Node Production (Tách biệt dịch vụ)

> Tách DNS, Core API, Redis thành các node riêng để chịu tải và bảo mật tốt hơn.

| Hạng mục | Spec | Chi phí/tháng |
|----------|------|---------------|
| **Node DNS Resolver** | 1vCPU / 2GB RAM | **$6–12** (Vultr HF 2GB) |
| **Node Core API** | 2vCPU / 4GB RAM | **$12–24** (Vultr HF 4GB) |
| **Node Redis + Dashboard** | 1vCPU / 2GB RAM | **$6–12** (Vultr HF 2GB) |
| **Load Balancer** | Cloudflare (free) hoặc DO LB | **$0–12** |
| **Domain + DNS** | | **$1** |
| **Object Storage (log/backup)** | 100 GB | **$5** |
| **External APIs** | | **$0** |
| **Monitoring** | Grafana Cloud free | **$0** |
| **TỔNG** | | **~$40–65 / tháng** (~1.0–1.6 triệu đồng) |
| **TỔNG / năm** | | **~$500–780 / năm** (~12.5–19.5 triệu đồng) |

> ✅ **Phù hợp:** Doanh nghiệp nhỏ, ISP nhỏ, tổ chức cần HA cơ bản.

---

### Kịch bản E: High Availability (HA) — Cloud Scale

> Dùng cho tổ chức lớn, ISP, hoặc triển khai rộng. Nhiều node + redundancy.

| Hạng mục | Số lượng | Đơn giá | Chi phí/tháng |
|----------|----------|---------|---------------|
| **DNS Resolver nodes** | 2 | $12 | **$24** |
| **Core API nodes** | 2 | $24 | **$48** |
| **Redis Cluster** | 3 nodes | $12 | **$36** |
| **Dashboard node** | 1 | $6 | **$6** |
| **Load Balancer (Cloud)** | 1 | $20 | **$20** |
| **Object Storage (2TB)** | | | **$20** |
| **Domain + DNS Pro** | | | **$2** |
| **Monitoring (Datadog/ New Relic)** | | | **$15–30** |
| **External APIs (VT + AI nếu vượt free)** | | | **$50–200** |
| **TỔNG** | | | **~$220–400 / tháng** (~5.5–10 triệu đồng) |
| **TỔNG / năm** | | | **~$2,600–4,800 / năm** (~65–120 triệu đồng) |

> ⚠️ **Lưu ý:** VirusTotal Enterprise có thể đẩy chi phí lên $10,000–50,000/năm. Nếu cần >500 req/ngày, hãy cân nhắc dùng **AlienVault OTX + AbuseIPDB + URLhaus** thay thế hoàn toàn.

---

## 4. Bảng So sánh Tổng hợp

| Kịch bản | Chi phí / tháng | Chi phí / năm | Phù hợp với |
|----------|----------------|---------------|-------------|
| **A. Home Server** | $4–10 | $50–120 | Cá nhân thử nghiệm, lab |
| **B. Single VPS Budget** | **$10** ⭐ | **$120** | MVP, personal project, <500 users |
| **C. Single VPS Standard** | $28–30 | $340 | Production SME, 1,000+ users |
| **D. Multi-Node** | $40–65 | $500–780 | Doanh nghiệp nhỏ, ISP nhỏ |
| **E. HA Cloud Scale** | $220–400 | $2,600–4,800 | Tổ chức lớn, ISP, chính phủ |

---

## 5. Chiến lược Tối ưu Chi phí (Cost Optimization)

### 5.1. Giảm chi phí VPS
- **Hetzner Cloud** luôn rẻ hơn 50–70% so với DigitalOcean/Vultr cho cùng cấu hình. Nếu latency chấp nhận được (DC ở Đức/Phần Lan), đây là lựa chọn tốt nhất.
- Dùng **Cloudflare Tunnel** nếu không có IP public static (tránh thuê IP riêng $3–5/tháng).
- Tắt snapshot tự động nếu không cần, chỉ snapshot thủ công trước khi update.

### 5.2. Giảm chi phí API
- **Cache aggressively:** Redis TTL cho Risk Score nên đủ dài (1–6 giờ cho domain đã phân tích). Một domain chỉ cần phân tích 1 lần/ngày.
- **Tiered analysis:** Chỉ gọi VT/GSB khi local modules (Levenshtein, WHOIS age, x.509) cho kết quả ambiguous (40–75 điểm).
- **Batch processing:** Gom nhiều domain kiểm tra VirusTotal vào 1 request (nếu API hỗ trợ multi-lookup).
- **Dùng nguồn thay thế miễn phí:**
  - Thay VT: AbuseIPDB (1,000/day), URLhaus (unlimited), AlienVault OTX.
  - Thay AI paid: Gemini Flash free 60 req/phút là đủ cho hầu hết use case.

### 5.3. Giảm chi phí Bandwidth
- **DNS over HTTPS (DoH)** nén tốt hơn DoT và dễ cache ở CDN edge.
- Nếu dùng Cloudflare DNS proxy (không phải resolver), có thể giảm bandwidth ra origin. Tuy nhiên với custom resolver, bandwidth chủ yếu là DNS payload rất nhỏ.

### 5.4. Giảm chi phí Backup
- Redis RDB snapshot lưu local đã đủ cho v1.0. Chỉ cần copy RDB file ra máy tính cá nhân 1 lần/tuần.
- Dùng **rclone + Google Drive free 15GB** để backup log thay vì S3 paid.

---

## 6. Kết luận & Khuyến nghị

| Mục tiêu của bạn | Chi phí tối thiểu / năm | Lựa chọn |
|------------------|------------------------|----------|
| **Chỉ thử nghiệm, học tập** | **$50–120** (~1.2–3 triệu đồng) | Home Server PC cũ + DDNS |
| **Triển khai thật cho cộng đồng nhỏ** | **$120** (~3 triệu đồng) ⭐ | **Hetzner CPX21 Single Node** |
| **Production ổn định cho doanh nghiệp** | **$340** (~8.5 triệu đồng) | Vultr/DigitalOcean 4GB Singapore |
| **Hệ thống phân tán, HA cơ bản** | **$600–780** (~15–19 triệu đồng) | Multi-node Vultr/Linode |

> **💡 Lời khuyên thực tế nhất:**
> Bắt đầu bằng **Kịch bản B (Hetzner $10/tháng)** hoặc **Kịch bản C (Vultr $28/tháng)**. Safe Zone v1.0 hoàn toàn có thể chạy mượt trên 1 VPS 2vCPU/4GB vì:
> - Go goroutines cực kỳ nhẹ.
> - Redis in-memory nhanh.
> - DNS query là I/O bound, không CPU bound.
> 
> Chỉ nâng lên Multi-node khi bạn thực sự có > 10,000 users hoặc cần SLA 99.9%.

---

*Document generated: 2026-05-18*  
*Dữ liệu giá VPS tham khảo từ: Hetzner, Vultr, DigitalOcean, Linode, AWS Lightsail (2026).*
