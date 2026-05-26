# Hướng dẫn deploy Safe Zone bằng gói free / trial cho `quorix.io.vn`

**Ngày cập nhật:** 2026-05-21  
**Dự án:** Safe Zone  
**Domain chính:** `quorix.io.vn`  
**Website hiện tại:** Hugo đang chạy trên Vercel  
**DNS / nhà đăng ký domain:** PA Viet Nam  
**Subdomain khuyến nghị để test:** `safe.quorix.io.vn`

> Bản này là phiên bản tiếng Việt, chi tiết hơn, tập trung vào việc **test bằng gói free / trial**.  
> Nguyên tắc sống còn: **không đụng vào DNS của `quorix.io.vn` và `www.quorix.io.vn`** nếu bạn chưa muốn chuyển website chính khỏi Vercel.

---

## 0. Kết luận nhanh

Nếu mục tiêu của bạn là deploy Safe Zone **đầy đủ tính năng**, gồm:

- Docker Compose nhiều container;
- Caddy tự cấp HTTPS;
- Redis;
- dashboard;
- API `/v1/analyze`;
- DoH `/dns-query` qua HTTPS;
- DoT qua port `853/tcp`;

thì bạn nên dùng **VPS / Cloud VM thật**.

Nếu chỉ muốn demo nhẹ API/web thì có thể dùng Render, Koyeb, Railway hoặc Cloud Run-style hosting, nhưng đó chỉ là **bản rút gọn**, không phải Safe Zone đầy đủ.

---

## 1. Vì sao khó có VPS free đúng cấu hình?

Cấu hình bạn muốn là:

```text
Ubuntu 24.04 LTS
2 vCPU
2–4 GB RAM
40+ GB disk
1 public IPv4
Docker + Docker Compose
Mở được inbound 80/tcp, 443/tcp, 853/tcp
```

Nếu loại Oracle ra, hiện tại gần như **không có VPS free vĩnh viễn** nào đáp ứng trọn bộ cấu hình này.

Lý do:

1. **Public IPv4 đắt và dễ bị abuse.**  
   Nhiều nền tảng free chỉ cho endpoint HTTP/HTTPS qua proxy, không cho bạn toàn quyền public IPv4.

2. **2–4 GB RAM vượt quá đa số gói free.**  
   Gói free phổ biến thường chỉ 512 MB đến 1 GB RAM.

3. **Port `853/tcp` cho DoT là vấn đề lớn.**  
   PaaS như Render/Koyeb/Railway thường không cho mở TCP port tùy ý kiểu VPS.

4. **Free tier hay sleep, suspend, hoặc giới hạn runtime.**  
   Dùng để demo được, nhưng không nên xem là hạ tầng production.

Vì vậy, cách đúng không phải là đi săn “VPS free thần thánh”, mà là chọn đúng **profile test**.

---

## 2. Chọn hướng deploy nào?

| Hướng | Phù hợp khi | Hỗ trợ Docker Compose | Hỗ trợ custom domain | Hỗ trợ DoH | Hỗ trợ DoT `853` | Kết luận |
|---|---|---:|---:|---:|---:|---|
| **A. Full VPS / Cloud VM test** | Muốn test gần production nhất | Có | Có | Có | Có, nếu firewall mở | Nên chọn nếu muốn test Safe Zone đầy đủ |
| **B. API-only PaaS demo** | Chỉ demo dashboard/API | Thường không, thường chỉ 1 container | Có | Có thể | Không | Dùng để demo nhanh, không đầy đủ |
| **C. Local Docker + Cloudflare Tunnel** | Muốn zero cloud cost | Có, chạy local | Có | Có | Không phù hợp cho public DoT | Rất tốt để test nội bộ / demo HTTPS |

Khuyến nghị của mình:

1. **Muốn test đầy đủ:** dùng Azure Free Account hoặc Google Cloud trial credit.
2. **Muốn không tốn tiền cloud:** dùng local Docker + Cloudflare Tunnel.
3. **Muốn demo API nhanh:** dùng Render/Koyeb/Railway, nhưng chấp nhận cắt bớt tính năng.

---

## 3. Bảng so sánh gói free / trial

> Giới hạn free tier thay đổi thường xuyên. Trước khi nhập thẻ hoặc deploy, hãy kiểm tra lại trang pricing chính thức.

| Nền tảng | Loại miễn phí | Tài nguyên liên quan | Disk | Public IPv4 | Custom domain | Chạy 24/7? | Phù hợp Safe Zone không? |
|---|---|---:|---:|---:|---:|---:|---|
| **Google Cloud Free Tier** | Always-free nhỏ + $300 trial credit cho user mới | Always-free `e2-micro`, yếu cho full stack | 30 GB-month standard persistent disk ở region đủ điều kiện | Có thể có external IP, coi chừng billing | Có | Có trong giới hạn | Dùng free tier chỉ hợp API nhẹ; dùng trial credit để test VM 2 vCPU/4 GB |
| **AWS Free Tier** | EC2 micro 12 tháng | Thường `t2.micro`/`t3.micro`, khoảng 1 GB RAM | 30 GB EBS baseline | Có, nhưng IPv4/bandwidth có điều kiện tính phí | Có | Có trong 750 giờ/tháng | Không đủ RAM cho full stack; chỉ test tối giản |
| **Azure Free Account** | Free services 12 tháng + credit ban đầu | VM free-eligible như B-series tùy vùng | Cần chọn đúng disk free-eligible | Có public IP nếu cấu hình đúng | Có | Có trong 750 giờ/tháng | Ứng viên non-Oracle tốt nhất để test VM |
| **Render Free** | Free web service | Web service, không phải VPS | Managed/giới hạn | Không có VM IPv4 trực tiếp | Có | Có thể sleep/suspend | Demo dashboard/API, không DoT |
| **Koyeb Free** | Free web service nhỏ | Rất nhỏ, thường 0.1 vCPU/512 MB RAM/2 GB SSD | 2 GB SSD | Không có VM IPv4 trực tiếp | Có | Có giới hạn | Quá nhỏ cho full stack; chỉ demo/mock |
| **Railway** | Trial/credit-based | App hosting, không phải VPS | Volume nhỏ | Không có VM IPv4 trực tiếp | Có | Phụ thuộc credit | Demo nhanh, không full Safe Zone |
| **Fly.io** | Trial/usage-based | MicroVM nhưng không phải free VPS dài hạn | Có volume nhưng tính phí/giới hạn | Proxy/anycast, không giống VPS IPv4 thường | Có | Phụ thuộc trial/plan | Mạnh về kỹ thuật nhưng không phải lựa chọn free lâu dài |
| **Vercel** | Frontend/serverless | Rất tốt cho Hugo/Next/static | Không phải VPS disk | Không | Có | Có cho frontend | Giữ Hugo site ở đây, không deploy Safe Zone full stack |
| **Cloudflare Tunnel + máy local** | Tunnel miễn phí, compute local | Dùng tài nguyên laptop/mini PC | Disk local | Không cần public IPv4 | Có | Máy phải bật | Rất tốt để demo HTTPS dashboard/API, không public DoT `853` |

---

## 4. Layout domain an toàn

Hiện tại bạn đang có:

```text
quorix.io.vn      -> Hugo site trên Vercel
www.quorix.io.vn  -> Hugo site trên Vercel
```

Không đụng hai cái này.

Tạo subdomain riêng cho Safe Zone:

```text
safe.quorix.io.vn        -> bản VM/VPS đầy đủ
safe-api.quorix.io.vn    -> bản API-only trên PaaS
safe-local.quorix.io.vn  -> bản local + Cloudflare Tunnel
```

Khuyến nghị:

```text
safe.quorix.io.vn
```

cho bản VM/VPS thật.

Nếu bạn sợ ảnh hưởng domain chính, có thể dùng:

```text
test-safe.quorix.io.vn
```

---

## 5. Các biến môi trường cần chuẩn bị

### 5.1 Biến bạn tự tạo

Bạn tự chọn hoặc tự generate:

```env
SAFE_ZONE_ADMIN_PASSWORD=
SAFE_ZONE_ADMIN_API_KEY=
```

Trên Windows PowerShell, tạo API key dạng hex:

```powershell
[guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N")
```

Nếu có OpenSSL:

```powershell
openssl rand -hex 32
openssl rand -base64 24
```

Khuyến nghị:

```text
SAFE_ZONE_ADMIN_PASSWORD = mật khẩu dài, lưu trong password manager
SAFE_ZONE_ADMIN_API_KEY  = chuỗi hex 64 ký tự
```

### 5.2 Biến theo hạ tầng

```env
SAFE_ZONE_PUBLIC_HOST=safe.quorix.io.vn
SAFE_ZONE_CADDY_EMAIL=email-thật-của-bạn@example.com
```

### 5.3 Biến nên để khi test lần đầu

```env
SAFE_ZONE_AI_PROVIDER=none
SAFE_ZONE_DUCKDNS_DOMAIN=
SAFE_ZONE_DUCKDNS_TOKEN=
```

Vì sao để `SAFE_ZONE_AI_PROVIDER=none` trước?

Vì lần deploy đầu tiên chỉ nên kiểm tra:

- DNS;
- Docker;
- Caddy;
- HTTPS;
- API health;
- container có lên không.

Đừng vội bật AI/Ollama/hybrid. Khi móng nhà còn chưa khô, đừng dựng tháp chuông.

---

# PHẦN A — Deploy đầy đủ trên VPS / Cloud VM trial

Đây là hướng nên dùng nếu bạn muốn test Safe Zone giống production nhất.

---

## 6. Tạo VM trên Azure Free Account

Azure là lựa chọn non-Oracle đáng thử nhất nếu bạn muốn VM thật. Nhưng cần cẩn thận billing.

### 6.1 Nguyên tắc tránh mất tiền oan

Khi dùng Azure:

- Vào mục **Free services** trước, đừng tạo VM lung tung từ marketplace.
- Chọn đúng VM size được ghi là free-eligible.
- Chọn đúng loại disk được cover bởi free tier.
- Không bật thêm dịch vụ phụ nếu không hiểu rõ.

Tránh tạo nhầm:

```text
Azure Backup
Load Balancer
NAT Gateway
Premium SSD
Extra managed disk
Paid monitoring add-ons
Static Public IP nếu không được cover
```

### 6.2 Cấu hình VM khuyến nghị

```text
Image: Ubuntu Server 24.04 LTS
Authentication: SSH public key
Inbound ports ban đầu: 22, 80, 443
Sau khi tạo VM: mở thêm 853/tcp
```

Nếu có lựa chọn size:

```text
Ưu tiên: 2 vCPU, 2–4 GB RAM
Tối thiểu chấp nhận test: 1 vCPU, 1 GB RAM, nhưng phải giảm tải
```

### 6.3 Mở port trong Azure Network Security Group

Vào VM → Networking → Add inbound port rule.

Tạo các rule:

| Port | Protocol | Source | Action | Mục đích |
|---:|---|---|---|---|
| 22 | TCP | Your IP hoặc Any | Allow | SSH |
| 80 | TCP | Any | Allow | HTTP / Let's Encrypt |
| 443 | TCP | Any | Allow | HTTPS / DoH |
| 853 | TCP | Any | Allow | DoT |

Nếu muốn an toàn hơn, port `22` chỉ nên allow IP nhà bạn.

---

## 7. Tạo VM trên Google Cloud trial credit

Google Cloud always-free `e2-micro` quá yếu cho Safe Zone đầy đủ, nhưng nếu tài khoản mới có trial credit thì bạn có thể tạo VM tốt hơn để test ngắn hạn.

### 7.1 Cấu hình khuyến nghị

```text
Region: gần Việt Nam nhất trong khả năng chi phí, ví dụ asia-southeast1 nếu dùng trial credit
Machine type: e2-standard-2 hoặc e2-medium nếu muốn nhẹ hơn
OS: Ubuntu 24.04 LTS
Disk: 40–60 GB standard persistent disk
Firewall: allow HTTP, HTTPS, SSH; tạo rule thêm 853/tcp
```

Nếu chỉ dùng always-free thật sự:

```text
Machine: e2-micro
Disk: 30 GB standard persistent disk
```

Cấu hình này chỉ nên dùng để test API rất nhẹ, không nên kỳ vọng full stack mượt.

---

## 8. Tạo VM trên AWS Free Tier

AWS Free Tier thường chỉ cho EC2 micro 1 GB RAM. Safe Zone full stack có thể chạy rất căng, dễ thiếu RAM.

Chỉ nên dùng AWS nếu bạn chấp nhận:

- tắt AI provider;
- không chạy tác vụ nặng;
- theo dõi RAM kỹ;
- có thể thêm swap.

### 8.1 Cấu hình EC2 tối thiểu

```text
AMI: Ubuntu Server 24.04 LTS
Instance type: t2.micro hoặc t3.micro nếu free-eligible
Storage: 30 GB gp2/gp3 nếu nằm trong free tier
Security Group: 22, 80, 443, 853
```

### 8.2 Thêm swap nếu RAM thấp

Trên VM:

```sh
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
free -h
```

Swap không biến máy yếu thành máy mạnh, nhưng giúp tránh chết container đột ngột.

---

## 9. Chuẩn bị SSH key trên Windows

Nếu chưa có SSH key:

```powershell
ssh-keygen -t ed25519 -C "safe-zone-vps"
```

Cứ Enter để dùng đường dẫn mặc định.

Public key thường nằm ở:

```text
C:\Users\<ten-user-windows>\.ssh\id_ed25519.pub
```

Mở file `.pub`, copy toàn bộ nội dung và dán vào phần SSH key của nhà cung cấp VM.

---

## 10. Kết nối vào VM

Nếu username là `ubuntu`:

```powershell
ssh ubuntu@YOUR_VPS_IP
```

Nếu Azure dùng `azureuser`:

```powershell
ssh azureuser@YOUR_VPS_IP
```

Nếu nhà cung cấp dùng `root`:

```powershell
ssh root@YOUR_VPS_IP
```

Sau khi vào được VPS, kiểm tra OS:

```sh
lsb_release -a
uname -a
free -h
df -h
```

---

## 11. Setup VPS lần đầu

Chạy:

```sh
sudo apt update
sudo apt upgrade -y
sudo apt install -y git curl ca-certificates nano ufw htop
```

Bật firewall UFW:

```sh
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 853/tcp
sudo ufw enable
sudo ufw status
```

Nếu đang SSH, khi UFW hỏi thì nhập `y`.

---

## 12. Cài Docker và Docker Compose

Chạy:

```sh
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
```

Kiểm tra:

```sh
docker version
docker compose version
```

Nếu `docker compose version` hiện version là được.

---

## 13. Trỏ DNS ở PA Viet Nam

Chỉ thêm record cho subdomain Safe Zone.

Không sửa:

```text
@
www
```

Thêm record:

```text
Host/Name: safe
Type: A
Value/Address: YOUR_VPS_IP
TTL: để mặc định
```

Sau đó kiểm tra trên Windows:

```powershell
nslookup safe.quorix.io.vn
```

Hoặc trên VPS:

```sh
getent hosts safe.quorix.io.vn
```

Kết quả phải ra đúng public IP của VPS.

Nếu chưa ra, chờ DNS propagate vài phút đến vài giờ.

---

## 14. Clone dự án Safe Zone

Trên VPS:

```sh
git clone https://github.com/vmcchooky/safe-zone.git
cd safe-zone
```

Nếu repo private, bạn cần dùng GitHub token hoặc SSH deploy key.

---

## 15. Tạo file `.env`

```sh
cp .env.example .env
nano .env
```

Cấu hình tối thiểu để test:

```env
SAFE_ZONE_PUBLIC_HOST=safe.quorix.io.vn
SAFE_ZONE_CADDY_EMAIL=your-real-email@example.com

SAFE_ZONE_ADMIN_PASSWORD=your-long-random-password
SAFE_ZONE_ADMIN_API_KEY=your-long-random-api-key

SAFE_ZONE_AI_PROVIDER=none

SAFE_ZONE_DUCKDNS_DOMAIN=
SAFE_ZONE_DUCKDNS_TOKEN=
```

Lưu file trong nano:

```text
Ctrl + O
Enter
Ctrl + X
```

---

## 16. Deploy production-edge profile

```sh
chmod +x scripts/safe-zone.sh scripts/duckdns-update.sh scripts/bench.sh
scripts/safe-zone.sh deploy
```

Nếu script dùng Docker Compose profile `production-edge`, nó sẽ khởi động các thành phần như:

```text
core-api
dns-resolver
redis
caddy
```

Kiểm tra:

```sh
docker compose --profile production-edge ps
scripts/safe-zone.sh status
```

Xem log:

```sh
docker compose --profile production-edge logs -f --tail=100
```

---

## 17. Kiểm tra local trên VPS trước

Trước khi đổ lỗi cho DNS/HTTPS, kiểm tra service nội bộ:

```sh
curl -I http://127.0.0.1:8080/healthz
curl -I http://127.0.0.1:8081/healthz
```

Nếu không trả về OK, vấn đề nằm trong container/app.

Kiểm tra container nào chết:

```sh
docker compose --profile production-edge ps
```

Xem log container cụ thể:

```sh
docker compose --profile production-edge logs core-api --tail=200
docker compose --profile production-edge logs caddy --tail=200
docker compose --profile production-edge logs dns-resolver --tail=200
```

---

## 18. Kiểm tra HTTPS public

Sau khi DNS đúng và Caddy chạy:

```sh
curl -I https://safe.quorix.io.vn/healthz
curl "https://safe.quorix.io.vn/v1/analyze?domain=example.com"
```

Kỳ vọng:

```text
HTTPS hoạt động
/healthz trả về OK hoặc status thành công
/v1/analyze trả JSON
```

Mở dashboard:

```text
https://safe.quorix.io.vn/dashboard
```

Đăng nhập:

```text
username: admin
password: SAFE_ZONE_ADMIN_PASSWORD
```

---

## 19. Test DoH và DoT

### 19.1 DoH

Endpoint:

```text
https://safe.quorix.io.vn/dns-query
```

Có thể test bằng `curl` hoặc DNS client hỗ trợ DoH.

### 19.2 DoT

Thông tin:

```text
Host: safe.quorix.io.vn
Port: 853
```

Lưu ý:

- Port host `853` có thể map vào port container khác, ví dụ `8533`.
- Điều này bình thường nếu compose đã cấu hình như vậy.
- Quan trọng là từ ngoài Internet kết nối được tới `safe.quorix.io.vn:853`.

Kiểm tra port từ máy local nếu có `Test-NetConnection`:

```powershell
Test-NetConnection safe.quorix.io.vn -Port 853
```

Nếu `TcpTestSucceeded: True` là port đã mở.

---

## 20. Bật threat feeds miễn phí sau khi base stack ổn

Chỉ làm sau khi HTTPS/API đã chạy tốt.

Sửa `.env`:

```env
SAFE_ZONE_AGENT_FEED_SOURCES=https://urlhaus.abuse.ch/downloads/csv_recent/,https://rescure.me/rescure_domain_blacklist.txt
```

Chạy sync:

```sh
scripts/safe-zone.sh feed-sync
```

Nếu lỗi, xem log:

```sh
docker compose --profile production-edge logs --tail=200
```

---

## 21. Backup cơ bản

Backup thủ công:

```sh
scripts/safe-zone.sh backup
```

Restore:

```sh
scripts/safe-zone.sh restore /full/path/to/redis-dump.rdb
```

Khi đang test free/trial, backup rất quan trọng vì nền tảng free có thể bị suspend/reclaim/xóa nếu vượt limit.

---

## 22. Chưa nên bật cron ngay

Khi mới test, chưa cần bật cron.

Sau khi mọi thứ ổn, mới mở:

```sh
crontab -e
```

Nếu không dùng DuckDNS, hãy bỏ/comment dòng DuckDNS job.

Cron nên dùng cho:

```text
feed sync định kỳ
backup định kỳ
health check đơn giản
```

Không nên bật quá dày trên VM free vì dễ tốn tài nguyên.

---

# PHẦN B — Deploy API-only trên Render/Koyeb/Railway

Dùng hướng này khi bạn chỉ muốn demo nhanh:

```text
https://safe-api.quorix.io.vn/healthz
https://safe-api.quorix.io.vn/v1/analyze?domain=example.com
```

Không dùng hướng này nếu bạn cần:

```text
DoT :853
Docker Compose nhiều container
Redis riêng trong cùng stack
Caddy full reverse proxy
quyền root/full VPS
```

---

## 23. API-only nghĩa là gì?

Thay vì chạy toàn bộ stack:

```text
core-api + dns-resolver + redis + caddy
```

Bạn chỉ chạy một service HTTP đơn giản, ví dụ:

```text
core-api
```

hoặc một container đã được chỉnh để expose HTTP port.

PaaS sẽ lo HTTPS và custom domain thay bạn.

---

## 24. Deploy trên Render Free

### 24.1 Khi nào chọn Render?

Chọn Render nếu bạn muốn:

- GitHub push là tự deploy;
- custom domain dễ;
- HTTPS tự động;
- demo web/API nhanh.

Không chọn Render nếu bạn cần DoT hoặc Docker Compose full.

### 24.2 Các bước tổng quát

1. Đăng nhập Render.
2. New → Web Service.
3. Kết nối GitHub repo `safe-zone`.
4. Chọn branch.
5. Runtime: Docker hoặc native tùy repo.
6. Set environment variables:

```env
SAFE_ZONE_PUBLIC_HOST=safe-api.quorix.io.vn
SAFE_ZONE_AI_PROVIDER=none
SAFE_ZONE_ADMIN_PASSWORD=...
SAFE_ZONE_ADMIN_API_KEY=...
```

7. Deploy.
8. Kiểm tra URL Render cấp.
9. Thêm custom domain:

```text
safe-api.quorix.io.vn
```

10. Trong PA Viet Nam thêm CNAME theo hướng dẫn Render.

Ví dụ DNS thường là:

```text
Host/Name: safe-api
Type: CNAME
Value: <render-target-domain>
```

Không tự đoán value CNAME; lấy đúng từ Render dashboard.

---

## 25. Deploy trên Koyeb Free

### 25.1 Khi nào chọn Koyeb?

Chọn Koyeb nếu bạn muốn demo container HTTP rất nhẹ.

Nhược điểm:

- tài nguyên free nhỏ;
- không phù hợp Redis + resolver + Caddy;
- chỉ nên test endpoint HTTP.

### 25.2 Các bước tổng quát

1. Đăng nhập Koyeb.
2. Create Service.
3. Chọn GitHub repo hoặc Docker image.
4. Chọn free instance nếu còn khả dụng.
5. Set port HTTP của app.
6. Thêm env:

```env
SAFE_ZONE_PUBLIC_HOST=safe-api.quorix.io.vn
SAFE_ZONE_AI_PROVIDER=none
SAFE_ZONE_ADMIN_PASSWORD=...
SAFE_ZONE_ADMIN_API_KEY=...
```

7. Deploy.
8. Test endpoint Koyeb cấp.
9. Add custom domain và tạo DNS record theo Koyeb hướng dẫn.

---

## 26. Deploy trên Railway

### 26.1 Khi nào chọn Railway?

Railway hợp khi bạn muốn:

- deploy nhanh;
- dùng trial credit;
- test API nhỏ;
- có GitHub integration.

Nhược điểm:

- credit có thể hết;
- không phải VPS;
- volume/free resource hạn chế;
- không phù hợp DoT.

### 26.2 Các bước tổng quát

1. Tạo Railway project.
2. Deploy from GitHub repo.
3. Chọn service cần chạy.
4. Set env:

```env
SAFE_ZONE_PUBLIC_HOST=safe-api.quorix.io.vn
SAFE_ZONE_AI_PROVIDER=none
SAFE_ZONE_ADMIN_PASSWORD=...
SAFE_ZONE_ADMIN_API_KEY=...
```

5. Kiểm tra deployment logs.
6. Mở generated domain Railway cấp.
7. Add custom domain:

```text
safe-api.quorix.io.vn
```

8. Tạo DNS theo hướng dẫn Railway.

---

# PHẦN C — Local Docker + Cloudflare Tunnel

Đây là hướng rất đáng cân nhắc nếu bạn muốn **không tốn tiền cloud**.

Bạn chạy Safe Zone trên laptop/PC ở nhà, rồi dùng Cloudflare Tunnel để public HTTPS.

---

## 27. Khi nào nên dùng hướng local?

Chọn hướng này nếu:

- bạn chỉ cần demo;
- máy bạn có Docker ổn;
- không cần public DoT `853`;
- chấp nhận máy phải bật khi demo;
- muốn tránh billing cloud.

Không chọn nếu:

- muốn uptime 24/7;
- muốn resolver public thật;
- muốn test latency/network giống production.

---

## 28. Domain layout cho local

Dùng subdomain riêng:

```text
safe-local.quorix.io.vn
```

Không dùng chung `safe.quorix.io.vn` nếu bạn còn muốn dùng nó cho VPS thật.

---

## 29. Chạy Safe Zone local

Trên máy local có Docker:

```sh
git clone https://github.com/vmcchooky/safe-zone.git
cd safe-zone
cp .env.example .env
```

Cấu hình `.env`:

```env
SAFE_ZONE_PUBLIC_HOST=safe-local.quorix.io.vn
SAFE_ZONE_CADDY_EMAIL=your-real-email@example.com
SAFE_ZONE_ADMIN_PASSWORD=...
SAFE_ZONE_ADMIN_API_KEY=...
SAFE_ZONE_AI_PROVIDER=none
```

Chạy stack:

```sh
chmod +x scripts/safe-zone.sh scripts/duckdns-update.sh scripts/bench.sh
scripts/safe-zone.sh deploy
```

Kiểm tra local:

```sh
curl -I http://127.0.0.1:8080/healthz
```

---

## 30. Tạo Cloudflare Tunnel

Tổng quát:

1. Đưa domain `quorix.io.vn` vào Cloudflare DNS nếu bạn muốn quản lý tunnel bằng Cloudflare dễ nhất.
2. Cài `cloudflared` trên máy local.
3. Login Cloudflare.
4. Tạo tunnel.
5. Route hostname:

```text
safe-local.quorix.io.vn -> http://localhost:8080
```

Cloudflare Tunnel phù hợp để publish HTTP/HTTPS app. Nó không phải cách chuẩn để public DoT `853`.

---

# PHẦN D — Checklist chống mất tiền khi dùng free/trial

## 31. Checklist trước khi tạo cloud resource

Trước khi bấm Create:

- [ ] Đã bật budget alert.
- [ ] Đã xem region có free-tier không.
- [ ] Đã chọn đúng VM size free/trial.
- [ ] Đã chọn đúng disk type/size.
- [ ] Không bật backup tự động trả phí.
- [ ] Không thêm load balancer/NAT gateway.
- [ ] Không tạo nhiều public IP.
- [ ] Không tạo database managed trả phí.
- [ ] Biết cách xóa toàn bộ resource group/project sau test.

---

## 32. Checklist sau khi deploy xong

- [ ] `docker compose ps` thấy container chạy.
- [ ] `curl http://127.0.0.1:8080/healthz` OK.
- [ ] `nslookup safe.quorix.io.vn` ra đúng IP.
- [ ] `curl https://safe.quorix.io.vn/healthz` OK.
- [ ] Dashboard mở được.
- [ ] API `/v1/analyze` trả JSON.
- [ ] Port `853` mở nếu test DoT.
- [ ] Budget/billing không báo bất thường.

---

## 33. Checklist khi không dùng nữa

Nếu dùng VM trial:

- [ ] Stop chưa đủ, hãy **delete VM** nếu không dùng nữa.
- [ ] Xóa disk đi kèm.
- [ ] Xóa public IP nếu bị tách riêng.
- [ ] Xóa snapshot nếu có.
- [ ] Xóa resource group/project nếu chỉ dùng để test.
- [ ] Kiểm tra billing sau 1–2 ngày.

Cloud là cái giếng: nhìn tưởng trong, nhưng thả nhầm một cái xô là tiền rơi xuống không tiếng động.

---

# PHẦN E — Lỗi thường gặp

## 34. DNS không trỏ đúng IP

Kiểm tra:

```powershell
nslookup safe.quorix.io.vn
```

Nếu chưa ra IP VPS:

- kiểm tra PA Viet Nam record có đúng `safe` không;
- kiểm tra có nhập nhầm `safe.quorix.io.vn.quorix.io.vn` không;
- chờ DNS propagate;
- thử đổi DNS resolver sang 1.1.1.1 hoặc 8.8.8.8.

---

## 35. Caddy không cấp được HTTPS

Nguyên nhân thường gặp:

- DNS chưa trỏ về VPS;
- port 80/443 chưa mở ở cloud firewall;
- UFW chặn 80/443;
- `SAFE_ZONE_PUBLIC_HOST` sai;
- Caddy container không chạy.

Lệnh kiểm tra:

```sh
sudo ufw status
docker compose --profile production-edge ps
docker compose --profile production-edge logs caddy --tail=200
curl -I http://safe.quorix.io.vn
```

---

## 36. API không chạy

Kiểm tra:

```sh
docker compose --profile production-edge logs core-api --tail=200
```

Các lỗi thường gặp:

- thiếu biến môi trường;
- port mapping sai;
- Redis chưa lên;
- image build lỗi;
- RAM quá thấp.

Nếu RAM thấp:

```sh
free -h
docker stats
```

Có thể thêm swap như phần AWS.

---

## 37. DoT port 853 không hoạt động

Kiểm tra 3 tầng:

### Tầng cloud firewall

Phải allow:

```text
853/tcp
```

### Tầng UFW trong VPS

```sh
sudo ufw allow 853/tcp
sudo ufw status
```

### Tầng Docker Compose

Kiểm tra mapping port:

```sh
docker compose --profile production-edge ps
```

Từ Windows:

```powershell
Test-NetConnection safe.quorix.io.vn -Port 853
```

Nếu PaaS như Render/Koyeb/Railway thì đừng cố: đa số không hỗ trợ raw TCP `853` kiểu VPS.

---

# PHẦN F — Lộ trình khuyến nghị cho bạn

## 38. Nếu mục tiêu là test nhanh nhất

Làm theo thứ tự:

1. Dùng local Docker trước.
2. Test `/healthz` và `/v1/analyze` local.
3. Nếu cần public demo, dùng Cloudflare Tunnel.
4. Nếu cần test DoT/public DNS thật, chuyển sang Azure/Google trial VM.

---

## 39. Nếu mục tiêu là giống production nhất

Làm theo thứ tự:

1. Tạo VM trial.
2. Trỏ `safe.quorix.io.vn` về VM.
3. Deploy production-edge.
4. Test HTTPS.
5. Test API.
6. Test DoH.
7. Test DoT.
8. Bật feed sync.
9. Bật backup.
10. Sau cùng mới nghĩ đến AI provider.

---

## 40. Nếu mục tiêu là không tốn tiền

Làm theo thứ tự:

1. Local Docker.
2. Cloudflare Tunnel.
3. Subdomain `safe-local.quorix.io.vn`.
4. Không test DoT public.
5. Chỉ demo dashboard/API/DoH-like HTTPS route nếu app hỗ trợ.

Đây là hướng “nghèo nhưng tỉnh”: không hào nhoáng, nhưng ít rủi ro billing.

---

# PHẦN G — Tóm tắt chọn nền tảng

| Nhu cầu | Nên chọn |
|---|---|
| Test đầy đủ Safe Zone, có DoT `853` | Azure Free Account / Google Cloud trial VM / VPS rẻ |
| Test API dashboard nhanh | Render / Railway / Koyeb |
| Không tốn tiền cloud | Local Docker + Cloudflare Tunnel |
| Production thật | VPS trả phí hoặc Oracle nếu chấp nhận |
| Giữ website Hugo hiện tại | Tiếp tục để Vercel quản lý `quorix.io.vn` và `www` |

---

## 41. File `.env` mẫu cho full VPS test

```env
SAFE_ZONE_PUBLIC_HOST=safe.quorix.io.vn
SAFE_ZONE_CADDY_EMAIL=your-real-email@example.com

SAFE_ZONE_ADMIN_PASSWORD=replace-with-long-password
SAFE_ZONE_ADMIN_API_KEY=replace-with-long-api-key

SAFE_ZONE_AI_PROVIDER=none

SAFE_ZONE_DUCKDNS_DOMAIN=
SAFE_ZONE_DUCKDNS_TOKEN=

SAFE_ZONE_AGENT_FEED_SOURCES=
```

Sau khi chạy ổn, mới thêm:

```env
SAFE_ZONE_AGENT_FEED_SOURCES=https://urlhaus.abuse.ch/downloads/csv_recent/,https://rescure.me/rescure_domain_blacklist.txt
```

---

## 42. Bộ lệnh kiểm tra nhanh

```sh
# Xem container
docker compose --profile production-edge ps

# Xem log tổng
docker compose --profile production-edge logs --tail=200

# Xem log Caddy
docker compose --profile production-edge logs caddy --tail=200

# Xem log API
docker compose --profile production-edge logs core-api --tail=200

# Test nội bộ
curl -I http://127.0.0.1:8080/healthz

# Test HTTPS public
curl -I https://safe.quorix.io.vn/healthz

# Test analyze API
curl "https://safe.quorix.io.vn/v1/analyze?domain=example.com"

# Test port DoT từ VPS
ss -tulpn | grep 853
```

Trên Windows:

```powershell
nslookup safe.quorix.io.vn
Test-NetConnection safe.quorix.io.vn -Port 443
Test-NetConnection safe.quorix.io.vn -Port 853
```

---

# Tài liệu tham khảo

- Google Cloud Free Tier: `e2-micro`, 30 GB-month standard persistent disk, vùng eligible.
- Azure Free Services: VM free-eligible theo tháng trong 12 tháng, giới hạn theo SKU/vùng.
- AWS EC2 Free Tier: theo dõi usage EC2 Free Tier, thường dùng micro instance trong giới hạn free tier.
- Render Free: 750 free instance hours/workspace/tháng, có cơ chế suspend khi hết giờ.
- Railway Pricing: free/trial credit và giới hạn tài nguyên service.
- Fly.io Free Trial/Pricing: trial ngắn/credit, không nên xem như free VPS dài hạn.
- Cloudflare Tunnel: publish app local qua public hostname.

