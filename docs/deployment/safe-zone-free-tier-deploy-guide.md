# Deploy Safe Zone for `quorix.io.vn` using free / trial infrastructure

Date: 2026-05-21  
Project: Safe Zone  
Domain: `quorix.io.vn`  
Target test hostname: `safe.quorix.io.vn`  
Current website hosting: Hugo on Vercel  
DNS provider / registrar: PA Viet Nam  

> This document is a more detailed free-tier/testing version of the previous deployment guide.  
> The core rule is simple: **do not touch the existing `quorix.io.vn` and `www.quorix.io.vn` records**. Deploy Safe Zone on a separate subdomain.

---

## 0. Executive decision

For Safe Zone, there are two very different deployment modes:

| Mode | Best platform type | Supports Docker Compose? | Supports custom domain? | Supports DoH `/dns-query`? | Supports DoT `:853`? | Suitable for full Safe Zone? |
|---|---:|---:|---:|---:|---:|---:|
| Full VPS mode | VPS / cloud VM | Yes | Yes | Yes | Yes, if firewall allows `853/tcp` | Yes |
| API-only demo mode | PaaS container/web service | Usually no Compose, single container only | Yes | Maybe, via HTTPS route | No | Partial only |
| Local + tunnel mode | Your laptop / mini PC + Cloudflare Tunnel or Tailscale | Yes, locally | Yes, for HTTPS | Yes, via tunnel | Usually no public DoT `853` | Good for private testing |

### Recommended route while testing

Use this order:

1. **If you need full Safe Zone including DoT:** use a real VPS / VM trial.
2. **If you only need dashboard + `/v1/analyze` + maybe DoH over HTTPS:** use Render, Koyeb, Railway, or Cloud Run-style hosting with a reduced deployment.
3. **If you want zero cloud cost and can keep your laptop running:** use local Docker + Cloudflare Tunnel for HTTPS demo.

---

## 1. Reality check: can any non-Oracle free VPS match this?

Target baseline:

```text
Ubuntu 24.04 LTS
2 vCPU
2–4 GB RAM
40+ GB disk
1 public IPv4
Docker + Docker Compose
Inbound 80/tcp, 443/tcp, 853/tcp
```

As of 2026-05-21, excluding Oracle, **a truly free permanent VPS with all of the above is effectively unavailable**.

The reason is not CPU. The bottlenecks are:

- public IPv4 is costly and abuse-sensitive;
- 2–4 GB RAM is above most permanent free tiers;
- port `853/tcp` is not supported by most PaaS platforms;
- free platforms often sleep, suspend, or block long-running network services.

So the correct testing strategy is not “find a magical free VPS.”  
The correct strategy is **choose a test profile**.

---

## 2. Free / trial platform limit matrix

> Limits change often. Verify before entering payment details or deploying anything important.

| Platform | Free/trial type | Compute limit relevant to Safe Zone | Disk/storage | Public IPv4 | Custom domain | 24/7? | Safe Zone verdict |
|---|---|---:|---:|---:|---:|---:|---|
| Google Cloud Free Tier | Always-free small VM + new-user credits | Always-free `e2-micro`; too weak for full stack. New users also get trial credit. | Always-free Compute Engine includes 30 GB-months standard persistent disk in eligible regions. | Usually external IP possible, but watch billing/region. | Yes | Yes within limits | Good for tiny API test; use credits for proper 2 vCPU/4 GB test VM. |
| AWS Free Tier | 12-month free EC2 micro | `t2.micro`/`t3.micro` class; usually 1 GB RAM, below target. | 30 GB EBS free-tier baseline. | 750 hours/month in-use public IPv4 included in EC2 Free Tier; overage billed. | Yes | Yes within 750 hours/month | Not enough RAM for full Safe Zone; usable for minimal API-only test. |
| Microsoft Azure Free Account | 12-month free VM SKUs + first-month credit | Free VM sizes include B1S/B2pts v2/B2ats v2 families; region availability matters. Some are 1 GB RAM class. | Some managed disk offers may be covered only with correct free-account configuration. | Public IP possible, but networking/disk can still surprise-bill if misconfigured. | Yes | Yes within 750 hours/month | Best non-Oracle VM trial candidate; use Free Services page only. |
| Render Free | Free web service / preview tier | Web service, not a full VPS. Free services are for preview/hobby workloads. | Limited/managed; persistent disk is not full VM disk. | No direct VM IPv4 control. | Yes | May sleep / limited | Good for dashboard/API demo only; no DoT. |
| Koyeb Free Instance | One free web service instance | 0.1 vCPU, 512 MB RAM, 2 GB SSD. | 2 GB SSD | No direct VM IPv4 control. | Yes | Limited | Too small for full Safe Zone; possible tiny API mock/demo. |
| Railway Free/Trial | Credit-based app hosting | Up to 1 vCPU / 0.5 GB RAM per service on free-style limits; credit can run out. | 0.5 GB volume storage in free plan info. | No direct VM IPv4 control. | Yes | Not reliable when credits run out | Good for quick web/API demo, not full Safe Zone. |
| Fly.io | Usage-based / trial, not real free tier for new users | MicroVM platform, not traditional VPS. | Volumes available but billed/limited. | Anycast/proxy model, not normal VPS IPv4. | Yes | Paid/usage-based | Technically strong, but not “free VPS.” |
| Vercel | Frontend/serverless | Great for Hugo/Next/static sites, not long-running Docker Compose. | Not VPS disk | No | Yes | Yes for frontend | Keep current Hugo site here; do not deploy Safe Zone full stack here. |
| Cloudflare Tunnel + local machine | Free tunnel, local compute | Uses your laptop/mini PC resources. | Local disk | No public IPv4 needed | Yes | Only when local machine is on | Excellent zero-cost demo for HTTPS dashboard/API; not public DoT `853`. |

---

## 3. Which free profile should you choose?

### Profile A — Full Safe Zone test on trial VM

Choose this if you want:

- Docker Compose production profile;
- Caddy auto HTTPS;
- Redis container;
- dashboard;
- `/v1/analyze`;
- DoH endpoint;
- DoT on port `853`;
- behavior close to production.

Use:

- **Azure Free Account** if you want a non-Oracle VM path.
- **Google Cloud trial credit** if you want temporary 2 vCPU/4 GB.
- **AWS Free Tier** only if you reduce memory usage; AWS micro is usually too small.

Recommended test VM shape:

```text
Ubuntu 24.04 LTS
2 vCPU
2–4 GB RAM
40–60 GB disk
1 public IPv4
```

If using trial credit, set a strict budget alert and delete the VM after testing.

### Profile B — API-only free PaaS demo

Choose this if you only need to show:

- dashboard or API health;
- `/v1/analyze`;
- simple HTTPS endpoint;
- GitHub-based deployment.

Do not expect:

- Docker Compose with multiple containers;
- host-level firewall control;
- raw TCP `853`;
- full DNS resolver behavior.

Possible platforms:

- Render
- Koyeb
- Railway
- Google Cloud Run, if you adapt the app to container HTTP only

This requires a **reduced Safe Zone deployment**, usually one container exposing only HTTP.

### Profile C — Local Docker + Cloudflare Tunnel

Choose this if you want:

- zero cloud VM cost;
- real Docker Compose behavior locally;
- custom domain HTTPS;
- quick demo from your laptop.

Limitations:

- laptop must stay on;
- not production;
- public DoT `853` is not the right fit through Cloudflare Tunnel;
- performance depends on your local network.

---

## 4. Domain layout

Keep Vercel untouched:

```text
quorix.io.vn      -> existing Hugo site on Vercel
www.quorix.io.vn  -> existing Hugo site on Vercel
```

Use one of these for Safe Zone:

```text
safe.quorix.io.vn        -> full VPS / VM deployment
safe-api.quorix.io.vn    -> API-only PaaS deployment
safe-local.quorix.io.vn  -> local + Cloudflare Tunnel demo
```

Recommended:

```text
safe.quorix.io.vn
```

for the real VM/VPS path.

---

## 5. Free VM path: Azure Free Account

Azure is the strongest non-Oracle candidate because it can provide VM-shaped resources during the free-account period, but it is also easy to misconfigure and accidentally create billable resources.

### 5.1 What Azure free VM can and cannot do

Azure free account includes limited VM usage for specific VM families, typically up to 750 hours/month for selected burstable sizes during the 12-month free period.

Important caveats:

- Create resources from **Free services**, not generic “Create VM.”
- Choose only free-eligible VM sizes.
- Choose free-eligible disk settings.
- Avoid extra paid services:
  - Azure Backup
  - Load Balancer
  - NAT Gateway
  - extra managed disks
  - premium SSD
  - paid monitoring add-ons
  - static public IP if not covered by your selected configuration

### 5.2 Azure recommended steps

1. Create or open Azure Free Account.
2. In Azure Portal, search for:

```text
Free services
```

3. Choose Linux Virtual Machine from the free services page.
4. Select:

```text
Image: Ubuntu Server 24.04 LTS
Size: free-eligible B-series option shown by Azure
Authentication: SSH public key
Inbound ports: SSH 22, HTTP 80, HTTPS 443
```

5. After VM creation, add inbound rule:

```text
853/tcp
```

6. SSH into the VM:

```powershell
ssh azureuser@YOUR_AZURE_PUBLIC_IP
```

7. Continue with the common VPS setup section.

### 5.3 Azure risk controls

Immediately configure:

- Budget alert: very low threshold, for example `$1` or local-currency equivalent.
- Cost analysis pinned to dashboard.
- Delete unused resources, not just stop the VM.

When testing is done, delete the **resource group**, not only the VM.

---

## 6. Free VM path: Google Cloud

Google Cloud has an always-free `e2-micro`, but it is too weak for full Safe Zone. The useful path is:

- use always-free only for tiny health/API experiments; or
- use new-user trial credits for a temporary proper VM.

### 6.1 Always-free tiny VM

Eligible always-free Compute Engine resources include:

```text
1 e2-micro VM per month in selected US regions
30 GB-months standard persistent disk
limited outbound data transfer
```

This is likely too small for full Docker Compose Safe Zone.

Use it only for:

- minimal Go API binary;
- health endpoint;
- no Redis, or Redis replaced with small in-process/mock mode;
- no AI provider;
- no heavy feed ingestion.

### 6.2 Trial-credit proper VM

For realistic Safe Zone testing, create:

```text
Machine type: e2-medium or e2-standard-2
OS: Ubuntu 24.04 LTS
Disk: 40–60 GB standard persistent disk
Firewall: 22/tcp, 80/tcp, 443/tcp, 853/tcp
```

Then deploy the full stack.

### 6.3 Google Cloud risk controls

Before deploying:

- create budget alert;
- disable or avoid GPUs;
- avoid external load balancers;
- delete snapshots and disks after testing;
- delete static IP addresses after testing.

---

## 7. Free VM path: AWS Free Tier

AWS Free Tier is useful for learning EC2, but its free VM class is usually too small for Safe Zone full stack.

### 7.1 AWS free-tier shape

Typical free-tier EC2 path:

```text
EC2: t2.micro or t3.micro class
RAM: around 1 GB
EBS: about 30 GB free-tier baseline
Public IPv4: 750 hours/month in-use public IPv4 included for EC2 Free Tier; overage billed
```

### 7.2 Verdict for Safe Zone

Use AWS only for:

- API-only test;
- single binary;
- no heavy Redis;
- no AI model;
- no large feed sync.

Avoid using it as the first full Safe Zone deployment unless you optimize memory aggressively.

### 7.3 Minimal AWS test config

```text
AMI: Ubuntu Server 24.04 LTS
Instance: t3.micro or free-eligible equivalent
Storage: 30 GB gp3/gp2 within free-tier limit
Security Group:
  - 22/tcp from your IP
  - 80/tcp from 0.0.0.0/0
  - 443/tcp from 0.0.0.0/0
  - 853/tcp from 0.0.0.0/0 only if testing DoT
```

If memory runs out, add swap:

```sh
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

---

## 8. PaaS path: Render / Koyeb / Railway

Use this when you want a quick public demo, not a full network service.

### 8.1 What must change

The original VPS deployment assumes:

```text
Docker Compose
core-api
dns-resolver
redis
caddy
multiple exposed ports
host firewall
public IPv4
```

Most free PaaS platforms want:

```text
one web process
one exposed HTTP port
no privileged ports
no custom raw TCP listener
ephemeral filesystem
managed routing/TLS
```

So create a new “demo” deployment profile:

```text
safe-zone-demo
```

That profile should:

- start only `core-api`;
- disable DoT;
- disable or mock DNS resolver if needed;
- use in-memory or small external storage;
- expose only one HTTP port;
- let platform handle TLS;
- set `SAFE_ZONE_AI_PROVIDER=none`.

### 8.2 Suggested environment for API-only demo

```env
SAFE_ZONE_PUBLIC_HOST=safe-api.quorix.io.vn
SAFE_ZONE_ADMIN_PASSWORD=change-me-long-random
SAFE_ZONE_ADMIN_API_KEY=change-me-long-random

SAFE_ZONE_AI_PROVIDER=none
SAFE_ZONE_MODE=demo
SAFE_ZONE_ENABLE_DOT=false
SAFE_ZONE_ENABLE_DOH=true
SAFE_ZONE_REDIS_URL=
PORT=8080
```

If your app currently requires Redis, either:

1. use a managed Redis/free key-value option if available; or
2. add a demo mode that uses memory storage; or
3. deploy Redis separately on the same platform if the platform supports it.

For free-tier stability, option 2 is cleanest.

---

## 9. Render demo deployment

### 9.1 Use case

Render is suitable for:

- web dashboard;
- API demo;
- GitHub auto-deploy;
- custom domain HTTPS.

Not suitable for:

- full Docker Compose;
- DoT `853`;
- true VPS behavior;
- long-running DNS resolver on raw TCP/UDP.

### 9.2 Render steps

1. Push Safe Zone to GitHub.
2. In Render, create a new Web Service.
3. Connect the GitHub repo.
4. Choose Docker if your project has a Dockerfile, or native runtime if supported.
5. Set build/start commands.

Example if using Docker:

```text
Environment: Docker
Port: 8080
```

6. Add environment variables:

```env
SAFE_ZONE_PUBLIC_HOST=safe-api.quorix.io.vn
SAFE_ZONE_ADMIN_PASSWORD=...
SAFE_ZONE_ADMIN_API_KEY=...
SAFE_ZONE_AI_PROVIDER=none
SAFE_ZONE_MODE=demo
SAFE_ZONE_ENABLE_DOT=false
SAFE_ZONE_ENABLE_DOH=true
PORT=8080
```

7. Add custom domain:

```text
safe-api.quorix.io.vn
```

8. In PA Viet Nam DNS, create the CNAME Render tells you to create.

Usually this looks like:

```text
Host/Name: safe-api
Type: CNAME
Value: something.onrender.com
```

Use the exact value from Render.

---

## 10. Koyeb demo deployment

### 10.1 Use case

Koyeb free instance is tiny. It is good only for:

- proof-of-concept;
- health endpoint;
- small API route;
- “does this deploy?” testing.

### 10.2 Koyeb steps

1. Create Koyeb service from GitHub.
2. Select the free instance type.
3. Use Dockerfile or buildpack.
4. Set public port:

```text
8080
```

5. Add env vars:

```env
SAFE_ZONE_PUBLIC_HOST=safe-api.quorix.io.vn
SAFE_ZONE_ADMIN_PASSWORD=...
SAFE_ZONE_ADMIN_API_KEY=...
SAFE_ZONE_AI_PROVIDER=none
SAFE_ZONE_MODE=demo
SAFE_ZONE_ENABLE_DOT=false
SAFE_ZONE_ENABLE_DOH=true
PORT=8080
```

6. Add custom domain in Koyeb.
7. Add the DNS record in PA Viet Nam according to Koyeb’s instruction.

### 10.3 Koyeb warning

With around 512 MB RAM and very low CPU on the free instance, avoid:

- Redis;
- big feed sync;
- AI model calls with large concurrency;
- heavy background workers.

---

## 11. Railway demo deployment

### 11.1 Use case

Railway is convenient for fast GitHub deployment but it is credit-based. Treat it as a short demo platform, not a permanent free server.

### 11.2 Railway steps

1. Create project from GitHub repo.
2. Let Railway detect Dockerfile/Nixpacks.
3. Set service variables:

```env
SAFE_ZONE_PUBLIC_HOST=safe-api.quorix.io.vn
SAFE_ZONE_ADMIN_PASSWORD=...
SAFE_ZONE_ADMIN_API_KEY=...
SAFE_ZONE_AI_PROVIDER=none
SAFE_ZONE_MODE=demo
SAFE_ZONE_ENABLE_DOT=false
SAFE_ZONE_ENABLE_DOH=true
PORT=8080
```

4. Add custom domain:

```text
safe-api.quorix.io.vn
```

5. Add DNS CNAME in PA Viet Nam using Railway’s generated target.

### 11.3 Railway warning

Railway is excellent for velocity, but if credits run out, service can pause. Do not use it for a long-running security/DNS demo that must stay online.

---

## 12. Local Docker + Cloudflare Tunnel path

This is often the most practical “free” path for student projects.

### 12.1 What you get

You get:

- real Docker Compose locally;
- no VPS bill;
- HTTPS public URL;
- custom subdomain;
- easy demo from anywhere.

You do not get:

- real public IPv4 on your server;
- public DoT `853`;
- production-grade uptime.

### 12.2 Local setup

On your Windows machine with Docker Desktop or WSL2 Docker:

```powershell
git clone https://github.com/vmcchooky/safe-zone.git
cd safe-zone
copy .env.example .env
notepad .env
```

Use:

```env
SAFE_ZONE_PUBLIC_HOST=safe-local.quorix.io.vn
SAFE_ZONE_CADDY_EMAIL=your-email@example.com

SAFE_ZONE_ADMIN_PASSWORD=your-long-random-password
SAFE_ZONE_ADMIN_API_KEY=your-long-random-api-key

SAFE_ZONE_AI_PROVIDER=none
SAFE_ZONE_ENABLE_DOT=false
```

Start locally:

```powershell
docker compose --profile production-edge up -d
docker compose --profile production-edge ps
```

Check local health:

```powershell
curl http://localhost:8080/healthz
```

### 12.3 Cloudflare Tunnel

If you use Cloudflare as DNS for a subdomain or can delegate a subdomain, create a tunnel:

```powershell
cloudflared tunnel login
cloudflared tunnel create safe-zone-local
cloudflared tunnel route dns safe-zone-local safe-local.quorix.io.vn
```

Create a config file:

```yaml
tunnel: safe-zone-local
credentials-file: C:\Users\<you>\.cloudflared\<tunnel-id>.json

ingress:
  - hostname: safe-local.quorix.io.vn
    service: http://localhost:8080
  - service: http_status:404
```

Run:

```powershell
cloudflared tunnel run safe-zone-local
```

Then open:

```text
https://safe-local.quorix.io.vn
```

If you cannot move DNS to Cloudflare, use the temporary `trycloudflare.com` tunnel for demo:

```powershell
cloudflared tunnel --url http://localhost:8080
```

---

## 13. Full VPS deployment steps

Use this section for Azure/GCP/AWS trial VM, or any paid VPS.

### 13.1 Generate local SSH key

On Windows PowerShell:

```powershell
ssh-keygen -t ed25519 -C "safe-zone-vps"
```

Copy the public key:

```powershell
type $env:USERPROFILE\.ssh\id_ed25519.pub
```

Paste it into your provider when creating the VM.

### 13.2 Firewall requirements

Provider firewall / security group:

```text
22/tcp   SSH
80/tcp   HTTP for Let's Encrypt and redirect
443/tcp  HTTPS
853/tcp  DNS-over-TLS
```

Optional during debugging:

```text
8080/tcp only from your IP
8081/tcp only from your IP
```

### 13.3 DNS in PA Viet Nam

Do not touch:

```text
@
www
```

Add only:

```text
Host/Name: safe
Type: A
Value/Address: YOUR_VPS_PUBLIC_IPV4
TTL: default
```

Verify:

```powershell
nslookup safe.quorix.io.vn
```

Expected: your VPS public IPv4.

### 13.4 First server setup

SSH:

```powershell
ssh ubuntu@YOUR_VPS_PUBLIC_IPV4
```

Then:

```sh
sudo apt update
sudo apt upgrade -y
sudo apt install -y git curl ca-certificates ufw
```

Enable firewall:

```sh
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 853/tcp
sudo ufw enable
sudo ufw status
```

### 13.5 Install Docker

```sh
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
docker version
docker compose version
```

### 13.6 Clone Safe Zone

```sh
git clone https://github.com/vmcchooky/safe-zone.git
cd safe-zone
```

### 13.7 Create `.env`

```sh
cp .env.example .env
nano .env
```

Minimum:

```env
SAFE_ZONE_PUBLIC_HOST=safe.quorix.io.vn
SAFE_ZONE_CADDY_EMAIL=your-real-email@example.com

SAFE_ZONE_ADMIN_PASSWORD=your-long-random-password
SAFE_ZONE_ADMIN_API_KEY=your-long-random-api-key

SAFE_ZONE_AI_PROVIDER=none

SAFE_ZONE_DUCKDNS_DOMAIN=
SAFE_ZONE_DUCKDNS_TOKEN=
```

### 13.8 Deploy

```sh
chmod +x scripts/safe-zone.sh scripts/duckdns-update.sh scripts/bench.sh
scripts/safe-zone.sh deploy
```

### 13.9 Verify

```sh
docker compose --profile production-edge ps
scripts/safe-zone.sh status
docker compose --profile production-edge logs --tail=100
```

Health checks:

```sh
curl -I http://127.0.0.1:8080/healthz
curl -I https://safe.quorix.io.vn/healthz
curl "https://safe.quorix.io.vn/v1/analyze?domain=example.com"
```

Dashboard:

```text
https://safe.quorix.io.vn/dashboard
```

Login:

```text
username: admin
password: SAFE_ZONE_ADMIN_PASSWORD
```

---

## 14. Testing DoH and DoT

### 14.1 DoH

Endpoint:

```text
https://safe.quorix.io.vn/dns-query
```

Basic availability check:

```sh
curl -I https://safe.quorix.io.vn/dns-query
```

A DNS-aware DoH client is better for full validation.

### 14.2 DoT

Host:

```text
safe.quorix.io.vn
```

Port:

```text
853
```

Check port:

```sh
nc -vz safe.quorix.io.vn 853
```

If failed:

1. Check provider firewall/security group.
2. Check `ufw`.
3. Check Docker port mapping.
4. Check Caddy/dns-resolver logs.
5. Confirm the app actually listens for DoT.

---

## 15. Low-memory tuning for free tiers

For 512 MB–1 GB RAM environments:

### 15.1 Add swap on VM

```sh
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
free -h
```

### 15.2 Disable heavy features

Use:

```env
SAFE_ZONE_AI_PROVIDER=none
SAFE_ZONE_ENABLE_DOT=false
SAFE_ZONE_FEED_SYNC_ON_START=false
SAFE_ZONE_MAX_WORKERS=1
SAFE_ZONE_LOG_LEVEL=info
```

### 15.3 Avoid on free PaaS

Avoid:

- large threat feed import at boot;
- browser automation;
- local AI models;
- multiple containers;
- large Redis memory;
- background workers with no sleep.

---

## 16. Cost safety checklist

Before deploying on any cloud provider:

- [ ] Add billing alert.
- [ ] Use free services page where available.
- [ ] Avoid GPU.
- [ ] Avoid load balancer unless covered.
- [ ] Avoid premium disk.
- [ ] Avoid snapshots unless needed.
- [ ] Avoid static IP if billed separately.
- [ ] Restrict SSH to your IP if possible.
- [ ] Delete unused disks after deleting VM.
- [ ] Delete unused public IPs.
- [ ] Delete the entire resource group/project after trial.

After testing:

```text
Stop is not enough.
Delete unused resources.
```

Clouds are gentle at signup and merciless in billing. The invoice does not care that the project was “just a test.”

---

## 17. Recommended final decision for Safe Zone

### If you want the cleanest free-ish test

Use:

```text
Azure Free Account VM
Ubuntu 24.04 LTS
free-eligible B-series VM
safe.quorix.io.vn A record
Docker Compose full deployment
```

Good because:

- closest to real VPS;
- supports inbound ports;
- can test Caddy, HTTPS, DoH, DoT;
- does not require changing current Vercel site.

Risk:

- billing mistakes if you create non-free resources.

### If you want zero billing risk

Use:

```text
Local Docker
Cloudflare Tunnel
safe-local.quorix.io.vn or temporary trycloudflare URL
```

Good because:

- no VM cost;
- fast iteration;
- safe for demo.

Risk:

- no true production networking;
- no public DoT `853`;
- dependent on laptop uptime.

### If you want easiest web demo

Use:

```text
Render or Koyeb
safe-api.quorix.io.vn
API-only demo profile
```

Good because:

- simple GitHub deployment;
- HTTPS and custom domain are easy.

Risk:

- not full Safe Zone;
- no Docker Compose;
- no port `853`;
- small RAM/CPU.

---

## 18. Suggested file/project changes

To make Safe Zone deploy well on free platforms, add these project-level profiles:

```text
docker-compose.demo.yml
Dockerfile.demo
.env.demo.example
```

### 18.1 `.env.demo.example`

```env
SAFE_ZONE_PUBLIC_HOST=safe-api.quorix.io.vn
SAFE_ZONE_ADMIN_PASSWORD=change-me
SAFE_ZONE_ADMIN_API_KEY=change-me

SAFE_ZONE_AI_PROVIDER=none
SAFE_ZONE_MODE=demo

SAFE_ZONE_ENABLE_DOH=true
SAFE_ZONE_ENABLE_DOT=false
SAFE_ZONE_FEED_SYNC_ON_START=false

SAFE_ZONE_REDIS_URL=
SAFE_ZONE_MAX_WORKERS=1
PORT=8080
```

### 18.2 `docker-compose.demo.yml`

Example direction:

```yaml
services:
  core-api:
    build:
      context: .
      dockerfile: Dockerfile.demo
    ports:
      - "8080:8080"
    env_file:
      - .env.demo
    restart: unless-stopped
```

### 18.3 Demo start command

```sh
docker compose -f docker-compose.demo.yml up -d --build
```

This makes Safe Zone portable across PaaS platforms that expect one HTTP service.

---

## 19. Troubleshooting commands

### VPS

```sh
docker compose --profile production-edge ps
docker compose --profile production-edge logs --tail=200
sudo ufw status
ss -tulpn | grep -E ':80|:443|:853|:8080|:8081'
curl -I http://127.0.0.1:8080/healthz
curl -I https://safe.quorix.io.vn/healthz
```

### DNS

```powershell
nslookup safe.quorix.io.vn
nslookup safe-api.quorix.io.vn
```

### TLS

```sh
curl -Iv https://safe.quorix.io.vn/healthz
```

### Memory

```sh
free -h
docker stats
```

---

## 20. References checked

- Google Cloud Free Tier docs: Compute Engine always-free `e2-micro`, 30 GB-months standard persistent disk, selected US regions.
  - https://docs.cloud.google.com/free/docs/free-cloud-features
  - https://cloud.google.com/free
- AWS announcement: EC2 Free Tier includes 750 hours/month of in-use public IPv4; overage billed.
  - https://aws.amazon.com/about-aws/whats-new/2024/02/aws-free-tier-750-hours-free-public-ipv4-addresses/
- Azure free services: Linux VM free-account entries include selected burstable VMs for 750 hours/month during 12-month period.
  - https://azure.microsoft.com/en-us/pricing/free-services
  - https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/create-free-services
- Render free deployment docs.
  - https://render.com/docs/free
  - https://render.com/pricing
- Koyeb instance docs: free instance is 512 MB RAM, 0.1 vCPU, 2 GB SSD.
  - https://www.koyeb.com/docs/reference/instances
  - https://www.koyeb.com/docs/faqs/pricing
- Railway pricing docs: free/trial credit model and small resource limits.
  - https://railway.com/pricing
  - https://docs.railway.com/pricing/plans
- Fly.io docs: no traditional free tier; usage/free allowances do not cap bills.
  - https://fly.io/docs/about/cost-management/
  - https://fly.io/docs/about/pricing/
