# Deploy Safe Zone for `quorix.io.vn` step by step

Date: 2026-05-21

This guide is written for the current situation:

- Main website: `quorix.io.vn`
- Current hosting: Hugo on Vercel
- Domain registrar / DNS management: PA Viet Nam
- Goal: keep the existing Vercel site working, and deploy Safe Zone on a separate subdomain

## Recommended domain layout

Keep the root site on Vercel:

- `quorix.io.vn` -> your Hugo site on Vercel
- `www.quorix.io.vn` -> your Hugo site on Vercel

Use a separate subdomain for Safe Zone:

- `safe.quorix.io.vn` -> Safe Zone public HTTPS endpoint

This is the safest path because it avoids breaking the current website.

Safe Zone public endpoints would then be:

- Dashboard: `https://safe.quorix.io.vn/app/`
- Analyze API: `https://safe.quorix.io.vn/v1/analyze`
- DoH: `https://safe.quorix.io.vn/dns-query`
- DoT: `safe.quorix.io.vn:853`

## What you need to prepare

### Values you create yourself

These are not issued by a provider. You choose or generate them:

- `SAFE_ZONE_ADMIN_PASSWORD`
- `SAFE_ZONE_ADMIN_API_KEY`

You can generate them on your local Windows machine. Examples:

PowerShell, 32-byte hex API key:

```powershell
[guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N")
```

If `openssl` is installed:

```powershell
openssl rand -hex 32
openssl rand -base64 24
```

Recommendation:

- Use the hex output for `SAFE_ZONE_ADMIN_API_KEY`
- Use a long password-manager-generated password for `SAFE_ZONE_ADMIN_PASSWORD`

You can generate these locally. They do not need to be generated on the VPS.

### Values you get from infrastructure

- `SAFE_ZONE_PUBLIC_HOST`
  Value for this guide: `safe.quorix.io.vn`
- `SAFE_ZONE_CADDY_EMAIL`
  Use your real email so Let's Encrypt certificate notices can reach you if needed

### Optional DuckDNS values

You do not need DuckDNS if your domain already works and you can edit DNS in PA Viet Nam.

DuckDNS is only useful if:

- you do not want to use PA Viet Nam DNS at all for this service, or
- you have a changing home IP and need dynamic DNS

If you still want DuckDNS, see the appendix at the end of this document.

## Step 1: choose a VPS

You said you do not have a VPS yet, so here is the practical decision:

### Option A: Oracle Cloud Always Free

Best if:

- you want to minimize cost
- you are okay with a more awkward signup flow
- you can tolerate occasional capacity frustration

Pros:

- official Always Free compute exists
- the Arm A1 free limit is large enough for this project

Cons:

- Oracle can show capacity errors
- Oracle may reclaim idle Always Free instances
- signup is stricter

### Option B: low-cost paid VPS

Best if:

- you want less signup friction
- you want a simpler first deployment

Good baseline:

- Ubuntu 24.04 LTS
- 2 vCPU
- 2 to 4 GB RAM
- 40+ GB disk
- 1 public IPv4

For a first deployment, a paid VPS is usually smoother than Oracle free tier.

## Step 2: register and create the VPS

The exact UI depends on the provider, but the server you create should be:

- OS: `Ubuntu 24.04 LTS`
- Architecture: `x86_64` is simplest; `arm64` is also okay if the provider offers it
- Access: prefer SSH key login
- Public network: must have at least one public IPv4

If the provider asks for hostname, use something like:

- `safe-zone-prod`

If the provider supports cloud firewall during provisioning, allow:

- `22/tcp`
- `80/tcp`
- `443/tcp`
- `853/tcp`

## Step 3: create an SSH key on your local machine

If you do not already have one, create one on Windows PowerShell:

```powershell
ssh-keygen -t ed25519 -C "safe-zone-vps"
```

Accept the default path unless you already manage many keys.

This gives you:

- private key on your machine
- public key, usually in:
  `C:\Users\<your-user>\.ssh\id_ed25519.pub`

Open the `.pub` file and copy its content into the VPS provider SSH key form.

## Step 4: connect to the VPS

After the VPS is created, your provider will show the public IP.

Connect from your local machine:

```powershell
ssh ubuntu@YOUR_VPS_IP
```

If the provider uses `root`, then use:

```powershell
ssh root@YOUR_VPS_IP
```

## Step 5: first VPS setup

Run this on the VPS:

```sh
sudo apt update
sudo apt upgrade -y
sudo apt install -y git curl ca-certificates
```

If you logged in as `root`, create a normal sudo user before continuing. If your provider already created `ubuntu`, you can keep using that.

## Step 6: install Docker and Compose

On the VPS:

```sh
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
docker version
docker compose version
```

## Step 7: point DNS in PA Viet Nam

Because `quorix.io.vn` is already on Vercel, do not touch the existing root records unless you are intentionally moving the whole website away from Vercel.

What you should add is only the Safe Zone subdomain:

- Host / Name: `safe`
- Type: `A`
- Value / Address: `YOUR_VPS_IP`
- TTL: leave the default if you are unsure

Do not change:

- `@`
- `www`

unless you want to break or move the current Vercel setup.

### PA Viet Nam click path

General flow:

1. Log in to `https://access.pavietnam.vn/login.php`
2. Open the domain management area for `quorix.io.vn`
3. Find the DNS management section
4. Add a new DNS record
5. Enter:

```text
Host/Name: safe
Type: A
Value/Address: YOUR_VPS_IP
```

6. Save

If PA Viet Nam asks for root host syntax, common patterns are:

- `@` for root
- plain label like `safe` for subdomain

For your case, use `safe`, not `@`.

## Step 8: confirm DNS propagation

From your local machine:

```powershell
nslookup safe.quorix.io.vn
```

Or from the VPS:

```sh
getent hosts safe.quorix.io.vn
```

You should see the VPS public IP.

## Step 9: clone the project on the VPS

On the VPS:

```sh
git clone https://github.com/vmcchooky/safe-zone.git
cd safe-zone
```

## Step 10: create `.env`

On the VPS:

```sh
cp .env.example .env
```

Edit it:

```sh
nano .env
```

Minimum values for your case:

```env
SAFE_ZONE_PUBLIC_HOST=safe.quorix.io.vn
SAFE_ZONE_CADDY_EMAIL=your-real-email@example.com

SAFE_ZONE_ADMIN_PASSWORD=your-long-random-password
SAFE_ZONE_ADMIN_API_KEY=your-long-random-api-key

SAFE_ZONE_AI_PROVIDER=none

SAFE_ZONE_DUCKDNS_DOMAIN=
SAFE_ZONE_DUCKDNS_TOKEN=
```

Why `SAFE_ZONE_AI_PROVIDER=none` first:

- the first deployment should focus on networking, TLS, DNS, and containers
- we can enable `ollama` or `hybrid` later once the base stack is healthy

## Step 11: deploy

Make scripts executable and start the production profile:

```sh
chmod +x scripts/safe-zone.sh scripts/duckdns-update.sh scripts/bench.sh
scripts/safe-zone.sh deploy
```

This will start:

- `core-api`
- `dns-resolver`
- `redis`
- `caddy`

## Step 12: verify containers and health

On the VPS:

```sh
docker compose --profile production-edge ps
scripts/safe-zone.sh status
docker compose --profile production-edge logs -f --tail=100
```

Healthy signs:

- `core-api` is up
- `dns-resolver` is up
- `redis` is up
- `caddy` is up

## Step 13: verify HTTPS

After DNS has propagated and Caddy is up:

```sh
curl -I https://safe.quorix.io.vn/healthz
curl "https://safe.quorix.io.vn/v1/analyze?domain=example.com"
```

Expected:

- HTTPS works
- `/healthz` returns success
- `/v1/analyze` returns JSON

## Step 14: log in to the dashboard

Open:

- `https://safe.quorix.io.vn/app/`

Login values:

- username: `admin`
- password: `SAFE_ZONE_ADMIN_PASSWORD`

## Step 15: test DoH and DoT

### DoH

Endpoint:

- `https://safe.quorix.io.vn/dns-query`

### DoT

Host:

- `safe.quorix.io.vn`

Port:

- `853`

Note:

- host port `853` maps to container port `8533` internally
- this is intentional so the service can run as a non-root process in the container

## Step 16: optionally enable free threat feeds

Edit `.env` and set:

```env
SAFE_ZONE_AGENT_FEED_SOURCES=https://urlhaus.abuse.ch/downloads/csv_recent/,https://rescure.me/rescure_domain_blacklist.txt
```

Then run:

```sh
scripts/safe-zone.sh feed-sync
```

## Step 17: optionally install cron jobs

There is an example file:

- [safe-zone-production.cron.example](D:/Quorix/services/safe-zone/ops/cron/safe-zone-production.cron.example:1)

On the VPS:

```sh
crontab -e
```

Then paste the file content you want to use.

For your case, if you are not using DuckDNS, remove or comment out the DuckDNS job.

## Step 18: backup and restore basics

Manual backup:

```sh
scripts/safe-zone.sh backup
```

Manual restore:

```sh
scripts/safe-zone.sh restore /full/path/to/redis-dump.rdb
```

## If deployment fails, collect these first

Run on the VPS and keep the output ready:

```sh
docker compose --profile production-edge ps
docker compose --profile production-edge logs --tail=200
curl -I http://127.0.0.1:8080/healthz
curl -I http://127.0.0.1:8081/healthz
```

Also note:

- VPS public IP
- exact hostname you used
- whether DNS for `safe.quorix.io.vn` already resolves to the VPS

## Appendix: DuckDNS

You do not need this for `quorix.io.vn`, but here is how it works.

### Create a DuckDNS domain

1. Open `https://www.duckdns.org/`
2. Sign in
3. Choose a subdomain name
4. Create it

You will then have:

- a domain name like `yourname.duckdns.org`
- an account token shown in the DuckDNS dashboard

### Values to use

- `SAFE_ZONE_DUCKDNS_DOMAIN`: only the subname, for example `yourname`
- `SAFE_ZONE_DUCKDNS_TOKEN`: your account token from DuckDNS

### Manual test

```sh
curl "https://www.duckdns.org/update?domains=yourname&token=YOURTOKEN&ip=&verbose=true"
```

Expected response:

- `OK`

In this API:

- `domains` is the subname only
- `token` is your account token
- `ip` can be blank and DuckDNS will auto-detect IPv4

### When to use DuckDNS instead of your own domain

Use DuckDNS only if:

- you do not want to manage DNS in PA Viet Nam
- you do not want to attach Safe Zone to `quorix.io.vn`
- your public IP changes often and you want dynamic DNS quickly

## References

- Vercel says apex domains use `A` records and subdomains use `CNAME` records in project domain settings:
  [Vercel domain setup](https://vercel.com/docs/domains/working-with-domains/add-a-domain)
- Vercel notes subdomains generally should use `CNAME`, while apex domains use `A` records:
  [Vercel A record guide](https://vercel.com/kb/guide/a-record-and-caa-with-vercel)
- A third-party PA Viet Nam walkthrough shows the current login portal and the DNS management flow:
  [PA Viet Nam DNS walkthrough](https://docs.shopone.io/english/domain-setup/pointing-a-domain-from-some-popular-domain-providers/pointing-a-domain-from-pa-viet-nam)
- DuckDNS official API spec describes the `domains` and `token` parameters and the `OK` response:
  [DuckDNS API spec](https://www.duckdns.org/spec.jsp?id=duc127&prev=duc614)
- Oracle documents the Always Free compute limits and warns about idle reclaim/capacity issues:
  [Oracle Always Free resources](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)
