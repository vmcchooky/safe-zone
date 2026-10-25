# Production edge runbook

## Goal

Run Safe Zone on a single VPS with public HTTPS for the dashboard/API and DoH, while keeping internal ports `8080` and `8081` reachable only on loopback. Direct DoT on port `853` is optional and disabled by default.

## Prerequisites

- Docker Engine with the Compose plugin.
- DNS record pointing `SAFE_ZONE_PUBLIC_HOST` to the VPS, or DuckDNS credentials.
- Firewall/security group allows inbound `22/tcp`, `80/tcp`, and `443/tcp` only. Add `853/tcp` only when DoT is enabled.
- `.env` created from `ops/vps-edge/env.production-edge.production.example` (or the staging template).

## Deploy

```sh
cp ops/vps-edge/env.production-edge.production.example .env
vi .env
mkdir -p ops/certs/dot
mkdir -p ops/secrets
scripts/ops/release-preflight.sh --edge-mode production-edge --version 0.1.0
scripts/ops/safe-zone.sh deploy
```

Set at minimum:

- `SAFE_ZONE_ENV=production`
- `SAFE_ZONE_PUBLIC_HOST`
- `SAFE_ZONE_CADDY_EMAIL`
- `SAFE_ZONE_BLOCK_PAGE_IP` set to the public IPv4 that serves the block page
- `SAFE_ZONE_DNS_DOT_ENABLED=false` unless a trusted DoT certificate pair is already in place
- `SAFE_ZONE_ADMIN_PASSWORD` or `SAFE_ZONE_ADMIN_PASSWORD_FILE`
- `SAFE_ZONE_ADMIN_API_KEY` or `SAFE_ZONE_ADMIN_API_KEY_FILE`
- `SAFE_ZONE_ADMIN_USERNAME` (optional; defaults to `admin`)

Recommended file-based secret layout:

```env
SAFE_ZONE_ENV=production
SAFE_ZONE_ADMIN_USERNAME=admin
SAFE_ZONE_ADMIN_PASSWORD_FILE=./ops/secrets/admin_password
SAFE_ZONE_ADMIN_API_KEY_FILE=./ops/secrets/admin_api_key
SAFE_ZONE_GEMINI_API_KEY_FILE=./ops/secrets/gemini_api_key
SAFE_ZONE_DUCKDNS_TOKEN_FILE=./ops/secrets/duckdns_token
SAFE_ZONE_AGENT_WEBHOOK_URL_FILE=./ops/secrets/agent_webhook_url
SAFE_ZONE_BLOCK_PAGE_SUPPORT_EMAIL=security@example.com
```

The services mount `./ops/secrets` into `/app/ops/secrets`, so the same relative path works in local binaries, Compose containers, and the DuckDNS helper script.

Production deploy now uses:

- `docker-compose.yml` as the internal service baseline
- `docker-compose.production.yml` for public edge bindings
- `127.0.0.1:8080` and `127.0.0.1:8081` for host-local health/debug only
- `80` and `443` as the intended public surface
- `853` only when DoT is enabled through `ops/vps-edge/docker-compose.dot.yml`
- `docs/runbooks/release-gate.md` as the formal staging-to-production release flow

## Verify

```sh
scripts/ops/check-production-ports.sh
curl -fsS https://$SAFE_ZONE_PUBLIC_HOST/healthz
curl -fsS "https://$SAFE_ZONE_PUBLIC_HOST/v1/analyze?domain=example.com"
scripts/ops/public-edge-smoke.sh "$SAFE_ZONE_PUBLIC_HOST"
scripts/ops/check-block-page.sh "$SAFE_ZONE_PUBLIC_HOST" "$SAFE_ZONE_BLOCK_PAGE_IP" blocked.example.test
```

DoH uses the same host at `/dns-query`. DoT is opt-in: when
`SAFE_ZONE_DNS_DOT_ENABLED=true`, the resolver is started with
`ops/vps-edge/docker-compose.dot.yml`, which publishes host port `853` and maps
it to container port `8533` so the non-root resolver process does not need to
bind a privileged port inside the container. `scripts/ops/safe-zone.sh` adds
that overlay automatically when the flag is true. With DoT disabled, `853` is
not published and the port/certificate smoke checks are skipped.

If you use UFW on the VPS, the expected rule set is:

```sh
sudo ufw default deny incoming
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
# Add this only when SAFE_ZONE_DNS_DOT_ENABLED=true:
# sudo ufw allow 853/tcp
sudo ufw status verbose
```

Cloud firewalls/security groups should mirror the same rule set. Keep `853`
closed unless DoT is enabled. The public smoke script verifies the public
endpoints, but the cloud rule confirmation itself still needs to be recorded
per environment.

## Block page behavior

The production edge now supports two block-page flows:

- Plain HTTP sinkhole requests for arbitrary blocked domains are rewritten by Caddy to `/block` and rendered by `core-api`.
- Canonical HTTPS access is available at `https://$SAFE_ZONE_PUBLIC_HOST/block?domain=...`.

Choose `SAFE_ZONE_DNS_BLOCK_STRATEGY` based on the desired user experience:

- `sinkhole` returns `SAFE_ZONE_BLOCK_PAGE_IP` for blocked A/AAAA answers and enables the HTTP block-page flow.
- `nxdomain`, `refused`, and `nullip` avoid arbitrary-domain HTTPS certificate mismatch warnings by failing the DNS lookup instead of sending browsers to the block-page IP.

Direct HTTPS access to an arbitrary blocked third-party domain will still hit a browser certificate warning before any block page can render when `sinkhole` is selected. That is an expected TLS hostname-validation limit, not an application bug.

## Telemetry write sampling & storage sizing

In production, raw analysis logging without write sampling produces ~71 bytes per request into SQLite, which can consume hundreds of gigabytes over 30 days under sustained traffic.

Safe Zone bounds disk growth using write sampling at the single choke point `RecordAnalysis`:

- **Production default:** `docker-compose.production.yml` defaults `SAFE_ZONE_TELEMETRY_WRITE_PERCENT` to **5%** (a 20x write reduction).
- **High-traffic override:** Operators can explicitly override `SAFE_ZONE_TELEMETRY_WRITE_PERCENT=1` (1%) for sustained high-volume environments or VPS hosts with limited disk space.
- **Base/development default:** Unsampled at **100%** in `docker-compose.yml`.
- **Separate unsampled writers:** Security audit log (`agent_audit_log`), URL ML durable feedback (`url_ml_feedback`), local overrides, and brand lists use separate dedicated writers and are **never sampled**.
- **Sizing formula:**
  $$\text{Dung lượng steady-state} \approx W \times 71\text{ B} \times \text{RPS} \times 86.400 \times \text{retention\_days}$$
  *(Ví dụ: Tại 1.000 RPS liên tục với 30 ngày retention: 100% tốn ~184 GB; 5% tốn ~9.2 GB; 1% tốn ~1.8 GB)*.
- **Budget policy:** Projected telemetry in the retention window should not exceed **20–25%** of the available disk space allocated to Safe-Zone. Higher sampling (10–100%) should only be used temporarily during bounded investigation windows with close disk monitoring.

## DuckDNS

Set `SAFE_ZONE_DUCKDNS_DOMAIN` and `SAFE_ZONE_DUCKDNS_TOKEN`, then run:

```sh
scripts/ops/safe-zone.sh duckdns
```

`SAFE_ZONE_DUCKDNS_TOKEN_FILE` is also supported for file-based or Docker-secret-style setups.

Install `ops/cron/safe-zone-production.cron.example` to keep the record fresh.


## DoT certificates (optional)

Enable DoT only when you have a trusted certificate pair for
`SAFE_ZONE_PUBLIC_HOST`. The opt-in overlay mounts
`${SAFE_ZONE_DNS_DOT_CERTS_DIR:-./ops/certs/dot}` into `dns-resolver`. The
resolver expects:

- `fullchain.pem`
- `privkey.pem`

Export them into place, set `SAFE_ZONE_DNS_DOT_ENABLED=true` in `.env`, and
recreate the resolver:

```sh
scripts/ops/export-dot-cert.sh /path/to/fullchain.pem /path/to/privkey.pem
# Set SAFE_ZONE_DNS_DOT_ENABLED=true in .env before this step.
docker compose -f docker-compose.yml -f docker-compose.production.yml \
  -f ops/vps-edge/docker-compose.dot.yml up -d dns-resolver
```

`export-dot-cert.sh` writes `privkey.pem` as mode `0640` and assigns group
`101` (the container `app` GID) by default. Production refuses to start with
the self-signed development fallback.
