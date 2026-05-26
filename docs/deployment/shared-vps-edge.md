# Safe Zone On The Shared Quorix VPS

Use this path when Safe Zone runs behind the host-level Caddy edge for all Quorix apps.

## First Deploy

```sh
cd /opt/safe-zone
cp ops/vps-edge/env.shared-host-edge.production.example .env
nano .env
scripts/release-preflight.sh --edge-mode shared-host-edge --version 0.1.0

docker compose \
  -f docker-compose.yml \
  -f ops/vps-edge/docker-compose.host-edge.yml \
  up -d --build redis core-api dns-resolver
```

The app listens only on loopback:

- `127.0.0.1:8080` for Safe Zone core API/dashboard
- `127.0.0.1:8081` for DNS resolver HTTP/DoH

The shared VPS Caddyfile should route `safe.quorix.io.vn` to these loopback ports.

## Verify

```sh
curl -I http://127.0.0.1:8080/healthz
curl -I http://127.0.0.1:8081/healthz
curl "http://127.0.0.1:8080/v1/analyze?domain=example.com"
curl -I https://safe.quorix.io.vn/healthz
curl "https://safe.quorix.io.vn/v1/analyze?domain=example.com"
```

## Enable DoT Later

Only do this after HTTPS is healthy and DoT certificate files exist at:

```text
ops/certs/dot/fullchain.pem
ops/certs/dot/privkey.pem
```

Then update `.env`:

```env
SAFE_ZONE_DNS_DOT_ENABLED=true
SAFE_ZONE_DNS_DOT_PUBLISHED_PORT=853
SAFE_ZONE_DNS_DOT_CONTAINER_PORT=8533
SAFE_ZONE_DNS_DOT_CERTS_DIR=./ops/certs/dot
```

Start with the DoT override:

```sh
docker compose \
  -f docker-compose.yml \
  -f ops/vps-edge/docker-compose.host-edge.yml \
  -f ops/vps-edge/docker-compose.dot.yml \
  up -d --build dns-resolver
```

Open the VPS firewall after the container is healthy:

```sh
sudo ufw allow 853/tcp
```

## Notes

- Do not start the internal Safe Zone `caddy` service on the shared VPS.
- Keep `SAFE_ZONE_BLOCK_PAGE_IP` set to the VPS public IPv4 in production.
- Keep `SAFE_ZONE_AI_PROVIDER=none` for the first deploy; enable Gemini only after the base stack is stable.
- Use `docs/runbooks/release-gate.md` for the formal staging and production release flow.
