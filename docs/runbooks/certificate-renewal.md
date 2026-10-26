# Certificate renewal runbook

Caddy manages public HTTPS certificates automatically for `SAFE_ZONE_PUBLIC_HOST`.

## Detect

```sh
docker compose logs caddy --tail=200
curl -Iv https://$SAFE_ZONE_PUBLIC_HOST/healthz
# Daily cron can alert instead: exit 1 while any certificate is inside the
# warning window (14 days by default, see SAFE_ZONE_CERT_WARN_DAYS).
scripts/ops/monitor-certs.sh --fail-on-warning
```

## Common causes

- DNS record does not point to the VPS.
- Ports `80/tcp` or `443/tcp` are blocked.
- `SAFE_ZONE_PUBLIC_HOST` is still set to `localhost`.
- Let's Encrypt rate limits after repeated failed attempts.

## Mitigate

```sh
scripts/ops/safe-zone.sh duckdns
docker compose -f docker-compose.yml -f docker-compose.production.yml --profile production-edge restart caddy
```

DoT is opt-in. When `SAFE_ZONE_DNS_DOT_ENABLED=true`, the resolver reads:

- mounted files under `${SAFE_ZONE_DNS_DOT_CERTS_DIR:-./ops/certs/dot}`
- `/run/safe-zone/dot-certs/fullchain.pem`
- `/run/safe-zone/dot-certs/privkey.pem`

Outside production (`local`/`test`), an empty pair generates a temporary
self-signed certificate. Production refuses to start without a configured
pair. The production base Compose file does not publish `853`; the opt-in
overlay `ops/vps-edge/docker-compose.dot.yml` adds both the port and the
certificate mount.

After a renewal, refresh the mounted DoT pair and recreate only the resolver:

```sh
scripts/ops/export-dot-cert.sh /path/to/fullchain.pem /path/to/privkey.pem
# SAFE_ZONE_DNS_DOT_ENABLED=true must be set in .env
docker compose -f docker-compose.yml -f docker-compose.production.yml \
  -f ops/vps-edge/docker-compose.dot.yml up -d dns-resolver
scripts/ops/public-edge-smoke.sh --dot "$SAFE_ZONE_PUBLIC_HOST"
```

`export-dot-cert.sh` writes the key as mode `0640` and assigns it to container
group `101` by default, so the unprivileged `app` user can read it. Override
the group with `SAFE_ZONE_DOT_KEY_GROUP` only if the image GID changes.
