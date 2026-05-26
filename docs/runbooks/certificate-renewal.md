# Certificate renewal runbook

Caddy manages public HTTPS certificates automatically for `SAFE_ZONE_PUBLIC_HOST`.

## Detect

```sh
docker compose logs caddy --tail=200
curl -Iv https://$SAFE_ZONE_PUBLIC_HOST/healthz
```

## Common causes

- DNS record does not point to the VPS.
- Ports `80/tcp` or `443/tcp` are blocked.
- `SAFE_ZONE_PUBLIC_HOST` is still set to `localhost`.
- Let's Encrypt rate limits after repeated failed attempts.

## Mitigate

```sh
scripts/safe-zone.sh duckdns
docker compose -f docker-compose.yml -f docker-compose.production.yml --profile production-edge restart caddy
```

DoT certificates are configured separately through:

- mounted files under `${SAFE_ZONE_DNS_DOT_CERTS_DIR:-./ops/certs/dot}`
- `/run/safe-zone/dot-certs/fullchain.pem`
- `/run/safe-zone/dot-certs/privkey.pem`

If they are empty, the resolver generates a temporary self-signed certificate for development.

After a renewal, refresh the mounted DoT pair and restart only the resolver:

```sh
scripts/export-dot-cert.sh /path/to/fullchain.pem /path/to/privkey.pem
docker compose -f docker-compose.yml -f docker-compose.production.yml restart dns-resolver
scripts/public-edge-smoke.sh "$SAFE_ZONE_PUBLIC_HOST"
```
