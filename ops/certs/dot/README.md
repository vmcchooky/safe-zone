# DoT certificate mount point

Production Compose mounts this directory into `dns-resolver` as:

- `/run/safe-zone/dot-certs/fullchain.pem`
- `/run/safe-zone/dot-certs/privkey.pem`

Do not commit real certificate material. The repository ignores `*.pem` in this directory.

Recommended workflow:

1. Obtain or renew the public certificate for `SAFE_ZONE_PUBLIC_HOST`.
2. Export/copy the pair into this directory with `scripts/export-dot-cert.sh`.
3. Restart only the resolver:

```sh
docker compose -f docker-compose.yml -f docker-compose.production.yml restart dns-resolver
```
