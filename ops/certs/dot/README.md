# DoT certificate mount point

DoT is opt-in. When `SAFE_ZONE_DNS_DOT_ENABLED=true`, the resolver mounts this
directory as:

- `/run/safe-zone/dot-certs/fullchain.pem`
- `/run/safe-zone/dot-certs/privkey.pem`

The production base Compose file does not publish `853` or mount this
directory. Use `ops/vps-edge/docker-compose.dot.yml` when enabling DoT.

Do not commit real certificate material. The repository ignores `*.pem` in
this directory.

Recommended workflow:

1. Obtain or renew the public certificate for `SAFE_ZONE_PUBLIC_HOST`.
2. Export/copy the pair into this directory with
   `scripts/ops/export-dot-cert.sh`. The script writes the key as mode `0640`
   and assigns it to group `101` (the container `app` GID) by default.
3. Enable DoT in `.env`:

   ```env
   SAFE_ZONE_DNS_DOT_ENABLED=true
   ```

4. Deploy or recreate the resolver with the DoT overlay:

   ```sh
   scripts/ops/safe-zone.sh deploy
   ```

   Or, for a resolver-only restart:

   ```sh
   docker compose -f docker-compose.yml -f docker-compose.production.yml \
     -f ops/vps-edge/docker-compose.dot.yml up -d dns-resolver
   ```

5. Verify the public path:

   ```sh
   scripts/ops/public-edge-smoke.sh --dot "$SAFE_ZONE_PUBLIC_HOST"
   ```

Production requires a trusted pair. The self-signed fallback exists only for
local/test runs.
