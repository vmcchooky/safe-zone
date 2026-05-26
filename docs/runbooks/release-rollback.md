# Release rollback runbook

## Goal

Roll back the Safe Zone application release to the last-known-good images and config without restoring Redis or SQLite by default.

Use this runbook when:

- the new release fails health or smoke checks
- version metadata is wrong
- edge routing or auth behavior regresses
- application binaries must be reverted quickly

Do not restore Redis or SQLite unless the release caused data corruption or a state incompatibility that cannot be resolved by rolling back the application images alone.

## Inputs required before release

Record these before every production deployment:

- last-known-good image tags for each released service
- last-known-good git commit
- last-known-good `.env` or equivalent config snapshot
- backup directory or restore point if data rollback becomes necessary

## Standard rollback

1. Stop and assess the failed release.
2. Restore the last-known-good image tags.
3. Restore the last-known-good config snapshot if the failure is config-related.
4. Bring the stack back up.
5. Verify health, version metadata, and smoke checks.

## Production-edge rollback

1. Replace the current image tags or release checkout with the last-known-good release.
2. Restore the last-known-good `.env` if needed.
3. Redeploy:

```sh
scripts/safe-zone.sh deploy
```

4. Verify:

```sh
curl -fsS https://$SAFE_ZONE_PUBLIC_HOST/healthz
curl -fsS https://$SAFE_ZONE_PUBLIC_HOST/v1/version
scripts/public-edge-smoke.sh "$SAFE_ZONE_PUBLIC_HOST"
```

5. If `sinkhole` blocking is enabled, also run:

```sh
scripts/check-block-page.sh "$SAFE_ZONE_PUBLIC_HOST" "$SAFE_ZONE_BLOCK_PAGE_IP" blocked.example.test
```

## Shared-host-edge rollback

1. Replace the current image tags or release checkout with the last-known-good release.
2. Restore the last-known-good `.env` if needed.
3. Redeploy:

```sh
docker compose \
  -f docker-compose.yml \
  -f ops/vps-edge/docker-compose.host-edge.yml \
  up -d --build redis core-api dns-resolver
```

4. Verify:

```sh
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8081/healthz
curl -fsS http://127.0.0.1:8080/v1/version
curl -fsS http://127.0.0.1:8081/v1/version
curl -fsS "https://$SAFE_ZONE_PUBLIC_HOST/v1/analyze?domain=example.com"
```

## Data restore is exceptional

Only restore Redis or SQLite when:

- the release wrote incompatible state
- the release corrupted persistent data
- application rollback alone cannot restore service integrity

If data restore is required, use the existing backup/restore helpers and record the reason:

- Linux: `scripts/safe-zone.sh restore`
- Windows: `pwsh ./scripts/safe-zone.ps1 restore`

After any data restore, rerun health, version, and smoke checks before closing the incident.
