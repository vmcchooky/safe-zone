# Credential rotation runbook

## Goal

Rotate admin and third-party credentials without guessing which components need a restart or what to verify afterward.

## Covered secrets

- `SAFE_ZONE_ADMIN_PASSWORD`
- `SAFE_ZONE_ADMIN_API_KEY`
- `SAFE_ZONE_GEMINI_API_KEY`
- `SAFE_ZONE_DUCKDNS_TOKEN`
- `SAFE_ZONE_AGENT_WEBHOOK_URL`
- `SAFE_ZONE_ALERT_TELEGRAM_TOKEN`
- `SAFE_ZONE_ALERT_SLACK_WEBHOOK_URL`
- `SAFE_ZONE_ALERT_EMAIL_PASSWORD`

The administrator login name is configured separately with
`SAFE_ZONE_ADMIN_USERNAME` and defaults to `admin`.

## Recommended storage

Use `*_FILE` entries that point into `./ops/secrets`, for example:

```env
SAFE_ZONE_ADMIN_PASSWORD_FILE=./ops/secrets/admin_password
SAFE_ZONE_ADMIN_API_KEY_FILE=./ops/secrets/admin_api_key
SAFE_ZONE_GEMINI_API_KEY_FILE=./ops/secrets/gemini_api_key
```

Write the new value atomically and keep file permissions restricted:

```sh
umask 077
printf '%s\n' 'NEW-SECRET-VALUE' > ./ops/secrets/admin_api_key.new
mv ./ops/secrets/admin_api_key.new ./ops/secrets/admin_api_key
```

## Rotation steps

1. Generate the new secret outside the server if possible and store it in your password manager.
2. Replace the file under `./ops/secrets` or update the direct env value in `.env`.
3. Revoke the old third-party credential at the provider if one exists.
4. Restart the affected services.

For admin/API/AI/alert secrets:

```sh
docker compose -f docker-compose.yml -f docker-compose.production.yml restart core-api dns-resolver
```

To change the administrator login name, edit `.env` and recreate `core-api`
so Compose loads the new environment value:

```env
SAFE_ZONE_ADMIN_USERNAME=henry
```

```sh
docker compose -f docker-compose.yml -f docker-compose.production.yml --profile production-edge up -d --no-deps --force-recreate core-api
```

The username is normalized to lowercase. The reserved username `guest` cannot
be used for the administrator account. Existing admin sessions are not valid
for the new login identity after the restart; sign in again.

The admin password is bcrypt-hashed once at core-api startup and never
stored in plaintext by the service. It must be 12-72 **bytes** long (the
bcrypt input limit; multibyte characters count per byte, not per rune) —
core-api refuses to start otherwise. Rotating `SAFE_ZONE_ADMIN_PASSWORD`
requires the restart above; there is no plaintext copy to update in the
database. The restart also invalidates every issued admin session (sessions
are revocable and re-validated per request), so operators must log in again
with the new password.

For feed sync Redis password changes:

```sh
docker compose -f docker-compose.yml -f docker-compose.production.yml restart feed-syncd
```

For DuckDNS token changes:

```sh
scripts/ops/safe-zone.sh duckdns
```

## Verification

Run the basics:

```sh
scripts/ops/check-production-ports.sh
curl -fsS https://$SAFE_ZONE_PUBLIC_HOST/healthz
curl -fsS "https://$SAFE_ZONE_PUBLIC_HOST/v1/analyze?domain=example.com"
scripts/ops/public-edge-smoke.sh "$SAFE_ZONE_PUBLIC_HOST"
```

Then verify the rotated capability specifically:

- Admin password: log in to `/app/` with the new password. Use `/dashboard` only for legacy compatibility checks.
- Admin API key: call an authenticated endpoint with `Authorization: Bearer <new key>`.
- Gemini key: trigger an analysis path that may use AI and confirm no provider auth error appears.
- DuckDNS token: run `scripts/ops/safe-zone.sh duckdns`.
- Webhook or alert secrets: manually trigger the `alert` task from the dashboard or `POST /v1/agent/trigger?task=alert`.

## Rollback

If the new credential fails and cannot be fixed quickly:

1. Restore the previous secret file or env value.
2. Restart the same affected services.
3. Verify the known-good credential path again.
