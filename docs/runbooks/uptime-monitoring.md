# Uptime monitoring runbook

Use this runbook to add an external uptime check for Safe Zone so operators get alerted when the service is down before users have to tell them.

## Goal

Continuously probe the public `core-api` health endpoint and trigger an alert when the service stops responding successfully.

## Preferred target

Monitor:

- `https://<public-host>/healthz`

Fallback for private staging only:

- `http://127.0.0.1:8080/healthz`

Expected success response:

- HTTP `200`
- JSON body containing `"status":"ok"`

## Option A: Uptime Kuma

1. Create a new HTTP(s) monitor.
2. Set the URL to:

   ```text
   https://safe.example.com/healthz
   ```

3. Recommended settings:
   - Check interval: `60s`
   - Retry count: `3`
   - Request timeout: `10s`
   - Accepted status codes: `200-299`
4. Add at least one notification target:
   - Telegram
   - Slack
   - Email
5. Optional keyword check:
   - Require response body to contain `ok`

## Option B: UptimeRobot

1. Create a new `HTTP(s)` monitor.
2. Set the friendly name to `Safe Zone core-api`.
3. Set the monitored URL to:

   ```text
   https://safe.example.com/healthz
   ```

4. Configure alert contacts.
5. If available in the selected plan, enable keyword validation for `ok`.

## Alert policy

Recommended minimum alert rule:

- Alert after `3` consecutive failures
- Notify the primary on-call operator
- Escalate if the monitor stays red for more than `10` minutes

## What to do when it fires

1. Confirm `/healthz` is still failing manually.
2. Check `/readyz` and `/v1/version`.
3. Review:
   - container status
   - reverse proxy / Caddy
   - Redis availability
   - certificate expiry if HTTPS just broke
4. If the service is not recovering quickly, follow:
   - [release-rollback.md](D:/Quorix/services/safe-zone/docs/runbooks/release-rollback.md)
   - [redis-outage.md](D:/Quorix/services/safe-zone/docs/runbooks/redis-outage.md)
   - [certificate-renewal.md](D:/Quorix/services/safe-zone/docs/runbooks/certificate-renewal.md)

## Minimum production expectation

Production should not rely only on local smoke scripts. At least one external uptime monitor should probe the public `core-api` endpoint continuously and send alerts outside the Safe Zone host.
