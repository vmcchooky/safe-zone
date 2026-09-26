# Threat feed staleness runbook

Threat feeds are defense-in-depth. If feed sync fails, Safe Zone continues to analyze domains, but known-bad coverage degrades over time.

## Detect

```sh
# feed-syncd only runs under the feed-sync Compose profile
docker compose --profile feed-sync logs feed-syncd --tail=200
# file log exists only when cron file-logging is enabled
grep -i "feed" logs/feed-sync.log
```

When the agent is enabled, feed sync events are recorded in SQLite agent events.
Authenticated `GET /v1/status` carries feed freshness under `feed_sync`
(`curl` needs `Authorization: Bearer $SAFE_ZONE_ADMIN_API_KEY`); the public
`/metrics` endpoint exposes request counters only.

## Adblock emergency control

Adblock is a content-policy layer, separate from security verdicts. It is the
largest single source of blocked requests, and on a shared-infrastructure
footprint a `suffix` rule can also take down Firebase, Crashlytics, messaging
or payment endpoints. It therefore ships **enabled by default** but with a
first-class switch.

### Turn it off in the dashboard

`Settings → Ad blocking → toggle`. The change applies within 30 seconds, with
no restart and no resync, because the enable flag is evaluated at decision
time. Turning adblock off does **not** weaken malware, phishing, threat-feed or
brand detection; those layers are independent.

### Match mode

| Mode | Behaviour | Consequence |
| --- | --- | --- |
| `suffix` (default) | A listed domain also blocks all its subdomains | Broader. Can block shared service infrastructure. |
| `exact` | Only the hostname literally listed is blocked | Narrower. Fewer collateral blocks, but some ad subdomains get through. |

Changing the mode is applied asynchronously: the rules are rebuilt from the
configured sources, so the new scope takes effect once that rebuild finishes
rather than instantly.

### Verify the current state

```sh
curl -s http://127.0.0.1:8080/v1/status | jq '.adblock | {enabled, match_mode, domain_count}'
```

### API

```sh
# Disable (emergency stop)
curl -X POST http://127.0.0.1:8080/v1/settings \
  -H "Authorization: Bearer $SAFE_ZONE_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"adblock_enabled": false}'

# Narrow the rule scope
curl -X POST http://127.0.0.1:8080/v1/settings \
  -H "Authorization: Bearer $SAFE_ZONE_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"adblock_match_mode": "exact"}'
```

Both fields are pointers on the request: omitting `adblock_enabled` never
changes the switch, so saving an unrelated setting cannot silently re-enable
the layer. An unsupported `adblock_match_mode` is rejected with 400 and
changes nothing.

### Environment defaults

`SAFE_ZONE_ADBLOCK_ENABLED` (default `true`) and `SAFE_ZONE_ADBLOCK_MATCH_MODE`
(default `suffix`) seed the process. A value persisted under the
`adblock_enabled` / `adblock_match_mode` system-config keys overrides them and
survives a restart, so the dashboard switch is authoritative once used.

## Inventory stale shared-host members

Before any targeted purge, inventory the members that the current admission
policy would refuse today:

```sh
go run ./cmd/feed-shared-host-audit -redis-addr <host:port>
```

The command is strictly read-only: it never writes, deletes or mutates Redis.
Classification uses `feed.IsAdmissibleDomain`, the same predicate that every
feed writer and the OSINT promotion path use, so the inventory cannot drift
from runtime behavior when the analysis registries change.

Use it on a production container when a local build cannot reach Redis:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/audit ./cmd/feed-shared-host-audit
docker cp /tmp/audit <redis-container>:/tmp/audit
docker exec <redis-container> chmod +x /tmp/audit
docker exec <redis-container> /tmp/audit -redis-addr 127.0.0.1:6379
```

To classify specific hostnames without touching Redis at all:

```sh
go run ./cmd/feed-shared-host-audit -member docs.google.com -member github.com
```

Refused members are exactly the ones a purge may target. Members reported as
admissible include tenant subdomains (`microsoft.github.io`) and suffix
lookalikes (`raw.githubusercontent.com.evil.com`); those must never be purged.

## Manual sync

```sh
. ./.env
scripts/ops/safe-zone.sh feed-sync
```

Recommended free source preset:

```sh
SAFE_ZONE_AGENT_FEED_PRESET=production-free
SAFE_ZONE_AGENT_FEED_ADMISSION_MODE=corroborated-url-host-shadow
```

That preset currently expands to:

- `https://urlhaus.abuse.ch/downloads/csv_recent/`
- `https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt`

`REScure` is not in the first-class preset because `https://rescure.me/` currently serves a temporary-closure page as of 2026-05-21.

## Follow-up

- Keep sources additive unless a feed is known compromised.
- Prefer HTTPS feed URLs.
- Review parser stats for high invalid counts, which may indicate feed format drift.
- In shadow mode, review each source's `admission.authoritative_hosts`,
  `contextual_hosts`, and `authoritative_retention`. Shadow mode does not change
  Redis membership or verdicts.
- Do not configure `corroborated-url-host-filter` for runtime sync. The binary
  rejects it outside dry-run until malicious-retention and per-source removal
  guardrails are satisfied.
- Treat `feed_sync.status=stale` or any source with `stale=true` as an operator action item before relying on feed-backed blocking coverage.
