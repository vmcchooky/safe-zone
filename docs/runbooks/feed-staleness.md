# Threat feed staleness runbook

Threat feeds are defense-in-depth. If feed sync fails, Safe Zone continues to analyze domains, but known-bad coverage degrades over time.

## Detect

```sh
docker compose logs feed-syncd --tail=200
grep -i "feed" logs/feed-sync.log
```

When the agent is enabled, feed sync events are recorded in SQLite agent events.
`core-api` also exposes feed freshness on `/` and `/metrics` under `feed_sync`.

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
