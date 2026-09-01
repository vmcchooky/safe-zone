# Redis outage runbook

Safe Zone is designed to fail open when Redis is unavailable. Domain analysis and policy checks continue with lexical, feed-independent, TLS, WHOIS, and optional AI signals, but cache hits and Redis-backed feed matches are degraded.

## Detect

```sh
scripts/ops/safe-zone.sh status
docker compose logs redis --tail=100
```

The dashboard system panel also reports Redis state.

## Mitigate

```sh
docker compose restart redis
docker compose exec redis redis-cli ping
```

If Redis data is corrupt, restore the newest known-good RDB:

```sh
scripts/ops/safe-zone.sh restore backups/<timestamp>/redis-dump.rdb
```

## Follow-up

- Confirm `/v1/analyze` works.
- Run `scripts/ops/safe-zone.sh feed-sync` to repopulate threat feeds if needed.
- Check memory pressure against `SAFE_ZONE_REDIS_MAXMEMORY`.
- Confirm `.redis.maxmemory_policy` is `volatile-lru` (or `noeviction`) and
  `.redis.eviction_policy_safe` is `true` on `/v1/status`.
- Confirm `.feed_sync.active_entries` is greater than zero after a successful
  sync. A `missing` feed status is critical even while Redis still answers
  `PING`.

## Memory pressure and eviction safety

The shared single-VPS Redis stores two classes of data:

- expiring analysis/cache keys, which may be evicted under pressure;
- non-expiring threat-feed, feed-status and revision keys, which must survive.

The Compose baseline therefore uses `volatile-lru`. Never use an `allkeys-*`
policy with a shared Redis because it makes the threat-feed ZSET eligible for
whole-key eviction. `noeviction` also protects the feed, but cache/feed writes
will fail once memory is full.

### Verify

```sh
curl -fsS http://127.0.0.1:8080/v1/status | jq '{redis: .redis, feed_sync: {status: .feed_sync.status, active_entries: .feed_sync.active_entries}}'
docker compose exec redis redis-cli CONFIG GET maxmemory-policy
docker compose exec redis redis-cli ZCOUNT safe-zone:threat:feed "$(date +%s)" +inf
```

When changing from `allkeys-lru`, first back up Redis, change
`SAFE_ZONE_REDIS_MAXMEMORY_POLICY=volatile-lru`, recreate/restart Redis, then
run feed sync and verify `active_entries > 0`. If feed sync returns OOM, raise
the bounded `SAFE_ZONE_REDIS_MAXMEMORY` budget or split cache and threat-feed
Redis instances; do not fall back to an `allkeys-*` policy.

## Threat feed key wrong type

The threat feed key (`SAFE_ZONE_THREAT_FEED_KEY`, default `safe-zone:threat:feed`) must be a Redis **ZSET** scored by expiry epoch. If it shows any other type (typically `set`, created by a pre-hardening build that used `SADD`), feed matching and OSINT promotion break; the OSINT task logs `threat feed key has incompatible type` and records a `threat_feed_key_wrong_type` agent event instead of writing into the bad key.

### Detect

```sh
docker compose exec redis redis-cli TYPE safe-zone:threat:feed
docker compose logs core-api --tail=200 | grep "incompatible type"
```

### Recover (manual — the service never deletes the key)

```sh
# 1. Back up the wrong-type key under a quarantine name.
docker compose exec redis redis-cli RENAME safe-zone:threat:feed safe-zone:threat:feed:quarantine-$(date +%Y%m%d%H%M%S)

# 2. Recreate the ZSET from the configured feed sources.
scripts/ops/safe-zone.sh feed-sync

# 3. Verify.
docker compose exec redis redis-cli TYPE safe-zone:threat:feed   # -> zset
```

Do not `DEL` the original key before inspecting the quarantined copy — it may contain manual promotions worth reviewing.
