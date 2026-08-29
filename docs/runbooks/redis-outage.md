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
