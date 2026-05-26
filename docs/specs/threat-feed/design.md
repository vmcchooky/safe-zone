# Design: Local Threat Feed

## Overview

Threat feed support adds a known-bad domain layer ahead of lexical scoring. The feed is stored in Redis so both `core-api` and `dns-resolver` share the same data without adding a new database.

## Redis Keys

- `safe-zone:threat:feed`: Redis Set of normalized domains.
- Existing analysis cache remains `safe-zone:analysis:<domain>`.

## Feed Sync Command

Add `cmd/feed-sync`.

### Inputs

Flags:

- `-source`: local file path or HTTP/HTTPS URL. Defaults to `SAFE_ZONE_THREAT_FEED_SOURCE`.
- `-redis-addr`: defaults to `SAFE_ZONE_REDIS_ADDR`.
- `-redis-password`: defaults to `SAFE_ZONE_REDIS_PASSWORD`.
- `-redis-db`: defaults to `SAFE_ZONE_REDIS_DB`.
- `-key`: defaults to `SAFE_ZONE_THREAT_FEED_KEY`, then `safe-zone:threat:feed`.
- `-dry-run`: parse and report without writing Redis.
- `-replace`: replace the set atomically enough for this local-first version by deleting the key before adding parsed domains.

### Parsing

- TXT: each line is a candidate.
- CSV: each field is scanned and the first field that normalizes as a domain is accepted.
- Lines beginning with `#` are ignored.
- Inline comments beginning with `#` are stripped for TXT-like rows.

### Output

The command logs:

- source
- dry-run/replace mode
- valid domains
- invalid rows
- duplicate domains
- written domains

## Risk Service Integration

`internal/risk.Service` gains:

- `ThreatFeedKey string`
- feed exact/suffix matching inside `analyze`, after cache miss and before lexical analysis.

Flow:

1. Normalize domain.
2. Check cached analysis result.
3. Check exact match in `safe-zone:threat:feed`.
4. Check parent suffixes from nearest parent to root, such as `a.b.example.com` -> `b.example.com`, `example.com`, `com`.
5. On match, return malicious feed result and write it to analysis cache.
6. If Redis feed check fails, log and continue with lexical analysis.

## Dashboard

Dashboard already renders `reasons`. Feed result visibility is provided by rendering `matched local threat feed` in the reason chips and recent table remains unchanged.

## Testing

Use a Redis-compatible test server for feed matching tests. Also test Redis-disabled behavior without a server.
