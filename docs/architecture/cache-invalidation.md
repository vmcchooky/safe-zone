# Cross-process cache invalidation

Safe Zone runs two long-lived Go services (`core-api`, `dns-resolver`) plus the
opt-in `feed-syncd` daemon against **one shared SQLite file and one shared
Redis**. Both Go services construct a full `risk.Service`
(`cmd/core-api/main.go`, `cmd/dns-resolver/main.go`), so every cache below
exists once **per process**. This document is the contract for how a change
written by one process reaches the others, and the worst-case staleness an
operator should expect from each layer.

Audited 2026-10-29 against `main`; the audit's findings and their resolution
are recorded at the bottom.

## Invalidation mechanisms

| Mechanism | Where used | Worst-case staleness |
|---|---|---|
| Redis pub/sub (`safe-zone:config:analysis:updated`) | analysis config, whitelist, client mappings | immediate (bounded by the poll fallback below when Redis is down) |
| Revision epoch, read live per request | analysis result cache (feed + brand revisions from Redis, config + model revisions in-process) | 0 (a write bumps the revision before the next read) |
| Poll fallback (30s reconciler tick) | analysis config, whitelist, client mappings — works with Redis disabled | ≤ 30s (`SAFE_ZONE_CONFIG_RELOAD_POLL_SECONDS`) |
| Adblock config poll (30s tick) | adblock enabled flag, match mode, per-source policies, content-exception file | ≤ 30s + trie rebuild duration |
| TTL only | analysis cache entries, brand list in non-writer processes, OSINT evidence, WHOIS cache, recent list | the entry's TTL (table below) |
| Restart only | ML bundle, ML mode/canary, URL-ML ops baseline | by design; cache entries stay coherent because the model revision participates in the epoch check |

Pub/sub is an optimization, never a correctness requirement: every pub/sub
event is gated by a durable revision, and the 30s reconciler
(`internal/risk/config_reload.go`) delivers the same change from the shared
store alone. Tests pin this in `internal/risk/config_reload_test.go`
(`TestReconcilerConvergesWithoutRedis`,
`TestPubSubReloadEventsApplyAndDeduplicate`).

## Inventory

| # | Cache / derived state | Storage | Writer(s) | Invalidation | Worst-case staleness |
|---|---|---|---|---|---|
| 1 | DNS upstream response cache (`internal/dns/resolver/cache.go`) | in-process LRU, ≤4096 entries | every upstream answer | TTL (capped 300s) + LRU; serve-stale extends to TTL+1h at TTL 30s during upstream outage; policy/overrides/whitelist are re-evaluated on **every** hit, so a hit never bypasses a policy change | ≤300s fresh; ≤1h stale under outage |
| 2 | DoH upstream health pool (`internal/dns/doh/upstream.go`) | in-process | traffic + probe loop | active probe every 30s | ≤30s |
| 3 | Analysis result cache (`internal/risk/analysis_pipeline.go`) | Redis JSON per domain | `analyze()`, enrichment worker (CAS), OSINT rewrite | revision epoch checked on every read: `analysis_revision` (algorithm, const), `config_revision` (in-process), `model_revision` (in-process), `feed_revision` + `brand_revision` (read live from Redis, fail-closed on read error); agent promotions additionally delete the entry | ≤ entry TTL (3h/1h/6h by verdict) after a revision bump; immediate for agent promote/override |
| 4 | Analysis config (`internal/risk/config_reload.go`) | SQLite `system_config:analysis_config` + in-process | `PUT /v1/config/analysis` (core-api) | pub/sub + revision compare + 30s poll | ≤30s (restart-only if poll=0 **and** Redis down at write time — keep poll enabled) |
| 5 | Whitelist RAM index (`internal/risk/whitelist.go`) | SQLite `whitelist_domains` + `whitelist_revision`; RAM Bloom+exact index | API restore (publishes), agent auto-update task (poll-only), file import at startup | pub/sub + revision compare + 30s poll; failed rebuild keeps the old index and retries next tick | ≤30s |
| 6 | Client-mappings CIDR index (`internal/store/groups.go`) | SQLite `client_mappings` + `client_mappings_revision`; per-handle RAM cache | mapping/group CRUD (core-api) | pub/sub + revision compare + 30s poll (per store handle) | ≤30s |
| 7 | Brand list (`internal/store/brand.go`) | in-process snapshot + Redis copy | brand CRUD (core-api) | writer invalidates locally + Redis; other processes: TTL only; analysis-cache entries stay coherent via `brand_revision` epoch | ≤ `SAFE_ZONE_BRAND_CACHE_TTL_SECONDS` (300s) in non-writer processes |
| 8 | Threat feed ZSET (`internal/risk/feed_engine.go`) | Redis ZSET | feed-syncd daemon / `feed-sync` / agent tasks | read live per query (no snapshot); `feed_revision` epoch invalidates analysis-cache entries | 0 for coherence; feed data freshness = sync interval (24h default) |
| 9 | OSINT evidence cache (`internal/osint/osint.go`) | Redis + SQLite mirror | lookup on demand | TTL, keyspace scoped by source-config fingerprint | ≤6h |
| 10 | WHOIS cache (`internal/whois/lookup.go`) | SQLite table | lookup on demand | TTL only | ≤7 days |
| 11 | Adblock rule trie (`internal/risk/adblock_engine.go`) | in-process RAM trie + warm-start files under `data/` | source sync (12h ticker), operator actions | 12h rebuild ticker; resync request on operator changes; **match-mode changes in another process now rescope within 30s** (see findings) | ≤12h for source content; ≤30s for operator switches |
| 12-15 | Adblock enabled flag / match mode value / per-source policies / content exceptions | in-process atomics; source of truth in `system_config` or the exceptions file | operator writes; out-of-band file edit | 30s config poll (`runAdblockConfigSync`); policies additionally fingerprint-compared and resynced on change | ≤30s each |
| 16 | Telemetry recent ring (`internal/risk/telemetry_engine.go`) | Redis list | write-through on every analysis | write-through, TTL 24h | 0 |
| 17 | ML bundle + URL-ML baseline (`internal/analysis/ml_classifier.go`) | in-process, loaded once | deployment (bundle swap + restart) | restart-only by design; `model_revision` participates in the analysis-cache epoch | n/a |
| 18 | URL-ML feedback store (`internal/risk/url_feedback_durable.go`) | SQLite or memory | feedback API | retention prune every 10min | n/a (operational data) |
| 19-20 | Enrichment queue, rate-limit buckets | in-process | internal / traffic | drained at shutdown / idle-key eviction | n/a (process-local) |
| 21 | Overrides, group overrides, client groups, guest access, other `system_config` | SQLite | API writes | **no cache** — read through on every request | 0 |

## Audit findings (2026-10-29)

**Fixed in the same change as this document:**

- **Match-mode rescope crossed processes through the 12h rebuild ticker.**
  `refreshAdblockMatchMode` picked up a persisted `adblock_match_mode` change
  within 30s but never requested a trie rebuild, and rule scope
  (suffix vs exact) is decided at rebuild time — so a mode flip applied from
  the dashboard left the *other* process enforcing the old scope for up to
  12 hours. The refresh now compares the mode and requests a resync on change
  (`TestMatchModePollTriggersResync` pins the contract). Residual: a process
  that starts between the write and its first 30s tick briefly builds its
  startup trie from the environment default; the first tick rescopes it.

**Accepted and bounded (no change required):**

- **Agent-driven whitelist import relies on the 30s poll** instead of
  publishing a reload event
  (`internal/agent/whitelist_update.go`). Bounded at 30s; a publish would be
  a nice-to-have, not a correctness fix.
- **Brand list in the non-writer process is TTL-only (300s).** Decision
  correctness is immediate (the `brand_revision` epoch invalidates analysis
  cache entries), but lexical brand evidence used during re-analysis can be
  up to 300s old. Bounded and short.
- **`SAFE_ZONE_CONFIG_RELOAD_POLL_SECONDS=0` with Redis down at write time**
  makes analysis config, whitelist and client-mapping changes restart-only.
  The default (30s) is safe; operators who disable polling accept the
  documented trade-off.
- **Whitelist reload with SQLite disabled is restart-only** (the startup
  file-loaded index never refreshes). SQLite is a deployment requirement for
  multi-process staleness bounds; single-process deployments are unaffected.

**Follow-ups (tracked, not yet fixed):**

- A failed per-domain analysis-cache delete during an agent promotion leaves
  the feed entry live while a stale cached verdict can shadow it until the
  entry TTL (mitigated: the OSINT cycle bumps `feed_revision`, which
  invalidates entries older than the bump).
  `internal/agent/osint.go` (`promote`), `internal/agent/audit.go`.
- Both Go processes run the adblock sync and write the same warm-start files
  under `SAFE_ZONE_FEED_FILE_ROOT` (last-writer-wins). Harmless today because
  the files are warm-start fallbacks only; if they ever become a source of
  truth, give one process ownership.

## Testing the contract

```sh
# Poll-fallback convergence, pub/sub delivery + dedupe, match-mode rescope:
go test ./internal/risk/ -run 'TestReconcilerConvergesWithoutRedis|TestPubSubReloadEventsApplyAndDeduplicate|TestMatchModePollTriggersResync' -count=1

# Response-cache semantics (TTL cap, LRU bound, serve-stale):
go test ./internal/dns/resolver/ -count=1
```
