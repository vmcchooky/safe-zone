# DNS response cache semantics

The dns-resolver keeps one bounded in-process cache of upstream answers
(`internal/dns/resolver/cache.go`). It exists to save upstream round-trips;
it never caches policy verdicts. Overrides, whitelist, group policy, adblock
and CNAME uncloaking are evaluated on **every** query, cache hit or not, so
the cache can never bypass a policy change. This page is the rulebook; every
rule names the test that pins it.

## Admission

| Rule | Behaviour | Test |
|---|---|---|
| Entry bound | `SAFE_ZONE_DNS_CACHE_ENTRIES` (default 4096, max 65536). `0` disables the cache entirely: a nil cache is valid, every operation is a no-op and `/v1/status` reports `enabled=false`. | `TestResponseCacheDisabledAtZeroEntries` |
| One question | Queries with more than one question are not cacheable. | `TestResponseCacheRejectsUncacheableInput` |
| EDNS discipline | A query may carry at most one OPT with version 0 and **padding only**; cookies, client-subnet, NSID and any other client-specific option bypass the cache. Responses carrying any EDNS option are never stored. | `TestResponseCacheRejectsUncacheableInput` |
| TSIG / signed | TSIG-signed queries and responses are never cached. | `FuzzResponseCache` (key construction) + code path `responseCacheKeyFor` |
| Failure states | SERVFAIL/REFUSED and friends are never cached — an outage must not outlive its cause. | `TestResponseCacheRejectsUncacheableInput` |
| Truncated / oversized | Truncated replies and messages above 8192 bytes are never cached (bounds memory; DNSSEC/ANY outliers excluded). | `TestResponseCacheRejectsUncacheableInput` |
| Zero freshness | A response whose smallest TTL clamps to 0 (including NXDOMAIN with SOA MINIMUM 0) is not stored. | `TestResponseCacheZeroTTLNotStored` |

Key dimensions: name (lower-cased), qtype, qclass, DO/CD/AD/RD bits, and
whether EDNS was present. A 0x20 case-variant is the same key but the caller's
spelling is restored on the reply.

## Lifetime

| Rule | Behaviour | Test |
|---|---|---|
| TTL cap | Every record is clamped to 300s (`DNSCacheMaxTTLSeconds`) no matter what the upstream said; the whole entry lives for the smallest record TTL after clamping. | `TestResponseCacheCapsLongTTL` |
| Negative answers | RFC 2308: NXDOMAIN/NODATA entries also honour the SOA MINIMUM as an upper bound on their lifetime. | `TestResponseCacheNegativeAnswerUsesSOAMinimum` |
| Aging | On a hit, every record TTL is reduced by the entry's age; the OPT/TSIG pseudo-records are exempt. | `TestResponseCacheHitRestoresIDAndAgesTTL` |
| Eviction | Strict LRU at the entry bound; each cacheable message is capped at 8 KiB so the entry count bounds memory. | `TestResponseCacheEvictsLeastRecentlyUsed` |

## Serve-stale and refresh-ahead

| Rule | Behaviour | Test |
|---|---|---|
| Serve-stale window | When the upstream is unreachable, an entry up to 1 hour past its TTL (`DNSCacheStaleWindow`) is served with record TTLs clamped to 30s (`DNSCacheStaleTTL`) so clients re-ask soon; the entry is retained and replaced by the next successful upstream answer. | `TestResponseCacheGetStale` |
| Refresh-ahead | An entry with ≥3 hits (`refreshAheadMinHits`) and more than half its TTL consumed is eligible for a single-flight background refresh (`BeginRefresh`/`EndRefresh` claim the slot); one-off queries refresh lazily as before. | `TestResponseCacheShouldRefreshSingleFlight` |
| Window bound | Entries past TTL + 1h are gone, not served — very old data must not mask a long outage as success. | `TestResponseCacheGetStale` |

## CNAME uncloaking

CNAME chains are followed by the resolver pipeline (not the cache) and every
target is policy-checked up to a hard cap
(`TestResolveQueryUncloaksBlockedCNAMETargetWithinCap`,
`TestResolveQueryCNAMEFloodFailsClosed`,
`TestResolveQueryCNAMEAtCapEvaluates`). Cached answers still re-run uncloaking
on every hit.

## Concurrency and fuzzing

The cache is mutex-guarded; `-race` covers it in the shared Go gates and
`TestResponseCacheConcurrentAccess` exercises it directly. Fuzz coverage lives
in `internal/dns/resolver/cache_fuzz_test.go` (`FuzzResponseCache`) and
`upstream_fuzz_test.go` (`FuzzUpstreamResponse`): arbitrary query/response
wire messages, extreme TTLs, bounded occupancy and a concurrent round on every
input.

## Benchmarks

```sh
go test ./internal/dns/resolver/ -run='^$' -bench 'BenchmarkResponseCache' -benchmem
```

`BenchmarkResponseCacheHit`, `BenchmarkResponseCacheMiss` and
`BenchmarkResponseCachePutEviction` pin the hot-path costs (hit = copy + TTL
aging, miss = key construction, put at capacity = eviction). Compare with
`-count=5` when touching the cache.

## Related

- Cross-process invalidation (why the cache needs none): see
  [cache-invalidation.md](cache-invalidation.md).
