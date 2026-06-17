# Requirements: Adblock Sync Hardening

## Goal

Strengthen the adblock subsystem so wildcard-heavy host lists are normalized safely, remote sync avoids unnecessary full downloads, and cached data can rebuild the trie source-by-source without silently dropping rules.

## Problem Summary

Current behavior has two practical gaps:

- Wildcard forms such as `*.ads.example.com` are not normalized explicitly before insertion.
- Remote sync currently uses a metadata pre-check but still re-downloads unchanged sources when at least one source changes, because cache reuse is only available as one combined file.

## Functional Requirements

- Trie insertion must strip any leading `*.` prefixes before suffix matching.
- Trie insertion must reject any remaining `*` characters after leading wildcard stripping.
- Adblock sync must keep per-source cache artifacts for remote sources, not only a combined cache.
- Remote HTTP/HTTPS adblock sync must use conditional GET with `If-None-Match` and `If-Modified-Since` when metadata exists.
- If a remote source returns `304 Not Modified`, the sync flow must rebuild that source from its cached copy instead of forcing a full network download.
- If a remote source returns a fresh `2xx` body, the sync flow must parse it into the trie and atomically refresh that source cache and metadata only after successful parsing.
- If a remote source fails during sync but a usable cached copy exists for that source, the sync flow may reuse the cached copy to avoid losing previously known rules.
- The existing combined cache fallback may remain for cold-start recovery, but it must not be the only reuse path for unchanged sources.
- Adblock sync must continue to fail open: when no fresh or cached data is available for a source, the service must prefer retaining the last good trie over clearing rules.

## Non-Functional Requirements

- Cache writes must be atomic (`tmp` + rename) to avoid partial file corruption.
- The implementation must remain compatible with large host files and gzip-compressed sources.
- The sync path must not increase steady-state bandwidth for unchanged remote sources.
- The trie structure does not need to change from sorted slices to maps unless profiling later proves a real bottleneck.

## Acceptance Criteria

- `*.ads.example.com` blocks `foo.ads.example.com`.
- Entries containing interior wildcards such as `bad*example.com` are ignored.
- When one adblock source changes and another returns `304`, the unchanged source is rebuilt from cache without a second full network fetch.
- When a remote source is unavailable but its source cache exists, cached rules can still contribute to the rebuilt trie.
- Existing cache-only cold-start recovery still works when network sync is unavailable.
- `go test ./internal/domaintrie ./internal/risk` passes.
