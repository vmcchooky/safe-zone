# ADR 0007: Dedicated DoH (RFC 8484) protocol module

Date: 2026-08-27

## Status

Accepted

## Context

The `dns-resolver` service answered DoH queries through `DoHHandler` living in the same `internal/dns/resolver` package as the policy engine, the DoT handler and the upstream DoH client. The DoH protocol logic (RFC 8484 wire mapping, HTTP status codes, caching headers) could not be read, tested or reused in isolation, and both transports duplicated the block/forward/uncloak pipeline. A compliance review against RFC 8484 also surfaced gaps: no `Cache-Control` freshness lifetime (section 5.1), wrong HTTP status codes for unsupported methods and media types (400 instead of 405/415), no 413 for oversized bodies, and no `Content-Type` validation on upstream responses.

## Decision

1. Extract a dedicated transport module `internal/dns/doh` with four concerns: `server.go` (the RFC 8484 HTTP endpoint), `client.go` (upstream DoH exchange), `upstream.go` (health-checked endpoint pool with failover and probing), and `cache.go` (HTTP freshness lifetime rules).
2. The DoH module is transport-only and exposes a narrow `QueryBackend` interface; the policy engine (block strategy, forwarding, CNAME uncloaking) stays in `internal/dns/resolver` and is implemented once as `Resolver.ResolveQuery`, shared by DoH and DoT. DoT keeps its transport-specific concerns (rate limiter, connection-level IP) in `internal/dns/resolver/dot.go`.
3. RFC 8484 compliance hardening on the server endpoint:
   - DNS-level failures (SERVFAIL) ride inside HTTP 200 DNS messages; only protocol violations use non-2xx status codes (section 4.2.1).
   - `405` with `Allow: GET, POST` for other methods, `415` for POST bodies not typed `application/dns-message`, `413` for bodies over 65535 bytes, `400` for malformed DNS messages or base64url (section 4.1, section 6).
   - Every 2xx response carries an explicit `Cache-Control: private, max-age=<n>` where `max-age` is capped by the smallest TTL in the Answer section, or by `min(SOA TTL, SOA MINIMUM)` for negative answers (section 5.1, RFC 2308). The `private` directive is required because block decisions are customized per client identity; it keeps shared caches such as Caddy from reusing one client's answer for another while still allowing browser-level reuse.
4. Upstream hardening on the client side: reject non-2xx, reject responses whose `Content-Type` is not `application/dns-message` (captive portal / proxy HTML pages), and reject bodies larger than the RFC 8484 65535-byte maximum.

## Rationale

Separating the protocol from the policy mirrors how RFC 7858 (DoT) support was introduced as an independent concern and makes future transports (e.g. DoQ, RFC 9250) a matter of writing one more thin adapter over `ResolveQuery`. The caching header work closes both a standards gap and a correctness gap: without `private`, an intermediary HTTP cache keyed on the GET URL could serve one client's allowed answer to a client whose policy blocks the same domain.

## Consequences

- `DoHHandler`, `readDNSMessage`, `writeDNSMessage`, `UpstreamResolver` and `DoDoH` no longer exist in `internal/dns/resolver`; imports move to `internal/dns/doh`.
- Response `Cache-Control` headers are observable in production; any intermediary added in front of the resolver must respect `private`.
- The legacy build-ignored `resolver_test.go` was revived against the current architecture (status/version/metrics/policy handlers, block strategies, DoT rate limiting, concurrency, panic recovery, IPv6 sanitization); live coverage sits in `internal/dns/resolver/resolver_test.go`, `internal/dns/resolver/pipeline_test.go`, `internal/dns/doh/server_test.go` and `internal/dns/doh/client_test.go`.
- No new environment variables or configuration are introduced; existing `SAFE_ZONE_UPSTREAM_DOH_URLS`, rate limiting and block strategy settings behave unchanged.
