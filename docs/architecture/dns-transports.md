# DNS transports: DoH and DoT protocol surface

Both encrypted-DNS transports share one policy pipeline (`Resolver.ResolveQuery`);
this page records the protocol-level guarantees each listener makes and where
they are tested. The response-cache semantics live in
[dns-cache.md](dns-cache.md).

## DoH (RFC 8484) — plaintext HTTP on :8081

| Guarantee | Detail | Test |
|---|---|---|
| Methods | GET with the `dns` query parameter and POST with `application/dns-message` only; everything else answers 405 with `Allow: GET, POST`. | `TestHandlerProtocolErrors`, `TestDoHServer` fuzz |
| Content type | The POST media type must parse to `application/dns-message`; parameters such as `charset` are accepted (RFC 8484 §4.2), any other type answers 415. | `TestHandlerProtocolErrors`, `TestHandlerPOSTAcceptsContentTypeParameters` |
| Size bounds | Request bodies above 65535 bytes answer 413 (`MaxDNSMessageSize`, RFC 8484 §6); empty bodies 400. | `TestHandlerProtocolErrors` |
| Malformed input | Undecodable base64url (including padded forms), DNS messages that fail `Unpack`, and messages without a question all answer 400. | `TestHandlerPaddedBase64Rejected`, `TestHandlerProtocolErrors` |
| Backend failure | A pipeline error becomes a SERVFAIL DNS message inside HTTP 200 with zero freshness (RFC 8484 §4.2.1). | `TestHandlerBackendErrorBecomesSERVFAILInsideHTTP200`, `TestServfailFreshnessIsZero` |
| Freshness | 200 replies carry `Cache-Control: max-age` derived from the smallest answer TTL (SOA minimum for negative answers), always `private` because decisions are per-client. | `TestHandlerPOSTReturnsAnswerWithCacheControl`, `TestCacheFreshnessLifetimeUnitCases` |
| Client identity | The optional `client_id` from the query string or the `/dns-query/{client_id}` path reaches the policy engine; the socket IP is proxy-aware via the rate limiter's header rules. | `TestHandlerExtractsClientIDFromPathAndQuery` |
| Timeouts | The listener runs with `ReadHeaderTimeout: 5s`, `ReadTimeout`/`WriteTimeout: 10s`, `IdleTimeout: 60s` (`cmd/dns-resolver/main.go`), so a stalled peer cannot hold the listener. | wiring (values asserted by the compose-smoke runtime gate) |
| HTTP/2 | The plaintext listener speaks HTTP/1.1; HTTP/2 is terminated by Caddy at the public edge, which forwards to this listener — the DoH handler is method- and body-driven and h2-transparent. | by architecture; exercised end to end by the compose smoke through the published port |

Fuzzing: `FuzzDoHServer` (`internal/dns/doh/server_fuzz_test.go`) drives the
endpoint with arbitrary method/path/content-type/body combinations and pins
the closed set of status codes plus "every 200 body is a parseable DNS
message".

## DoT (RFC 7858) — TLS on :8533 (published 853 in production overlay)

| Guarantee | Detail | Test |
|---|---|---|
| TLS floor | The listener is built with `MinVersion: tls.VersionTLS12`; TLS 1.0/1.1 handshakes are refused on the wire while TLS 1.2/1.3 clients exchange queries. | `TestDotServerEnforcesTLSFloor` |
| Certificates | Production requires a trusted, non-expired pair; local mode may use the generated self-signed pair. | `cmd/dns-resolver/dot_cert_test.go` |
| Framing | The two-byte length-prefix framing is owned by the DNS library; garbage prefixes, empty messages and binary noise close the stream without killing the server, which keeps answering. | `TestDotServerSurvivesMalformedFraming` |
| Handler limits | No question → FORMERR; limiter exhaustion → REFUSED (its own tier, `SAFE_ZONE_RATELIMIT_DOT_*`); pipeline errors → SERVFAIL; a panic in the pipeline is recovered into SERVFAIL. | `pipeline_test.go` (`TestDoTHandler*`) |
| Timeouts | `ReadTimeout`/`WriteTimeout: 5s` bound a stalled or slow-handshake peer per exchange. | wiring (values asserted by the compose-smoke runtime gate) |
| ALPN | Deliberately not configured: RFC 7858 defines no ALPN identifier for DoT and requiring one would break clients that offer none; the TLS floor above is the compatibility contract. | by design (documented here) |

Both transports funnel into `ResolveQuery`, so the policy, whitelist, adblock
and uncloaking guarantees in [dns-cache.md](dns-cache.md) apply identically
to DoH and DoT traffic.
