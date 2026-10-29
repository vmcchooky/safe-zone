# Policy and auth precedence

This is the canonical evaluation order for a Safe Zone decision, and the
authentication/authorization contract for the admin API. Every layer names
the test that pins it. Older documents
(`docs/specs/sqlite-telemetry-overrides/requirements.md`,
`docs/specs/tls-whois-analysis/design.md`) predate the adblock and identity
layers and show a shortened order — this page supersedes them.

## Decision order (one DNS query or one analyze call)

1. **Normalisation gate** — a domain that fails `NormalizeDomain` is refused
   by the lexical analyzer (reported INVALID) without touching any layer.
   (`internal/risk/policy.go:17`)
2. **Identity / client group** — the caller's group is resolved from the
   trusted client IP only: exact-IP mapping first, then CIDR (longest prefix
   per address family), then default. The DoH/API-supplied `client_id` is
   **unauthenticated and never selects a group** — `resolveClientGroup`
   hardcodes `clientIDTrusted=false`, and a failed lookup fails open to the
   default group, counted and logged. Store resolution order:
   `client_id` (trusted callers only) → exact IP → CIDR → default.
   (`internal/risk/analysis_pipeline.go:43`; `TestUntrustedClientIDCannotPickGroup`;
   `TestGetGroupForClient`, `TestGetGroupForClientPrefersMostSpecificCIDR`)
3. **Admin overrides** — a matching override (group override first, then
   global, per domain candidate walking specific → registrable floor)
   short-circuits everything below, including the whitelist.
   (`TestOverrideBlocksDomain`, `TestOverrideBeatsWhitelist`,
   `TestGetEffectiveOverride` "Group override preferred over global")
4. **Whitelist** — a whitelisted domain is reported SAFE and skips the
   threat feed, lexical scoring, ML, AI, OSINT and group enforcement.
   (`TestWhitelistPrecedenceLockedWithException`)
5. **Adblock** — on the DNS path a non-excepted adblock match short-circuits
   to a content-policy block with a lexical-local assessment (separated
   semantics); a scoped content exception suppresses exactly that match and
   falls through to the full pipeline below. On the API path, separated
   adblock evidence never short-circuits.
   (`TestSeparatedPolicyBlocksAdblockWithLexicalResult`,
   `TestExceptionSuppressesExactMatchAndRunsPipeline`)
6. **Threat feed** — a feed member is MALICIOUS with the feed reason before
   the lexical analyzer runs; lexical scoring only happens on a feed miss.
7. **Lexical heuristics** — brand/typosquat scoring, DGA, keywords, punycode
   on non-feed domains.
8. **ML / AI / OSINT** — only when enabled; they can raise or refine a
   verdict but never override an override, the whitelist, an adblock block
   or a feed decision (`docs/specs/safe-zone-ai-plan.md`).
9. **Group dynamic enforcement** — the group resolved in step 2 applies its
   category filters and group overrides to the verdict produced above.
   (`TestClientGroupPolicyDynamicEnforcement`)

The DNS response cache never interacts with this order: policy is
re-evaluated on every hit ([dns-cache.md](dns-cache.md)).

## Admin API authentication

| Rule | Contract | Test |
|---|---|---|
| Credential choice | A valid `Authorization: Bearer <admin key>` wins over a session cookie; the bearer path is exempt from CSRF. With an **invalid** bearer the enforcing middleware falls through to the cookie, while the annotating middleware (`/v1/analyze`) fails closed — deliberate divergence. | `TestBearerCredentialsTakePrecedenceOverSessionCookie`, `TestInvalidBearerFailsClosedOnAnnotatingPathOnly` |
| CSRF | Cookie-borne state changes require `Origin` (fallback `Referer`) to match the request Host, the configured PublicHost, or `SAFE_ZONE_PUBLIC_HOST`, compared on canonicalised hosts (default ports stripped, non-default ports significant). | `TestValidCSRFSources`, `TestLogoutRequiresCSRFForCookieSessions` |
| Roles | Read-only guests may call any auth-only endpoint; writes require the admin role (`RequireAdmin*`); guest sessions are revalidated per request. | `TestGuestAccessLifecycleAndPermissions` |
| Sessions | Admin sessions are persisted and revocable; an unavailable session store fails login closed. | `TestSessionStoreUnavailableFailsClosed` |
| Secure cookie | The session cookie is `Secure` on direct TLS, or when a **trusted proxy** sends `X-Forwarded-Proto: https`, or when `SAFE_ZONE_FORCE_SECURE_COOKIES` is set (production default). An untrusted peer's forwarded header can never set it. | `auth_cookie_test.go` |

## Rate-limit tiers

The core-api tier table (`cmd/core-api/ratelimit.go`) is first-prefix-match:
`/v1/auth/login` lands on the auth tier, `/v1/auth/session` on the dashboard
tier, `/app-background.avif` on the `/app` tier, and unlisted prefixes fall
through to the default limiter. The full table is pinned row by row in
`TestTierTableFirstMatchWins`; trusted-proxy handling (rightmost
non-trusted hop, all-trusted chains fail closed) is table-tested in
`internal/ratelimit/middleware_test.go` (`TestClientIP`).
