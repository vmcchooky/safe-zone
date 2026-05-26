# ADR 0001: Fail-open runtime behavior

Date: 2026-05-21

## Status

Accepted

## Decision

Safe Zone keeps deterministic analysis available when optional dependencies degrade. Redis cache loss, AI provider loss, or TLS/WHOIS enrichment failure must not turn into a blanket outage for the analyzer or resolver.

## Rationale

The system is intended for a single-VPS baseline with optional integrations. Treating every helper dependency as hard-required would let partial outages become full service failures or mass false positives.

## Consequences

- Cache misses fall back to direct analysis.
- AI refinement is optional and never the only decision path.
- TLS/WHOIS enrichment may be skipped without aborting the request.
- Operators must monitor reduced detection quality separately from total service uptime.
