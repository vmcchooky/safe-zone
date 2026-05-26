# ADR 0005: Optional AI provider strategy

Date: 2026-05-21

## Status

Accepted

## Decision

AI remains optional. Safe Zone supports `none`, `gemini`, `ollama`, and `hybrid`, with deterministic analysis always available underneath.

## Rationale

Production environments vary from low-RAM public VPS instances to offline-first local deployments. A single mandatory AI path would either raise cost or block installs that cannot run local models.

## Consequences

- `gemini` is the lightest cloud-assisted default for ambiguous domains.
- `ollama` remains available for offline/privacy-sensitive deployments.
- `hybrid` can blend local inference with cloud fallback.
- Operators must treat AI outages as degraded fidelity, not total outage.
