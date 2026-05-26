# Requirements: Local Threat Feed

## Goal

Add a local, zero-cost threat feed path so Safe Zone can block known bad domains from a configurable file or URL before relying on lexical heuristics.

## Functional Requirements

- Feed data must be loaded into Redis Set `safe-zone:threat:feed`.
- Feed sync must support a local file path or HTTP/HTTPS URL configured by CLI flag or env.
- Feed sync must parse simple TXT and CSV inputs.
- Feed sync must normalize domains using the same domain normalization rules as analysis.
- Feed sync must ignore blank lines, comment lines, invalid domains, and duplicate domains.
- Feed sync must support dry-run mode that parses and reports counts without writing Redis.
- Risk analysis must check exact feed match first.
- Risk analysis must check suffix match for subdomains, for example `login.bad.test` matches feed entry `bad.test`.
- If a feed match exists, result must be:
  - `verdict`: `MALICIOUS`
  - `score`: `100`
  - `confidence`: `1`
  - `reasons` includes `matched local threat feed`
- Redis/feed failures must be fail-open. If Redis is disabled or unavailable, analysis must continue with existing lexical rules.
- Existing cache behavior must remain intact: final analysis results are still cached by normalized domain.

## Non-Functional Requirements

- Do not introduce paid threat-intelligence dependencies.
- Do not require Redis for local development; Redis disabled must still work.
- Keep feed sync runnable manually before adding cron/container scheduling.
- Keep CSV parsing conservative and deterministic.

## Acceptance Criteria

- `cmd/feed-sync` can dry-run a local feed file and report valid/invalid/duplicate counts.
- `cmd/feed-sync` can write valid normalized domains into `safe-zone:threat:feed`.
- Exact feed match returns a malicious result with reason `matched local threat feed`.
- Subdomain suffix feed match returns a malicious result with reason `matched local threat feed`.
- Invalid domains still return `INVALID`.
- Redis disabled still returns lexical results without failing.
- `go test ./...` and `go build ./...` pass.
