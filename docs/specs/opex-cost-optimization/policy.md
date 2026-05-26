# Policy: OPEX Cost Governance

## Purpose

Define the rules that keep Safe Zone cache-first, free-tier-first, and budget-bounded while the project grows.

## External API Policy

- Prefer local data, Redis cache, and self-hosted feeds before any external call.
- Treat external API usage as a fallback, not a default path.
- If an external API is required, document the free tier, the quota, and the monthly cost delta before implementation.
- Any external API integration must have a cache strategy and an explicit timeout.
- If a cheaper free-tier or self-hosted alternative exists, it must be evaluated first.

## Backup Policy

- Keep backups bounded and predictable.
- Prefer local RDB snapshots and low-cost object storage only when the backup set outgrows local retention.
- Do not introduce paid backup infrastructure by default.
- Backup retention must be documented alongside the storage budget.

## Log Retention Policy

- Log growth must be capped by retention, not left open-ended.
- Use a short default retention window suitable for a single VPS baseline.
- If logs need to be exported off-box, use the lowest-cost free-tier option first.

## Storage Growth Policy

- Storage growth must stay within the budget ceiling described in the OPEX estimate.
- Any feature that materially increases storage must state the expected monthly growth.
- Features that require multi-GB growth by default need explicit approval and justification.

## Review Use

- Use this policy with [.github/pull_request_template.md](../../../.github/pull_request_template.md) and [review.md](review.md) before approving any change that touches cost-sensitive behavior.
- If a change violates this policy, it should be revised before implementation.