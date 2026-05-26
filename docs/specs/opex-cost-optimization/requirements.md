# Requirements: OPEX-First Cost Optimization

## Goal

Keep Safe Zone aligned to [Safe_Zone_OPEX_Estimate.md](../../Safe_Zone_OPEX_Estimate.md) as the governing roadmap, with the primary objective of minimizing monthly operating cost while preserving the current core anti-phishing behavior.

## Milestones

### Milestone 1: Budget Baseline

- The default deployment target must be a single budget VPS.
- The reference target is Hetzner CPX21 or an equivalent 2 vCPU / 4 GB RAM node.
- Any more expensive deployment tier must be explicitly justified against the OPEX estimate.

### Milestone 2: Cost-Controlled Runtime

- Default services must remain local-first and self-hosted.
- Redis, threat feed sync, metrics, and health checks must not require paid infrastructure.
- Optional components must stay optional by default.

### Milestone 3: Cost Governance

- External API usage must remain cache-first and free-tier-first.
- Any new external dependency must state its monthly cost impact and free-tier fallback.
- Backup, log retention, and storage growth must stay within the target budget.

### Milestone 4: Review Gate

- Every new feature must be reviewed against OPEX impact before implementation.
- No feature may introduce a paid dependency by default.
- The README and spec docs must stay aligned with the OPEX estimate.

## Functional Requirements

- The documented default stack must fit the target budget profile described in the OPEX estimate.
- Local development must remain usable with Redis disabled.
- Existing analysis and resolver behavior must remain compatible.
- Free-tier services and self-hosted components must be preferred over paid services.

## Non-Functional Requirements

- Do not introduce a database, queue, or paid managed service for the baseline path.
- Do not require a cloud AI service when a local or rule-based path is available.
- Keep the cost-control plan simple enough to understand without rereading the full SRS.

## Acceptance Criteria

- The OPEX estimate is the source of truth for deployment and budget decisions.
- The default stack has a clearly documented monthly cost target.
- New work cannot expand cost without a documented tradeoff.
- The project remains operable as a single-VPS deployment.