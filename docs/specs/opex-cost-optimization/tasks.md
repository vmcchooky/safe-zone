# Tasks: OPEX-First Cost Optimization

## Milestone 1: Budget Baseline

- [x] Lock the default deployment target to a single budget VPS.
- [x] Document the default budget ceiling and the preferred Hetzner-equivalent node.
- [x] List the deployment tiers that are allowed only by explicit exception.

## Milestone 2: Cost-Controlled Runtime

- [x] Verify that optional services remain optional in docs and defaults.
- [x] Keep Redis and feed sync local-first and dependency-free by default.
- [x] Ensure metrics and health checks stay low-cost and self-hosted.

## Milestone 3: Cost Governance

- [x] Define a cache-first policy for external API usage.
- [x] Document backup, log retention, and storage growth limits.
- [x] Add a simple OPEX review checklist for feature proposals.

## Milestone 4: Review Gate

- [x] Require every new feature proposal to state its monthly cost impact.
- [x] Require a free-tier or self-hosted fallback for any new dependency.
- [x] Keep README, OPEX estimate, and spec docs in sync.

## Completion Rule

No feature should move forward unless its OPEX impact is documented and accepted against the target budget profile.