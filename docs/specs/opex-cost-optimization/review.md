# Review: OPEX-First Cost Optimization

## Review Gate

Use this checklist before accepting any roadmap or implementation change:

1. Does the change preserve the single-VPS baseline?
2. Does the change avoid introducing a paid default dependency?
3. Is the monthly cost impact quantified or bounded?
4. Is there a free-tier or self-hosted alternative?
5. Can the change remain optional by default?

## Review Questions

- Which OPEX bucket does this change affect: compute, storage, monitoring, domain/DNS, or external intelligence?
- What is the cheapest acceptable implementation?
- What happens if the free-tier option disappears or changes limits?
- Can the feature be disabled without breaking the baseline path?
- Does the proposal require a new service, queue, or database that increases steady-state cost?

## Drift Prevention

- If a proposal cannot name its monthly cost delta, reject it.
- If a proposal needs a paid service by default, it is out of scope for the baseline.
- If a proposal cannot fit in the OPEX estimate, revise the estimate first.

## PR Template Rule

- Every change must open with the repository PR template at [.github/pull_request_template.md](../../../.github/pull_request_template.md) and fill in the OPEX Impact section before review.
- If the OPEX Impact section is incomplete, the change should not be reviewed.
- If the change increases cost, the PR must state the monthly delta and the reason the cheaper alternative was rejected.

## Suggested Next Artifact

- Add a short cost review checklist to the project PR template once this spec is in use.