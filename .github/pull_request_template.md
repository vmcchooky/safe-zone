## Summary

Describe the change in 2-4 sentences.

## OPEX Impact

- Monthly cost delta: 
- Cost bucket affected: 
- Default deployment tier after this change: 
- Free-tier or self-hosted alternative considered: 
- If this change increases cost, why is it justified: 

## Scope Check

- [ ] The change preserves the single-VPS baseline.
- [ ] The change does not introduce a paid default dependency.
- [ ] The monthly cost impact is quantified or bounded.
- [ ] A free-tier or self-hosted alternative was considered.
- [ ] The feature remains optional by default unless explicitly justified.

## Review Notes

- Relevant docs/specs:
- Risks or tradeoffs:
- Follow-up work, if any:

## Verification

- [ ] `go test ./...` passes.
- [ ] `go build ./...` passes.
- [ ] Any new behavior has a focused test.

## Reviewer Checklist

- [ ] This PR is aligned with [Safe_Zone_OPEX_Estimate.md](../docs/Safe_Zone_OPEX_Estimate.md).
- [ ] The change stays within the approved budget profile.
- [ ] The PR does not expand monthly OPEX without explicit approval.