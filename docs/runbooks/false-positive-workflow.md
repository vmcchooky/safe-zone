# False-positive review workflow

Use this runbook when an end user, support staff, or monitoring alert indicates that Safe Zone blocked a legitimate domain by mistake.

## Goal

Restore legitimate access quickly without losing operator traceability.

## Triggers

- A user reports that a domain is blocked but should be reachable.
- The block page form at `/block/report` creates a `false_positive_report` event.
- Internal testing finds a legitimate domain classified as `MALICIOUS`.

## Inputs to collect

- Reported domain
- Requested path or product context, if known
- Reporter contact or ticket ID
- Time of impact
- Screenshot or block-page text, if available

## Step 1: Confirm the current behavior

1. Open the primary admin dashboard at `/app/`. Use `/dashboard` only when validating the legacy compatibility UI.
2. Open `Reports` and select the pending report. This queue is admin-only because it can contain reporter contact details and notes.
3. Analyze the reported domain in the `Analysis` tab.
4. Confirm whether the current result is:
   - an `admin override: block`
   - a threat-feed match
   - a lexical / enrichment / OSINT classification
5. Check `Telemetry` to see whether the domain is isolated or part of a larger pattern.

## Step 2: Decide whether this is a local false positive or a broader incident

Treat it as a local false positive when:

- the domain owner is known or verified,
- the domain is needed for business access,
- and the evidence suggests a legitimate service.

Escalate to incident review when:

- many unrelated users are impacted,
- the domain belongs to a major provider and is blocked for multiple subdomains,
- a feed source appears poisoned or stale,
- or a recent config, brand, or group-policy change may have widened blast radius.

## Step 3: Apply the operator override

Preferred path in the dashboard:

1. Return to `Reports` and click `Allow` on the matching report.
2. Enter a review note that explains the evidence, ticket and expected lifetime of the override.
3. Confirm the decision. Safe Zone records the authenticated reviewer and server time automatically.

If the report is valid but does not require an allow override, use `Resolve`. If the evidence confirms that the block was correct, use `Reject`. Both decisions require a reason and remain visible in the queue history.

API fallback:

```bash
curl -X POST http://localhost:8080/v1/overrides/review-false-positive \
  -H "Authorization: Bearer $SAFE_ZONE_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "report_id": 42,
    "domain": "example.com",
    "reason": "verified partner portal during operator review",
    "source": "runbook",
    "previous_action": "block"
  }'
```

Expected result:

- Safe Zone writes a global `allow` override for the domain.
- The allow override, report resolution and `operator_false_positive_review` event commit in one SQLite transaction.
- Every pending report for the same normalized domain is resolved with `resolution_action=allow`.
- The queue stores `review_reason`, `reviewed_by` and `reviewed_at` for staging evidence.

`report_id` is optional for compatibility with reviews started from Analysis or the legacy dashboard. Queue-originated reviews should always send it so Safe Zone can reject a mismatched report/domain pair before changing the override.

## Step 4: Verify remediation

1. Re-run analysis for the same domain.
2. Confirm the response now shows `admin override: allow`.
3. Check the `Overrides` tab and verify the domain appears with action `allow`.
4. Return to `Reports`, filter by `Resolved`, and verify the reason, reviewer, review time and queue counter.
5. Query `agent_audit_log` or the agent audit view and verify `operator_false_positive_review` exists for the normalized domain.
6. If client-specific policies exist, validate from an affected client path as well.

## Step 5: Decide on follow-up cleanup

Use the table below:

| Finding | Follow-up |
| --- | --- |
| Single mistaken domain, no broader pattern | Keep the allow override and close the ticket. |
| Threat feed source caused the block | Review feed source health, stale-feed status, and source trust before next sync. |
| Lexical / brand / enrichment logic caused the block | Open an engineering issue with the analyzed domain, reasons, and expected verdict. |
| Group override or client policy caused the block | Fix the affected group override or mapping and record the change. |

## Step 6: Export targeted benign ML candidates

After one or more reports have been confirmed with the `Allow` action, export a
private supplemental replay set. The command reads the queue through the admin
API, pins the current analysis config and trusted-brand snapshot, and only keeps
domains whose counterfactual lexical verdict is `SUSPICIOUS`. It never exports
report contact, note, or review reason.

```powershell
go run ./cmd/ml-fp-candidates `
  --api-url http://127.0.0.1:8080 `
  --admin-api-key-file <private-admin-key-file> `
  --bundle <immutable-bundle> `
  --source-commit <exact-40-character-git-sha> `
  --min-candidates 25 `
  --output <new-private-run-directory>
```

The output directory must not exist. A ready run contains `manifest.json` and
`labels.csv`; feed the CSV into `cmd/ml-replay`. If the queue is empty, the tool
writes only a manifest with `status=empty_queue` and exits non-zero (`2` for the
compiled binary; `go run` may surface it as wrapper code `1`). Do not seed the
operator queue with synthetic reports and do not copy previously signed review
rows into it merely to satisfy the minimum.

Only new queue decisions are considered. The 78 reviewed-unclassifiable cases
in the archived packet do not need another review unless new evidence changes
their outcome.

## Required operator note format

Every false-positive override should capture:

- what was verified,
- who reviewed it,
- and whether the override is temporary or should remain until code/feed changes land.

Example:

`Verified legitimate payroll portal for internal vendor. Reviewed by ops on ticket INC-142. Keep allow override until feed source review is complete.`

## Accepted MVP limitations

- The allow decision is implemented as a global `allow` override, not a separate approval workflow.
- Review notes are stored as free text; there is no mandatory ticket-schema enforcement yet.
- There is no second-person approval gate in the current single-admin MVP.
