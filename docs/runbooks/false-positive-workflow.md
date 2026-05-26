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

1. Open the admin dashboard at `/dashboard`.
2. Analyze the reported domain in the `Analysis` tab.
3. Confirm whether the current result is:
   - an `admin override: block`
   - a threat-feed match
   - a lexical / enrichment / OSINT classification
4. Check `Telemetry` to see whether the domain is isolated or part of a larger pattern.

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

1. Stay on the `Analysis` tab after analyzing the domain.
2. In `False-positive review`, enter a review note that explains why the domain is legitimate.
3. Click `Allow / whitelist domain`.

API fallback:

```bash
curl -X POST http://localhost:8080/v1/overrides/review-false-positive \
  -H "Authorization: Bearer $SAFE_ZONE_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "reason": "verified partner portal during operator review",
    "source": "runbook",
    "previous_action": "block"
  }'
```

Expected result:

- Safe Zone writes a global `allow` override for the domain.
- The review reason is stored in the override record.
- An audit event `operator_false_positive_review` is recorded when SQLite is enabled.

## Step 4: Verify remediation

1. Re-run analysis for the same domain.
2. Confirm the response now shows `admin override: allow`.
3. Check the `Overrides` tab and verify the domain appears with action `allow`.
4. If client-specific policies exist, validate from an affected client path as well.

## Step 5: Decide on follow-up cleanup

Use the table below:

| Finding | Follow-up |
| --- | --- |
| Single mistaken domain, no broader pattern | Keep the allow override and close the ticket. |
| Threat feed source caused the block | Review feed source health, stale-feed status, and source trust before next sync. |
| Lexical / brand / enrichment logic caused the block | Open an engineering issue with the analyzed domain, reasons, and expected verdict. |
| Group override or client policy caused the block | Fix the affected group override or mapping and record the change. |

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
