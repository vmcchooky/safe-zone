## What this release changes

<!-- One or two sentences. An operator reading only this should know whether
     anything they must do changed. If the answer is "nothing", say that. -->

## Operator action required

<!-- Anything needing a manual step before or during deploy: env var changes,
     renames, migrations, secrets to rotate, defaults that now differ from
     before. Write "None." rather than deleting the section when there is
     nothing. Migration and default changes are the items operators miss. -->

## Evidence

- Commit: `<sha>`
- Gates: Go gates, UI e2e (shards 1-3), ML gates, 4x Docker build, dependency
  audit, secret scan — all green on that SHA.

## Waivers

<!-- Items from docs/runbooks/pre-release-checklist.md that could not run in
     this environment. All four parts are required: what, why, where it will be
     verified, who owns it. Delete this section only when nothing was waived —
     and if something always is, that is worth noticing. -->

- **<checklist item>** — <why it could not run>. Will be verified on <where>.
  Owner: <who>.

## Not in this release

<!-- Changes that landed but are out of scope for this tag, or work deferred
     to a later round. Prevents the notes from implying coverage they do not
     have. -->