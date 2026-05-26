# Review: Production Readiness

## Review Gate

Before merging any new production-readiness change, confirm:

1. The change maps to exactly one milestone or is explicitly split into multiple milestones.
2. The change does not introduce external paid dependencies.
3. The change preserves local-first behavior with Redis disabled.
4. The change has at least one focused test that fails before the change and passes after it.
5. The change does not expand the operational surface without a documented reason.

## Review Questions

- Does the change improve visibility, automation, hardening, or coverage?
- Is the new behavior available through a clear flag, env var, or endpoint?
- Can the change be validated with `go test ./...` or a narrow integration test?
- Does the change preserve existing API and DNS response shapes?
- Is the scope small enough that another engineer could implement the next slice without re-reading the whole repo?

## Drift Prevention

- If a proposal cannot be described in one paragraph, it is probably too broad.
- If a proposal needs a new service, new database, or new queue, it is out of scope for this spec.
- If a proposal cannot name its acceptance test, it should not be started.

## Suggested Next Spec Update

- If the project adds real deployment orchestration later, create a separate spec folder for orchestration and keep it out of this milestone set.