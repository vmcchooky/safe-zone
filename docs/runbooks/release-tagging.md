# Release tagging

How a Safe Zone release gets its version, and what has to be true before a tag
exists. This covers only the part that runs on a developer machine. Everything
that needs a deployed host — staging, smoke tests, restore drill, performance
proof — lives in [release-gate.md](release-gate.md) and
[pre-release-checklist.md](pre-release-checklist.md).

## Version policy

The version is `v1.<MM>.<DD>`, where `MM` is the release month and `DD` the day
of month, both in UTC.

```
v1.10.16   released 2026-10-16
```

The first release of a month is `.01`. The date is the release date, not the
date the work started: a change merged on the 28th and released on the 2nd is
`v1.11.02`.

**The major version stays 1** until the operator contract breaks: environment
variable names, the Compose layout, or an API endpoint the dashboard depends on.
Adding a gate, refactoring internals or tightening a default is not breaking and
does not move the major.

**Same-day collisions.** Prefer shipping on the next free day. If a hotfix
genuinely cannot wait, use a `-2` suffix (`v1.10.16-2`) rather than moving the
date, so the tag still says when the work happened.

The version is a label, not a constraint. The Go module is unversioned
(`module safe-zone`), and Compose pins images by commit SHA, so a version bump
never has to wait for, or coordinate with, consumers.

## Before tagging

Every item here runs without a VPS.

- [ ] `main` is green: every required status check passed **on the commit being
      tagged**, not on some earlier commit.
- [ ] The working tree is clean and on `main`, in sync with `origin/main`.
- [ ] The version follows the policy above and the tag does not already exist
      (`git tag --list "v1.11.*"`).
- [ ] `CHANGELOG.md` has its `Unreleased` heading replaced with the released
      version and date, and the entries describe what actually shipped.
      Stamp it **before** tagging: the changelog edit is a PR, and tagging a
      commit that predates its own changelog leaves the two out of sync.
- [ ] Release notes are drafted from `.github/release-notes-template.md`,
      including the waiver section below.
- [ ] `git tag -a vX.Y.Z -m "<summary>"` is created on that exact commit and
      pushed.
- [ ] The GitHub release is created against the pushed tag.
- [ ] The tag, the commit SHA and any waivers are recorded in the release
      record.

## Waivers

This repository has been releasing without a provisioned environment. That is
allowed, but only in writing. A waiver is valid when it states all four:

1. **What** was skipped, by checklist item name.
2. **Why** it could not run.
3. **Where** it will be verified instead — the first provisioned environment is
   a legitimate answer.
4. **Who** owns carrying it out.

A waiver is a transfer of responsibility, not a dismissal. The v1.10.16 release
deferred staging deploy, DoH/DoT/block-page smokes, the restore drill and the
performance proof to the first provisioned environment on exactly these terms.

What a waiver must never cover: anything that can run locally or in CI. If a
check can run here, a waiver for it is not a waiver, it is an omission.

## After tagging

Promotion to production is a separate act with its own gate. A tag is not a
deploy. See [release-gate.md](release-gate.md) for the deploy path and
[release-rollback.md](release-rollback.md) if it goes wrong.