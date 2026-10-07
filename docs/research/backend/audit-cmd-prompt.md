# Audit prompt: the `cmd/` binaries

## Context

You are auditing the command-line binaries in **Safe Zone**, a Go DNS-filtering /
threat-intel service. The Go module is `safe-zone`. There is an HTTP/UI service
(`core-api`), a DoH resolver (`dns-resolver`), and a set of operator tools under `cmd/`.

Threat-feed membership lives **only** in Redis. Losing it degrades to fail-open — a
miss allows — so a tool that mutates the feed badly weakens blocking quietly, while a
tool that fails loudly costs availability. Both directions matter.

Your job is an **independent audit**. Assume nothing about correctness.

## Scope — narrower than it looks, and that is deliberate

Two things are already audited and must not be re-audited:

- `internal/cache` — audited. Nothing found in that package itself.
- `internal/feed` — audited twice. Its writer, parser, admission and TTL contracts are
  covered, including two fixes derived from it (a documented "0 means unbounded" cap
  that silently ingested nothing, and an empty-ingest signal).

What you are auditing is the `cmd/` layer: the thin edges those tools use to reach the
outside world, and whether they honour the contracts the packages underneath already
have.

Two measurements I have already made, so you do not redo them — **but verify them, and
say so if they are wrong**:

- Only `feed-sync`, `feed-syncd` and `feed-shared-host-audit` construct a raw
  `redis.NewClient`. Everything else reaches Redis through `internal/cache`.
- Nothing under `cmd/` calls `FlushDB` or `FlushAll`.
- `core-api` and `dns-resolver` are the running services, not tools. Audit them only
  where `cmd/` framing applies (process startup, flag handling, wiring).

## Surfaces worth your attention

Form your own questions from the code; this is a starting map, not a list of answers.

- **The raw Redis edges.** `cmd/feed-sync/main.go` and
  `cmd/feed-shared-host-audit/main.go` build clients directly instead of going through
  `internal/cache`. For each call, ask what the package underneath would have done that
  this bypasses — the `Enabled()` check, the shared timeout, `ErrDisabled` semantics, the
  `ProtectsNonExpiringKeys` guard. A read-only edge is a smaller question than a writing
  one; find out which these are rather than assuming.
- **`warnIfFeedOversized`** in `cmd/feed-sync`. It counts members and then does
  something with the count. Establish exactly what, whether it can page anyone, and
  whether a threshold behaves sanely at the extremes.
- **Whether any tool can mutate production state.** Most take `-redis-addr`, defaulting
  from `SAFE_ZONE_REDIS_ADDR`. For each tool that writes — filesystem or Redis — ask
  whether there is a guard against pointing it at production, and whether the atomic
  staging-then-rename pattern used for on-disk artefacts is applied consistently. That
  pattern is the good precedent; look for places that write in place instead.
- **`feed-sync` versus `feed-syncd` parity.** They are the one-shot and the daemon form
  of the same job. There are tests pinning parity on TTL, admission mode, replace and
  insecure-source defaults. Check whether the parity actually holds for every flag that
  matters, or only the ones already asserted. Drift here is invisible until production
  and the daemon disagree.
- **Flag and configuration handling.** Anything that turns a typo into a destructive
  action. A duration, a TTL or an admission mode parsed from a string and then used in a
  comparison is worth reading twice.
- **The build and deploy surface.** The Dockerfile takes `ARG SERVICE` and builds
  `./cmd/${SERVICE}`. Establish which binaries can end up in an image, and whether any
  operator tool ships where it should not — a tool that can mutate the feed or the model
  bundle has no business being one keystroke from the serving path.

## Production reality worth knowing

- The hourly threat-feed sync is driven by a **host-only crontab script that is not in
  this repository**, running a **pinned binary** in throwaway containers. So the repo and
  what production executes can differ. Note where that matters; do not treat the drift
  itself as a finding about `cmd/`.
- That script runs one source per invocation across four sources, in **additive** mode.
  The staging-and-`Rename` path is therefore not live in production today.
- `SAFE_ZONE_OSINT_ENABLED=false` in production, so the OSINT audit task is off.

## Methodology — this matters

Mistakes I made on this codebase, so the next audit does not repeat them:

1. **Verify the premise before building on it.** I claimed `cmd/feed-sync` writes the feed
   through raw go-redis; it only issued a `ZCard`. A wrong premise sent a whole audit in
   the wrong direction.
2. **Check whether your own tooling is lying to you.** A regex I used counted writes
   across `*_test.go` as well, and I nearly reported a non-existent finding from it.
3. **Confirm a data format before parsing it.** I read a hosts file as bare domains and
   concluded a rule set had emptied.
4. **Do not compare aggregates across different windows.** Pair on the same key or find a
   mechanism.
5. **Counts can be capped.** `golangci-lint` defaults to `max-same-issues: 3`, so a
   default report saying "60 issues" may be 104. It also prints "0 issues" beside a
   typecheck error — read the exit status and stderr.
6. **Falsify, do not assume.** A passing test proves nothing until you break the code and
   watch it fail.
7. **Separate "measured", "inferred", "unknown".** Do not name a mechanism you did not
   observe.
8. **A red test is not automatically your regression.** This repo's suite is
   load-sensitive under concurrent package execution.

## Deliverable

Findings ordered by severity. For each:

- **Claim** — one sentence.
- **Where** — `file:line`.
- **Mechanism** — the specific path by which it goes wrong, naming the function and the
  branch. The most important field.
- **Evidence** — the command and its output. If the evidence is "I read this and it looks
  wrong", say that rather than implying you ran something.
- **Reachability** — who can actually run this, how, and what it touches. If a tool cannot
  reach production, say so; that is the difference between a real risk and a theoretical
  one.
- **Confidence** — measured, inferred, or unknown.

Then list what you checked and found clean, so coverage is visible.

Finish with:

- **Coverage** — which binaries, functions and call sites you read, and which you did not.
- **Recommendation** — whether anything is worth a PR, and whether it is worth doing now.

## Rules

- Read-only. Do not edit, commit, push, or open a PR.
- Report **"no findings"** plainly if that is the answer. An empty, honest report is more
  useful than a padded one.
- Do not propose changes outside `cmd/` except to note a package you had to read. If you
  find a defect in `internal/feed` or `internal/cache`, report it as an observation about
  the boundary rather than as a finding in that package.
- If something here is already well defended, say so and say what defends it.