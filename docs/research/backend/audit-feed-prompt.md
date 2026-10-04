# Audit prompt: `internal/feed`

## Context

You are auditing `internal/feed` in **Safe Zone**, a Go DNS-filtering / threat-intel
service (`safe-zone`). It resolves domains for `core-api` (HTTP/UI) and `dns-resolver`
(DoH), backed by SQLite for telemetry and by **Redis for the threat feed**. The feed is
the store of record for malicious-domain membership and it exists nowhere else: losing
Redis degrades to fail-open (a miss allows), and a missed update silently weakens
blocking rather than breaking it loudly.

Your job is an **independent audit**. Assume nothing about correctness.

## How this actually runs in production

This is not the usual "check the library" framing. Read this before forming questions.

- **It is a batch job, not a request path.** An hourly user crontab runs a shell script
  that is **host-only and not in the repository**. The script runs a **pinned binary**
  (`bin/feed-sync`) in throwaway `alpine` containers on the compose network.
- **One source per invocation, four sources.** urlhaus, openphish, phishdestroy,
  Phishing.Database. The script has `set -u` but **not `set -e`**, and appends each
  source's output to one log.
- **Additive mode.** Production does not pass the replace flag, so the staging-key plus
  `Rename` path is **not live there**. There is a test asserting the daemon variant
  (`feed-syncd`) keeps default parity with `feed-sync` on this, so verify that claim too.
  Do not spend your effort on the Replace path beyond checking its correctness.
- **The pinned binary may not be the code in this repository.** The audit is of the repo;
  note anywhere the two could have drifted, but do not treat drift itself as a finding
  about this package.

## Unit of work

Production files: `sync.go` (the writer, largest), `parse.go`, `admission.go`, `status.go`,
`ttl.go`. Tests: `sync_test.go`, `parse_test.go`, `admission_test.go`,
`admission_shadow_test.go`, `psl_guard_test.go`, `ttl_test.go`, `parse_memory_test.go`.

Read the production files completely before writing anything.

Callers, read-only: `cmd/feed-sync`, `cmd/feed-syncd`, `internal/store` (revision key),
`internal/risk` (feed reads on the decision path), `internal/api/handlers` (status
surface).

## Surfaces worth your attention

Form your own questions from the code, but these are where I would start:

- **`OpenSourceWithin`** in `sync.go` — the egress path. `MaxBytes`, `AllowInsecureHTTP`,
  and how redirects are handled. A plain-HTTP source is refused unless explicitly
  allowed; check whether anything else gets past that, and whether the download cap is
  enforced before anything is buffered or parsed.
- **The additive path.** What does a member get that makes the set self-expiring — a
  per-member TTL as a score, or a key-level `Expire`? What happens to a member's score
  when it is re-added by a later sync, and does the set grow monotonically?
- **Partial failure across the four sources.** The status surface is aggregate. If one
  source has been failing for a week, what does `stale`, `status`, `revision` and
  `parser_drift` report? Trace exactly what bumps the revision and whether one source
  succeeding masks three failing. This is the question I most want answered.
- **`admission.go` and the three admission modes.** Legacy, filter, shadow. What is
  rejected, what is merely counted, and can a mode be selected that silently discards
  IOCs? Check whether the default is the safest one and whether anything validates the
  choice.
- **`parse.go`** — line-format tolerance, size caps, and what a malformed or hostile feed
  can make it do. There is a public-suffix guard here and on the write side; check both
  ends agree, and that neither can be bypassed by a differently formatted line.
- **`ttl.go`** — the per-member expiry policy. Anything that can produce a member with no
  expiry, a zero score, or a score that makes it permanently live.
- **`status.go`** — what the operator actually sees, and whether a genuinely broken feed
  would be reported as broken.

For every finding, check what the caller does with the value: a problem that only matters
if a caller ignores an error is not a finding until you have read that caller.

## Methodology — this matters

These are mistakes I made on this codebase; the prompt exists partly to stop them
repeating.

1. **Verify the data or the premise before you build on it.** I read a hosts file
   (`0.0.0.0 domain`) as bare domains and concluded a rule set had emptied. I also
   twice guessed where risk lived from a grep hit and was wrong both times. Check the
   shape of the thing before reasoning about it.
2. **Do not compare aggregates across different windows.** "30 days versus 5 hours" is not
   a comparison; a traffic-mix shift looks exactly like a behaviour change. Pair on the
   same key or find a mechanism.
3. **Counts can be capped.** `golangci-lint` defaults to `max-same-issues: 3`, so a report
   saying "60 issues" may be 104. It also prints "0 issues" next to a typecheck error.
   Lift the caps and read exit status and stderr.
4. **Falsify, do not assume.** A passing test proves nothing until you have broken the
   code and watched it fail. If you cannot state the input that makes your finding
   appear, it may not be real.
5. **Separate "measured", "inferred", "unknown".** If you cannot determine a cause, say
   so instead of naming a mechanism you did not observe.
6. **A red test is not automatically your regression.** Check whether the same failure
   occurs on an unmodified tree; this repo's suite is load-sensitive under concurrent
   package execution.

## Deliverable

A findings report ordered by severity. For each:

- **Claim** — one sentence.
- **Where** — `file:line`.
- **Mechanism** — the specific path by which it goes wrong, naming the function and the
  branch. The most important field; a claim without a mechanism is not useful.
- **Evidence** — the command and the output. If the evidence is "I read this and it looks
  wrong", say that rather than implying you ran something.
- **Reachability** — which caller reaches it, and what that caller does with the result.
  Say explicitly if you found no reachable path. Given the production notes above, state
  whether the finding is live in the current deployment or needs a non-default flag.
- **Confidence** — measured, inferred, or unknown.

Then list what you checked and found clean, so coverage is visible.

Finish with:

- **Coverage** — which functions and callers you actually read, and which you did not.
- **Recommendation** — whether anything is worth a PR, and whether it is worth doing now.

## Rules

- Read-only. Do not edit, commit, push, or open a PR.
- Report **"no findings"** plainly if that is the answer. An empty, honest report is more
  useful than a padded one, and I would rather have the former.
- Do not propose changes outside `internal/feed` except to note a caller you had to read.
  One exception: if you find that the hourly driver (the host-only cron script) has no
  liveness check of its own, say so as an observation about operations rather than a
  finding about this package.
- If something here is already well defended, say so and say what defends it. That stops
  the next audit redoing your work.
