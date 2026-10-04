# Audit prompt: `internal/cache`

## Context

You are auditing `internal/cache` in **Safe Zone**, a Go DNS-filtering / threat-intel
service (`safe-zone`). It has two services (`core-api`, `dns-resolver`) plus a DoH
fronted by Caddy, a SQLite store (`internal/store`), and an in-memory adblock trie.

Redis (`internal/cache`) is the shared cache layer. It is used at ~20 call sites and
backs: the analysis verdict cache, the threat-feed membership set, the adblock
config-reload pub/sub, brand revisions, URL feedback, and various counters.

Your job is an **independent audit**. Assume nothing about correctness. An earlier
multi-round audit pass covered other packages; this one covers only this one.

## Unit of work

One production file: `internal/cache/redis.go`. Its tests are `redis_test.go`,
`cas_test.go`, `scan_delete_test.go`, `zscores_test.go`. Read the production file
completely before writing anything.

Call sites to survey for how the API is actually used (read-only, do not edit):
`grep -rn "cache\.New\|cache\.Redis" cmd internal --include=*.go | grep -v _test.go`

## Surfaces worth your attention

Start from the method list, but form your own questions from the code:

- `Enabled()`, `Close()`, `Ping()` — lifecycle, and what callers assume when disabled.
- `ProtectsNonExpiringKeys` / `RuntimeStats` / `parseRedisRuntimeStats` — a guard
  about non-expiring keys, and parsing of `INFO` output. Check what it is actually
  protecting and whether any caller can bypass it.
- `GetJSON`/`SetJSON`/`GetString`/`SetString` — hit/miss semantics, and the `ttl`
  argument: what happens at `0` and negative values. Trace what a zero TTL does to a
  key, and whether any caller can accidentally create an immortal key in a cache
  that is supposed to expire.
- `Subscribe` — returns a channel plus a cancel func. Check goroutine and connection
  lifecycle: what happens if the caller never calls cancel; what happens on
  reconnect; whether a slow consumer can block the publisher or leak.
- `Increment`, `GetInt64` — numeric parsing, overflow, and what a non-numeric value
  does.
- `ScanDelete`, `ZRemRangeByScore` — bounded deletion. Check the bound is actually
  enforced per call and per cycle, and what a partial completion leaves behind.
- `CompareAndSwapJSON` / `casOnce` — CAS correctness under concurrency, and the
  retry path.
- `Rename` — behaviour when the source key does not exist (does it clobber the
  destination?).
- `PushJSON` (`maxLen`) and `ListJSON` (its `appendItem func([]byte) error`
  callback) — bounded growth and the callback's error handling.

## What to look for

Correctness under concurrency and failure; resource leaks; unbounded growth or
unbounded memory; silent-failure modes where a Redis error degrades into a wrong
answer rather than an error; error handling that discards a real failure; TTL and
key-expiry semantics; and any place a caller can turn a cache into a source of
truth.

For every call site you touch, note what the caller does when the call returns an
error and when it returns a miss. A finding that only matters if a caller ignores
the error is not a finding until you have read that caller.

## Methodology — please read, this matters

I have already made these mistakes on this codebase, and they are the easiest way to
produce a wrong audit:

1. **Do not compare aggregates across different windows.** A before/after over
   "30 days versus 5 hours" is not a comparison, and a traffic-mix shift will look
   like a behaviour change. If you claim a behaviour changed, control for it — pair
   the data on the same key, or find a mechanism.
2. **Verify the data format before you parse it.** I read a hosts file
   (`0.0.0.0 domain`) as a list of bare domains, concluded 59/59 entries had
   vanished, and was wrong. Confirm the shape first.
3. **Counts can be capped.** `golangci-lint` defaults to
   `max-same-issues: 3`, so a report saying "60 issues" may really be 104. Lift the
   caps (`--max-issues-per-linter=0 --max-same-issues=0`) before quoting a number.
   Also, `golangci-lint` prints "0 issues" next to a typecheck error — check the
   exit status and stderr, not the summary line.
4. **Falsify, do not assume.** A passing test proves nothing until you have broken
   the code and watched it fail. If you cannot say what input would make your
   finding appear, it may not be real.
5. **Separate "measured", "inferred", and "unknown".** When you cannot determine a
   cause, say so. Do not name a specific mechanism you have not observed.
6. **A red test is not automatically your regression.** Before blaming your change,
   check whether the same failure occurs on an unmodified tree. Load-sensitive
   flakes in this repo only appear under concurrent package execution.

## Deliverable

A findings report, ordered by severity. For each finding:

- **Claim** — one sentence.
- **Where** — `file:line`.
- **Mechanism** — the specific path by which it goes wrong, naming the function and
  the branch. This is the most important part; a claim without a mechanism is not
  useful.
- **Evidence** — the command you ran and the output that shows it. If the evidence
  is "I read the code and it looks wrong", say that instead of implying you ran it.
- **Reachability** — which caller reaches this, and what that caller does with the
  result. Say explicitly if you could not find a reachable caller.
- **Confidence** — measured, inferred, or unknown.

Then list what you checked and found clean, so the coverage is visible.

Finish with:

- **Coverage** — which methods and call sites you actually read, and which you did
  not. Be explicit about the gaps.
- **Recommendation** — whether anything here is worth a PR, and whether it is worth
  doing now.

## Rules

- Read-only. Do not edit, commit, push, or open a PR.
- Report **"no findings"** plainly if that is the answer. An empty, honest report is
  more useful than a padded one, and I would rather have the former.
- Do not propose changes to other packages except to note a caller you had to read.
- If something in this package is already well defended, say so and say what defends
  it. That is a useful result and it stops the next audit re-doing your work.
