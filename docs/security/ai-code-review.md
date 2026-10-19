# AI-assisted code review process

Status: Proposed (needs owner approval) — Date: 2026-10-19

This is the review gate for AI-written code. It exists so item 4
(production runtime observability) is never again "AI wrote, AI merged".

## Evidence (verified 2026-10-19, do not trust prose)

- Branch protection on `main`:
  `required_approving_review_count: 0`, `enforce_admins: true`,
  `strict: true`, `dismiss_stale_reviews: false`.
  Verify: `gh api repos/vmcchooky/safe-zone/branches/main/protection`
- Rulesets: none (`gh api repos/vmcchooky/safe-zone/rulesets` returns `[]`).
- Last 10 merged PRs (#165-#186 window, e.g. #175-#180, #183-#186) are all
  `author=vmcchooky` and `mergedBy=vmcchooky`. Nothing forced a second reader.
  Verify: `gh pr list --state merged --limit 15 --json number,title,author,mergedBy`
- Root has no `CONTRIBUTING.md`, no `AGENTS.md`, no review doc.
  `.github/pull_request_template.md` only asks OPEX + `go test/build` — no
  security checklist.

## (a) Risk classification

High-risk = mandatory human diff read. CI green is NOT enough.

**Globs below are path hints, not shell globs**: `*` does not cross a directory
separator, so write `internal/api/handlers/*auth*` when you mean the handlers
package. Verify a hint matches what you think it matches (`git ls-files
'internal/api/auth*.go'`) — a glob that matches nothing is worse than no glob,
because it looks like coverage.

A PR is high-risk if it touches any of:

- auth / sessions / admin keys (`internal/auth/*` — `auth.go`, `bearer.go`;
  `internal/api/handlers/*auth*`; `*_FILE` secrets, login, API keys)
- store / policy state (`internal/store/*`, groups, mappings, overrides, whitelist, migrations)
- crypto / TLS / netguard (`internal/tlsinspect/*`, `internal/netguard/*`)
- deploy / edge (`Dockerfile`, `docker-compose*.yml`, `Caddyfile`, `deploy/*`, `ops/*`, `start.bat`)
- defaults / config (`internal/config/*`, `mise.toml`, `.github/workflows/*`, `go.mod`, `go.sum`, any `SAFE_ZONE_*` default)
- DNS hot path (`internal/risk/*`, `internal/ratelimit/*`, `internal/whois/*`, `internal/feed/*`, `internal/feedsync/*`, `internal/dns/*`)
- scoring and degradation paths (`internal/analysis/*`, `internal/cache/*`, `internal/ai/*`, `internal/osint/*`)
- dashboard surface (`ui/src/*`, `ui/tests/*`)

**When a path is not obviously in the low-risk list below, treat it as
high-risk.** The list is a floor, not a ceiling.

Everything else (docs-only, comments, pure test additions, CHANGELOG) is
low-risk: CI green is enough, self-merge still forbidden by (c).

## (b) 10-minute checklist (security-touching PRs only)

Answer in the PR body. Skip = not reviewed.

1. Where does untrusted input enter, and where does it exit?
   Trace `X-Forwarded-For` / `client_id` / domain / feed line from handler
   to store/cache/log. Unauthenticated `client_id` must never select policy
   (`internal/store/groups.go:491 GetGroupForClient`).
2. Which error path fails open silently?
   Fail-open is permitted by `ADR 0001`, but only in the loud form the runtime
   actually uses: "the policy is fail-open but loud — count it, log it, and
   publish it" (`internal/risk/admin.go:18-26`). ADR 0001 itself does not
   mandate the counter — it only says operators must monitor reduced detection
   quality separately from total uptime — so do not cite it as the rule. A
   fail-open path with no counter is not finished work.
3. Is the default safe when the env is NOT set?
   Known trap: `SAFE_ZONE_TRUSTED_PROXIES` when set overrides the whole
   Compose default (`docker-compose.yml`), collapsing Internet clients into
   one rate-limit bucket and killing exact-IP/CIDR mapping. Check
   `internal/ratelimit/middleware.go:198 configureTrustedProxies` — that is
   where a set value *replaces* the default rather than extending it, and
   `docker-compose.yml` is where the bridge-inclusive default lives. The
   supporting pieces are at `middleware.go:91,106,265,287`, but reading only
   those four misses the trap.
4. Does the test assert the BAD behavior, or only the happy path?
   A test that measures 1/200 operations it claims to measure stays green
   for months. For cascade fixes, temporarily revert one line below and
   prove the test goes red, then restore.
5. Purely additive, or accidental behavior change?
   `/v1/status` JSON may only gain keys (backward compatible). Counter must
   not change logic. If behavior must change, stop and report — do not
   sneak it in.

## (c) AI must not self-merge its own PR

Text rule (enforced now):

- An AI author — including this agent — must never merge its own PR,
  via `gh pr merge`, UI merge button, or auto-merge.
- Only the human owner (`vmcchooky`) merges, after checking (a)+(b).
- This holds even when all required checks are green.

Why not a GitHub ruleset now:

- This is a single-maintainer repo. Requiring 1 approving review with
  `required_approving_review_count: 1` would block every merge (no second
  human exists). The current protection is `count: 0` + `enforce_admins: true`.
- Rulesets are NOT in git — invisible, not reviewable, easy to drift.
  Current list is empty (verified above).
- Revisit when a second human reviewer exists. Track as:
  "re-enable approval requirement + no-self-merge actor rule".

If a ruleset is ever created for this, record here:

- List: `gh api repos/vmcchooky/safe-zone/rulesets`
- Delete/revert: `gh api --method DELETE repos/vmcchooky/safe-zone/rulesets/{id}`
- Branch protection is separate and stays `strict: true`. Patch only with
  the full required-contexts list, never a subset (renaming a job blocks
  merges). Current contexts include `Build metadata`, `Go gates`,
  `UI e2e (shard 1/2/3)`, `ML gates`, `Docker build (core-api|dns-resolver|feed-sync|feed-syncd)`,
  `Dependency audit (npm)`, `Secret scan (gitleaks)`.

## (d) Reviewer self-check (for whoever reviews, including an AI)

(b) checks the product. This checks *your evidence*, because a reviewer using
a broken measurement produces confident, specific, wrong findings that look
exactly like real ones. That is not hypothetical: a review here reported six
em dashes committed as literal `???`, backed by byte-level output — and the
byte-level output was itself an artifact of reading git through a console
codepage. The finding was wrong and had to be retracted.

- Measure bytes, not rendering. Any claim about encoding or non-ASCII must come
  from a tool that does not pass through a terminal:
  `python -c "import subprocess; b=subprocess.run(['git','cat-file','-p','REV:path'],capture_output=True).stdout; print(len(b), sum(1 for x in b if x>127))"`.
  Never conclude from what a console printed.
- Quote raw output for every "verified" claim. A command name is not evidence.
- Distinguish the working-tree file from the committed blob. CRLF
  normalization makes them differ in length; only the blob is what shipped.
- Check a glob before trusting it: `git ls-files '<pattern>'`. An empty result
  means the coverage is imaginary, not that the area is safe.
- Count required checks from branch protection, not from the checks rollup.
  The rollup includes non-required jobs (here, the skipped trivy scan), so it
  runs one higher than the number that actually gates a merge.
- If you retract a finding, say so on the PR with the corrected measurement.
  Do not quietly drop it.

## Done / revert for this item

- Done when: this file exists in `docs/security/`, owner approves the PR,
  and any protection/ruleset change (none in this PR) is listed with its
  revert command.
- This PR changes NO branch protection and renames NO jobs.
- Revert: `git revert <merge-sha>` or delete this file. No other state.
