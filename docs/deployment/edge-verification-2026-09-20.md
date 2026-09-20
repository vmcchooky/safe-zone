# RB-1 edge verification evidence — 2026-09-20

Target: VPS `safe-zone` (Azure, Ubuntu, `safe-zone` @ `6.17.0-1022-azure`),
public IP `85.211.194.199`, public host `safe.quorix.io.vn`.
Production build `f87f923` (containers healthy, up 2 days; redis 2 weeks).
Method: read-only checks only — no config, firewall, or container changes.
Collector: Muse Spark (review session), all times UTC.

## 1. Listening sockets (`ss -tlnp`, 2026-09-20T09:57:11Z)

| Socket | Scope | Expected | Result |
|---|---|---|---|
| `127.0.0.1:8080` (core-api) | loopback | loopback-only | PASS |
| `127.0.0.1:8081` (dns-resolver) | loopback | loopback-only | PASS |
| `0.0.0.0:80`, `[::]:80` (caddy) | public | public | PASS |
| `0.0.0.0:443`, `[::]:443` (caddy) | public | public | PASS |
| `0.0.0.0:853`, `[::]:853` (dns-resolver→8533) | public | public | PASS |
| `0.0.0.0:22`, `[::]:22` (SSH) | public | public | PASS |
| caddy admin `:2019` | — | not published | PASS (no listener) |
| redis `:6379` | container-internal | not published | PASS (`docker port safe-zone-redis-1` empty; no host listener) |

Docker bindings match `docker-compose.production.yml` exactly:
`127.0.0.1:8080->8080`, `127.0.0.1:8081->8081`, `0.0.0.0:853->8533`,
`0.0.0.0:80->80`, `0.0.0.0:443->443` (`docker port` output archived in §5).

## 2. Host firewall (`ufw status numbered`, INPUT policy DROP)

Active. Allow-list only (v4+v6 mirrored):
`22/tcp` (comment: SSH via Azure NSG), `80/tcp`, `443/tcp`, `853/tcp`.
No other inbound allows. Matches `docs/runbooks/production-edge.md` §Verify.

## 3. External negative probe (from operator workstation)

`curl http://85.211.194.199:8080/healthz` → `000`, exit 28 (timeout).
`curl http://85.211.194.199:8081/v1/policy` → `000`, exit 28 (timeout).
Internal ports unreachable from the internet (loopback bind + UFW DROP,
defense in depth).

## 4. DoH through Caddy (`POST https://safe.quorix.io.vn/dns-query`)

29-byte RFC 8484 query (ID `0x1234`, `example.com IN A`) →
HTTP 200, 83-byte DNS reply, ID echo `0x1234`, rcode 0.
Methodology note: one early probe returned 400 `invalid DNS message`
because the probe file was corrupted client-side (PowerShell `>` wrote
UTF-16); re-made byte-exact with Python and passed. Not a server issue.

## 5. DoT on 853 (direct, outside Caddy)

- Handshake: TLSv1.3, `TLS_AES_128_GCM_SHA256`.
- Leaf CN `safe.quorix.io.vn`, issuer Let's Encrypt `YE2` — real public
  cert, not the self-signed fallback path (supporting signal for RB-4,
  which needs its own cert-file evidence to close).
- Python (Windows root store): chain verifies OK. Strawberry-openssl CLI
  reported `Verify return code: 20 (unable to get local issuer
  certificate)` — local intermediate missing in that tool's bundle,
  not a server defect; recorded for honesty.
- Live query `example.com IN A` (2-byte length-prefixed framing) →
  83 bytes, rcode 0, 2 answers.

## 6. Block-page edge behavior

- `GET http://85.211.194.199/` with `Host: blocked.example.test` → 200,
  contains `This site was blocked.` + domain echo + report form.
- `GET https://safe.quorix.io.vn/block?domain=blocked.example.test&path=%2F`
  → 200, same quarantine message + domain echo.

## 7. Automated re-check (`scripts/ops/check-production-ports.sh`)

> **Correction 2026-09-20 (second pass):** the first version of this section
> wrongly claimed the script was missing and had been written for this
> verification. In fact `scripts/ops/check-production-ports.sh` pre-existed
> in git (committed in `fff9186`) — the "missing" claim was made
> without running an existence check, and a rewrite briefly overwrote it in
> the working tree before the mistake was caught via subagent cross-check.
> The tree has been restored to the committed version; no rewrite was pushed.
> Lesson recorded: verify existence (`git ls-files`/`Test-Path`) before
> claiming absence.

The committed script was validated instead: `sh -n` clean, local audit on
the VPS **all PASS, exit 0** (core-api + dns-resolver `/healthz` reachable on
loopback; 8080/8081 loopback-or-private only; no host listener on 6379 or
11434). Enhancement 2026-09-20 (same file, validated both modes): UFW
allow-list audit (`sudo -n` fallback), `docker port` binding checks for all
four services, `--evidence-dir` retention, DoT cert info, `-h/--help`;
remote-scan mode untouched and re-verified (80/443/853 OPEN, 8080/8081/6379/
11434 BLOCKED, exit 0).

Checkout caveat (found while validating): the git blob is pure LF, but this
working tree checks files out as CRLF, so `scp`-ing a working-tree `.sh` to
the VPS yields `set: Illegal option -` under `dash`. Copy from `git show
HEAD:<path>` bytes (or set `core.autocrlf`/`eol`) before transferring
scripts to Linux.

## 8. Residual gaps (RB-1 NOT self-closed by this file)

- Azure NSG rules were not audited here (UFW comments reference them);
  cloud-rule confirmation per environment is still required by the
  runbook — needs owner/Azure-portal evidence.
- `docs/runbooks/production-edge.md` §Verify references
  `scripts/ops/check-production-ports.sh` — reference was always valid
  (script committed in `fff9186`); an earlier draft of this file wrongly
  claimed otherwise (corrected in §7).
- This evidence reflects build `f87f923`; re-run after any re-deploy
  (planned post-gate ~25/09) before citing for release.
- RB-1 closure itself requires informed owner review per
  `docs/security/threat-model.md` §13 (any open blocker = no-go).
