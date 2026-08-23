# ML shadow representative replay and approval packet

Use this runbook before requesting approval for Custom Domain ML canary
enforce. It creates a private, stratified replay packet and a human-review
queue. Keep the working packet outside Git while it is being generated or
edited. After review, promote the exact packet to the tracked evidence archive
only after the repository's access and retention policy permits storing the
domain-level evidence.

## Evidence boundary

The repository currently has no production `analysis_log` rows. A local
replay built from curated safe/malicious sources and prior block reports is
therefore a traffic proxy, not production traffic. Source membership is a
sampling signal only; it is not a human ground-truth label.

The replay must run in `shadow` with the exact immutable bundle mounted
read-only into both services. During a clean ML-path replay, disable external
AI, enrichment, and OSINT calls so the result measures the deterministic
analysis plus ML shadow path without generating outbound requests for every
candidate domain.

## Required packet files

Create these files under an access-controlled private directory, for example
`D:\Quorix\private-artifacts\safe-zone\replay\<run-id>` or an equivalent
staging evidence store:

- `manifest.json`: Git SHA, model revision, policy threshold, source hashes,
  sampling counts, and run configuration;
- `requests.jsonl`: one normalized domain request per case, with source
  stratum and no human label;
- `results.jsonl`: core API and DNS policy responses plus HTTP status and
  timestamps;
- `labels.csv`: the review queue; reviewers fill only the human-review fields;
- `review-summary.json`: aggregate counts and adjudication notes after review;
- `approval-packet.md`: links to the evidence and explicit product/security
  decisions.

Do not commit an unreviewed working packet, contact details, credentials, or
AI-generated labels. For an approved audit archive, the reviewed run may be
stored at `ml/evidence/representative-replay/<run-id>/`; its checksum manifest
and provenance note must be reviewed with the Product/Security owner decision.

## Sampling strata

Use a deterministic, deduplicated sample with the source and retrieval time
recorded in `manifest.json`:

| Stratum | Intended use | Ground-truth status before review |
| --- | --- | --- |
| `strong_safe` | Curated official/public-service domains | Candidate only; human verification required |
| `weak_safe` | Tranco/top-domain traffic prior | Candidate only; compromised/shared-hosting risk |
| `strong_malicious` | Verified phishing/malware indicators | Candidate only; verify freshness/status |
| `specialist_malicious` | Specialist community phishing feeds | Candidate only; source-aware review |
| `context_only` | Ad/tracker or mixed-purpose lists | Never use as binary malicious ground truth |
| `user_reported` | Existing block-page reports | Prior signal only; adjudicate the report |

The packet should include benign hard cases (trusted brands, government/
education, IDN/punycode, shared hosting), malicious hard cases (brand spoof,
shortened/redirecting, fresh indicators), and the domains that generated the
existing user reports. Keep duplicate registrable domains in one review group
so the reviewer does not count sibling subdomains as independent evidence.

## Human-label rubric

Each case needs an independent reviewer who records:

- `human_label`: `benign`, `malicious`, `compromised`, `shared_hosting`, or
  `unknown`;
- `label_confidence`: `high`, `medium`, or `low`;
- `evidence_type`: verified owner, official source, live content review,
  strong feed with current status, incident/ticket, or insufficient evidence;
- `reviewer_id`, `reviewed_at`, `evidence_refs`, and a short `review_notes`;
- whether the ML shadow action would be a false positive, false negative, or
  unresolved disagreement.

Do not use the ML prediction, LLM output, or list membership as the sole
evidence for a human label. `shared_hosting`, `compromised`, and `unknown`
must not be forced into the benign/malicious binary metric.

## False-positive review

Before a canary request, calculate separately for the approved human-labelled
subset:

- false positives at threshold `0.85` among `benign` cases;
- false positives on critical benign strata (trusted brand, government/
  education, shared hosting, IDN/punycode);
- unresolved/disagreement count;
- coverage and reviewer agreement;
- cases where the current deterministic policy already blocks independently
  of ML.

Any confirmed critical-benign false positive, missing evidence for a proposed
block, or reviewer disagreement on a high-probability case blocks canary
approval until resolved or explicitly accepted by Product and Security.

Nếu Product/Security chấp nhận các case đã review nhưng không thể phân loại,
reporter chỉ áp dụng `reviewed_unclassifiable` waiver khi `case_count`,
`would_block_count` và SHA-256 của danh sách `case_id` đã sort khớp chính xác.
Waiver phải có lý do cụ thể, không biến case thành binary ground truth và tự
mất hiệu lực khi tập case thay đổi. Packet mới vẫn cần owner decision/date;
waiver hợp lệ ở review gate không tự phê duyệt rollout.

## Approval request

The approval packet must ask Product to approve the threshold and false-
positive budget, and Security to approve data handling, access, retention,
source terms, and rollout scope. Approval is not complete when the packet is
merely generated; each owner must record an explicit decision and date.

Only after both approvals and the human-review gates pass may the release
proceed to a small `enforce` canary with the documented kill switch back to
`shadow` or `disabled`.

## Clean bounded-canary replay

Use `cmd/ml-replay` to compare two independent classifier/service paths without
Redis, LLM, enrichment or OSINT. The command remains in `shadow`, checks model
probability parity and service response parity, and records the bounded selector
observation. Write the report to a private working directory; do not overwrite
the signed packet.

```powershell
go run ./cmd/ml-replay `
  --labels <reviewed-run>\labels.csv `
  --bundle <immutable-bundle> `
  --source-commit <exact-40-character-git-sha> `
  --canary-percent 10 `
  --canary-seed <stable-window-seed> `
  --rounds 3 `
  --tolerance 1e-12 `
  --output <private-run>\replay-report.json
```

The configured percentage bounds normalized-domain hash space, not the exact
request count in a finite sample. Require non-zero selected and excluded
predictions before treating the selector branches as observed. A replay with no
benign runtime candidates cannot establish runtime-candidate FPR even when the
offline reviewed-set FPR is zero.

### Targeted benign supplement from the operator queue

When `runtime_candidate_false_positive.benign_cases` is zero, use
`cmd/ml-fp-candidates` to build a private supplemental set from false-positive
reports already confirmed with the `Allow` action. The exporter fetches the
active analysis config and trusted-brand list, verifies that the local bundle
matches the runtime model contract, and retains only counterfactual lexical
`SUSPICIOUS` domains.

```powershell
go run ./cmd/ml-fp-candidates `
  --api-url http://127.0.0.1:8080 `
  --admin-api-key-file <private-admin-key-file> `
  --bundle <immutable-bundle> `
  --source-commit <exact-40-character-git-sha> `
  --min-candidates 25 `
  --output <new-private-targeted-run>
```

Run `cmd/ml-replay` against the resulting `labels.csv` as a separate report;
do not merge it into or overwrite the signed representative packet. Treat
`empty_queue` and `insufficient_candidates` as evidence gaps, not as passing
FPR results. This workflow consumes only new operator decisions and does not
ask the reviewer to repeat the archived 78 unclassifiable reviews.

### Vietnam whitelist proxy fallback

When the local false-positive queue is empty, use `cmd/ml-whitelist-proxy` as
an offline screening supplement. It evaluates the checksum-pinned Vietnam
whitelist snapshot counterfactually without changing the runtime whitelist or
requesting any source domain. The runtime must remain `shadow/ready/enabled`.

```powershell
go run ./cmd/ml-whitelist-proxy `
  --api-url http://127.0.0.1:8080 `
  --admin-api-key-file <private-admin-key-file> `
  --bundle <immutable-bundle> `
  --source data\whitelist\vietnam\vietnam_domains.txt `
  --data-manifest ml\data\data_manifest.json `
  --source-logical-name vietnam_domains.txt `
  --source-commit <exact-40-character-git-sha> `
  --near-threshold-margin 0.05 `
  --output <new-private-whitelist-proxy-run>
```

Treat `whitelist_proxy_fpr` as a proxy metric only. Whitelist membership is not
a human label, and a row in `would-block.csv` is a targeted review candidate,
not a confirmed false positive. Review the would-block cases and relevant
near-threshold critical domains before converting any row into approval
evidence. The source manifest currently records terms review as pending, so
the generated report is R&D evidence rather than a signed rollout packet.

Prefer the curated CSV mode before assigning cases to a reviewer. It excludes
rows without an approved evidence reference and rejects unknown public
suffixes without making outbound requests:

```powershell
go run ./cmd/ml-whitelist-proxy `
  --api-url http://127.0.0.1:8080 `
  --admin-api-key-file <private-admin-key-file> `
  --bundle <immutable-bundle> `
  --source data\whitelist\vietnam\vietnam_websites.csv `
  --data-manifest ml\data\data_manifest.json `
  --source-logical-name vietnam_websites.csv `
  --source-format csv `
  --domain-column domain `
  --evidence-url-column detail_url `
  --allowed-evidence-hosts tinnhiemmang.vn,giayphep.abei.gov.vn `
  --require-icann-suffix `
  --source-commit <exact-40-character-git-sha> `
  --near-threshold-margin 0.05 `
  --output <new-private-curated-run>
```

### Bounded Firecrawl evidence verification

After curated replay, use `cmd/ml-evidence-firecrawl` to prepare a dry-run of
the would-block and near-threshold review union. Dry-run performs no network
request and does not require an API key:

```powershell
go run ./cmd/ml-evidence-firecrawl `
  --replay-manifest <curated-run>\manifest.json `
  --candidates <curated-run>\candidates.csv `
  --data-manifest ml\data\data_manifest.json `
  --metadata data\whitelist\vietnam\vietnam_websites.csv `
  --source-logical-name vietnam_websites.csv `
  --runner-commit <exact-40-character-git-sha> `
  --max-cases 20 `
  --output <new-private-firecrawl-dry-run>
```

Review `cases.json` before external execution. Firecrawl may request only the
exact HTTPS evidence URLs on `tinnhiemmang.vn` and
`giayphep.abei.gov.vn`; it must never request candidate domains or follow their
links. Store a newly rotated key in `ops/secrets/firecrawl_api_key`, then run a
new output directory with both `--api-key-file` and `--execute`. Never place
the key in source, a command-line value, chat, output, or signed evidence.

Treat every extracted record as untrusted until local validation and operator
review pass. A directory/license match is evidence provenance, not a current
safety verdict or automatic `Allow` decision.

If the local validation contract changes, revalidate the immutable raw
responses offline in a new output directory. This mode does not read an API
key or make Firecrawl requests, and it verifies every stored response hash
before parsing:

```powershell
go run ./cmd/ml-evidence-firecrawl `
  --replay-manifest <curated-run>\manifest.json `
  --candidates <curated-run>\candidates.csv `
  --data-manifest ml\data\data_manifest.json `
  --metadata data\whitelist\vietnam\vietnam_websites.csv `
  --source-logical-name vietnam_websites.csv `
  --runner-commit <exact-40-character-git-sha> `
  --revalidate-results <prior-firecrawl-run>\results.jsonl `
  --max-cases 20 `
  --output <new-private-revalidated-run>
```

Require `contract_errors=0`. Keep `unresolved_not_found` separate from
`evidence_found`; a missing directory record neither confirms safety nor
confirms maliciousness.

## Tracked evidence archive

The completed Phase 5 run is archived at
`ml/evidence/representative-replay/run-20260808/`. It contains the run outputs,
the 137-case human-label packet, every referenced evidence file, an archive
provenance note, and `checksums.sha256`. The packet's `evidence_refs` are
relative to the archive, so a clone does not depend on the disposable `tmp/`
directory. The AI-filled adjudication draft remains quarantined and is not part
of the signed evidence.
