# Archive provenance and verification

## Identity

- Archive: `phase5-representative-replay/run-20260808`
- Source run: `tmp/phase5-representative-replay/run-20260808`
- Evidence source: `tmp/gemini/evidence`
- Archive purpose: preserve the replay inputs, outputs, human labels, decision
  summary, approval packet, and referenced review evidence before an owner
  signature.

The source directories are disposable working space. This tracked copy is the
canonical artifact for review. `manifest.generated.json` preserves the
generator's original manifest. The canonical `manifest.json` keeps the same
run/source hashes but is rebound to the committed validator/reporter/test code
so the signature can identify the reviewed implementation.

The `repository_git_sha` inside canonical `manifest.json` is the final code
commit SHA `311cef4fb52f70b58e8881c215402fbef2db27df`. Do not replace it with
the historical SHA in `manifest.generated.json` when signing this packet.

## Scope decisions

- All 10 files from the run directory are retained under their canonical names,
  plus the original run README as `README.source.md`, the original generator
  manifest as `manifest.generated.json`, and the pre-disclosure packet as
  `approval-packet.generated.md`.
- All 241 files from `tmp/gemini/evidence/` are retained because the packet's
  81 unique evidence references resolve into that directory (including the
  shared `scrape_log.jsonl`).
- `labels.csv` paths were mechanically rewritten from
  `tmp/gemini/evidence/...` to `evidence/...`; no label, probability, outcome,
  note, or reviewer field was changed.
- AI-filled labels and adjudication drafts under
  `tmp/gemini/quarantine-ai-adjudication-20260814/` are not release evidence
  and are intentionally not copied here.

## Integrity

`checksums.sha256` lists SHA-256 hashes for every archive file except the
checksum file itself. Verify from the repository root with PowerShell:

```powershell
$root = 'ml/evidence/representative-replay/run-20260808'
Get-Content "$root/checksums.sha256" | ForEach-Object {
  $parts = $_ -split '  ', 2
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $root $parts[1])).Hash.ToLowerInvariant()
  if ($actual -ne $parts[0].ToLowerInvariant()) { throw "Checksum mismatch: $($parts[1])" }
}
```

The checksum list is regenerated only after an intentional archive change.
The report should then be run twice and the hashes of `review-summary.json` and
`approval-packet.md` should remain unchanged on the second run.

## Review boundary

This archive records evidence; it does not itself approve rollout. Product and
Security owner decisions must be completed in `approval-packet.md`, and the
code revision containing the validator/reporter changes must be committed and
reviewed before a signature is treated as binding.
